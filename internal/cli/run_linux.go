//go:build linux

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/NX1X/Egret/internal/collector"
	"github.com/NX1X/Egret/internal/enforcer"
	"github.com/NX1X/Egret/internal/ingest"
	"github.com/NX1X/Egret/internal/monitor"
	"github.com/NX1X/Egret/internal/policy"
	"github.com/NX1X/Egret/internal/report"
	"github.com/spf13/cobra"
)

// executeRun is the Linux agent: load probes, (optionally) enforce, run the
// command, collect + evaluate events, and write the report.
func executeRun(cmd *cobra.Command, pol *policy.Policy, command []string, disableSudo bool) error {
	// Signal-aware context so Ctrl-C / SIGTERM triggers fail-closed teardown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out := cmd.OutOrStdout()

	// Block mode is FAIL-CLOSED on privilege: it is only a confinement boundary if
	// the build runs LESS privileged than Egret. If we can't drop the build to a
	// non-root uid, refuse to enter block mode rather than run the build at Egret's
	// (root) privilege - where it could `nft flush` or write itself out of the
	// cgroup, a silent egress bypass. (netsec re-gate F-B.) Refuse BEFORE any
	// enforcer setup so nothing is half-applied.
	if pol.IsBlocking() {
		if cred, warn := buildCredential(); cred == nil {
			return fmt.Errorf("refusing block mode: %s", warn)
		}
	}

	// --disable-sudo: revoke the build user's passwordless sudo for the run (a belt
	// to F-A's no_new_privs). It only makes sense when the build runs as a non-root
	// user, which is block mode - refuse otherwise so the flag never silently no-ops.
	// Fail-closed: if the revoke can't be applied+validated, abort rather than run
	// the build with the sudo the user asked us to remove still in place.
	if disableSudo {
		if !pol.IsBlocking() {
			return fmt.Errorf("--disable-sudo requires block mode (the build runs as a non-root user there; in audit mode it runs as root and sudo is moot)")
		}
		cred, _ := buildCredential()
		if cred == nil {
			return fmt.Errorf("--disable-sudo requires a non-root build user (run via sudo or set EGRET_BUILD_UID)")
		}
		restore, err := applyDisableSudo(int(cred.Uid))
		if err != nil {
			return fmt.Errorf("disable-sudo: %w", err)
		}
		defer restore()
	}

	// Enforcement + DNS correlation. Even in audit mode the DNS proxy runs so
	// connections can be labelled by domain.
	enf, err := enforcer.New(pol)
	if err != nil {
		return err
	}
	teardown, err := enf.Start(ctx)
	if err != nil {
		return err
	}
	// Teardown must run no matter how we exit - this restores the host network.
	defer func() {
		if terr := teardown(); terr != nil {
			fmt.Fprintln(os.Stderr, "egret: teardown error:", terr)
		}
	}()

	// Block-mode self-probe (F-C): confirm the cgroup egress filter actually confines
	// the build cgroup on THIS runner before trusting it. If a canary packet from the
	// build cgroup isn't dropped, the cgroup match is missing (e.g. a namespaced
	// container runner) and block mode would be silently fail-open - abort fail-closed
	// (the deferred teardown restores the host).
	if pol.IsBlocking() {
		if err := runSelfProbe(ctx, enf); err != nil {
			return err
		}
	}

	// eBPF collector.
	coll, err := collector.New(ctx)
	if err != nil {
		return err
	}
	defer coll.Close()

	// Aggregate events into a session, evaluating against policy as they arrive.
	startedAt := time.Now()
	mon := monitor.New(coll, pol, enf)
	mon.Start()

	// Run the monitored command, wired to the parent's stdio. In block mode it is
	// placed into the enforcer's cgroup so the egress filter scopes to the build.
	exitCode := runCommand(ctx, command, enf.ListenAddr(), enf.BuildCgroupFD())

	// Let any final in-flight events flush, then stop the collector (closes the
	// ring-buffer readers, which closes the event channels and ends the drains).
	time.Sleep(250 * time.Millisecond)
	_ = coll.Close()

	session := mon.Wait()
	session.StartedAt = startedAt
	session.FinishedAt = time.Now()
	session.Command = command
	session.ExitCode = exitCode

	if err := report.Write(session, pol); err != nil {
		fmt.Fprintln(os.Stderr, "egret: report error:", err)
	}

	// Optional self-hosted dashboard: when EGRET_INGEST_URL is set, ship the run.
	// Best-effort - a failed POST never fails the build. Unset URL = no-op, so
	// the dashboard stays entirely optional.
	if url := os.Getenv("EGRET_INGEST_URL"); url != "" {
		env := ingest.NewEnvelope(session, ingest.RunMetaFromEnv(), version)
		pctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		if err := ingest.Post(pctx, url, os.Getenv("EGRET_INGEST_TOKEN"), env); err != nil {
			fmt.Fprintln(os.Stderr, "egret: ingest error:", err)
		}
		cancel()
	}

	fmt.Fprintf(out, "egret: %d connection(s), %d violation(s); report in %s\n",
		len(session.Connections), len(session.Violations), pol.Report.OutputDir)

	// Propagate the command's exit code.
	if exitCode != 0 {
		return &exitError{code: exitCode}
	}
	return nil
}

// runCommand executes the wrapped command and returns its exit code. The DNS
// proxy address is exported so a child resolver could be pointed at it; full
// resolv.conf rewiring is handled by the Action entrypoint / docs. When
// cgroupFD >= 0 (block mode) the child is created directly inside the enforcer's
// cgroup (CLONE_INTO_CGROUP) so the nftables egress filter scopes to the build.
func runCommand(ctx context.Context, command []string, dnsAddr string, cgroupFD int) int {
	var c *exec.Cmd
	if cgroupFD >= 0 {
		// Block mode: the cgroup filter is only a real boundary if the build runs LESS
		// privileged than Egret - a root build could write itself out of the cgroup
		// or `nft flush`. executeRun already refused block mode when no non-root
		// credential is available; this is a defensive backstop (never run a root
		// build under the enforcer's cgroup).
		cred, _ := buildCredential()
		if cred == nil {
			fmt.Fprintln(os.Stderr, "egret: refusing to run a root build in block mode")
			return 126
		}
		// Re-exec through the guarded trampoline (egret __exec-guarded) rather than
		// only setting SysProcAttr.Credential: the trampoline additionally sets
		// no_new_privs and empties the capability bounding set before dropping to
		// the non-root uid, so a setuid-root/file-capability binary the build execs
		// (sudo, mount, …) can't re-escalate out of the confinement. The trampoline
		// starts as root INSIDE the cgroup (UseCgroupFD, no Credential) and drops
		// privilege itself; execve keeps the build in the same cgroup. (netsec F-A.)
		//
		// Re-exec via /proc/self/exe, NOT os.Executable()'s path: /proc/self/exe
		// re-opens the ORIGINAL running inode, so a replacement of the egret binary
		// on disk between startup and this re-exec can't run attacker code as root
		// (the trampoline runs as root before dropping). (netsec F-A finding #1.)
		guardedArgs := []string{
			execGuardedCmdName,
			"--uid", strconv.Itoa(int(cred.Uid)),
			"--gid", strconv.Itoa(int(cred.Gid)),
			"--",
		}
		guardedArgs = append(guardedArgs, command...)
		c = exec.CommandContext(ctx, "/proc/self/exe", guardedArgs...)
		c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgroupFD}
	} else {
		c = exec.CommandContext(ctx, command[0], command[1:]...)
	}
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = append(os.Environ(), "EGRET_DNS="+dnsAddr)

	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "egret: failed to start command:", err)
		return 127
	}
	err := c.Wait()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if asExitError(err, &ee) {
		return ee.ExitCode()
	}
	fmt.Fprintln(os.Stderr, "egret: command error:", err)
	return 1
}

// buildCredential returns the non-root credential to run the monitored command
// under in block mode, or (nil, reason) if one can't be determined. It prefers the
// sudo-invoking user (the usual `sudo egret run` in CI), then an explicit
// EGRET_BUILD_UID/GID override. A root build could escape the cgroup or flush nft,
// so block mode REFUSES (fail-closed) rather than run at Egret's privilege.
//
// Known residuals tracked in the project's internal security-followups (block-mode re-gate):
//   - F-A: os/exec can't set no_new_privs / drop the capability bounding set, so a
//     non-root build with passwordless sudo (GitHub-hosted runners) or a setuid-root
//     helper can still re-escalate and flush nft. Block mode is NOT yet a boundary
//     on such runners.
//   - F-C: the nft cgroup match is namespace-relative; on a cgroup-namespaced
//     (container:) runner it can miss and fall through to policy accept.
func buildCredential() (*syscall.Credential, string) {
	uid, gid, ok := lookupUID("SUDO_UID", "SUDO_GID")
	if !ok {
		uid, gid, ok = lookupUID("EGRET_BUILD_UID", "EGRET_BUILD_GID")
	}
	if !ok {
		return nil, "could not determine a non-root user for the build " +
			"(no SUDO_UID/EGRET_BUILD_UID) - run via sudo, or set EGRET_BUILD_UID. " +
			"Block mode refuses to run the build at Egret's privilege (it could flush " +
			"nft / escape the cgroup). Use audit mode if you can't drop privileges."
	}
	return &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}, ""
}

// lookupUID parses a non-zero uid/gid (each a valid 32-bit id) from the named env vars.
func lookupUID(uidVar, gidVar string) (uid, gid uint32, ok bool) {
	us, gs := os.Getenv(uidVar), os.Getenv(gidVar)
	if us == "" {
		return 0, 0, false
	}
	// ParseUint with bitSize 32 rejects negatives and anything above math.MaxUint32,
	// so the value provably fits a uid_t - no unchecked int->uint32 narrowing.
	u, err := strconv.ParseUint(us, 10, 32)
	if err != nil || u == 0 {
		return 0, 0, false
	}
	g := u // default gid to uid when unset
	if gs != "" {
		if parsed, err := strconv.ParseUint(gs, 10, 32); err == nil {
			g = parsed
		}
	}
	return uint32(u), uint32(g), true
}

func asExitError(err error, target **exec.ExitError) bool {
	for err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
