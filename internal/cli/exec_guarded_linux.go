//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// execGuardedCmdName is the hidden subcommand Egret re-execs to run a block-mode
// build with privilege PERMANENTLY dropped. It is not part of the public CLI.
const execGuardedCmdName = "__exec-guarded"

// addPlatformCommands registers Linux-only subcommands on the root. The guarded
// trampoline only exists on Linux (it is the block-mode privilege-drop path).
func addPlatformCommands(root *cobra.Command) {
	root.AddCommand(newExecGuardedCmd())
	root.AddCommand(newSelfProbeCmd())
}

// newExecGuardedCmd is an internal privilege-drop trampoline. `egret run` re-execs
//
//	egret __exec-guarded --uid U --gid G -- <command...>
//
// as root INSIDE the build cgroup (no SysProcAttr.Credential), and this command
// then makes the drop UNRECOVERABLE before exec'ing the build:
//
//  1. PR_SET_NO_NEW_PRIVS=1 - a later execve of a setuid-root or file-capability
//     binary (sudo, mount, ping, newgrp) can NEVER regain privilege. This is the
//     lock SysProcAttr.Credential alone does not give: dropping to a non-root uid
//     still lets `sudo` re-escalate; no_new_privs closes that hole (netsec F-A).
//  2. Drop the entire capability BOUNDING set - so even a file-capability binary
//     can't hand back CAP_NET_ADMIN/CAP_SYS_ADMIN (belt to no_new_privs' braces).
//  3. setgroups([]) / setgid / setuid to the non-root build user, in that order.
//  4. execve the build - it inherits the cgroup (exec does not move cgroups), the
//     no_new_privs bit, and the empty bounding set.
//
// Any failure exits non-zero WITHOUT exec'ing the build - fail-closed, so a build
// never runs with more privilege than intended.
func newExecGuardedCmd() *cobra.Command {
	var uid, gid int
	cmd := &cobra.Command{
		Use:                   execGuardedCmdName,
		Hidden:                true,
		DisableFlagsInUseLine: true,
		Args:                  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return execGuarded(uid, gid, args)
		},
	}
	cmd.Flags().IntVar(&uid, "uid", 0, "non-root uid to drop the build to")
	cmd.Flags().IntVar(&gid, "gid", 0, "non-root gid to drop the build to")
	return cmd
}

// runtimeCapLastCap returns the highest capability number the running kernel
// knows, from /proc/sys/kernel/cap_last_cap, never below the value Egret was built
// against. Using the runtime value means a kernel newer than our build still gets
// its full bounding set emptied; the PR_CAPBSET_DROP EINVAL break covers overshoot.
func runtimeCapLastCap() int {
	last := unix.CAP_LAST_CAP
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return last
	}
	if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > last {
		return n
	}
	return last
}

// execGuarded applies the irreversible privilege drop then execs command. On
// success it never returns (the process image is replaced by the build).
func execGuarded(uid, gid int, command []string) error {
	// Refuse to "drop" to root - that would defeat the entire boundary. The parent
	// only ever calls us with a real non-root uid/gid, but verify fail-closed.
	if uid <= 0 || gid <= 0 {
		return fmt.Errorf("%s: refusing to run without a non-root uid/gid (got uid=%d gid=%d)",
			execGuardedCmdName, uid, gid)
	}

	// prctl(no_new_privs), PR_CAPBSET_DROP and the exec are all thread-local
	// operations that must happen on the SAME OS thread the process finally execs
	// from. Pin the goroutine to its thread so a reschedule can't move the execve
	// onto a thread that never got no_new_privs. We never unlock - we exec or exit.
	runtime.LockOSThread()

	// Resolve the binary against PATH now, while we can still report a clean error
	// (syscall.Exec does not search PATH).
	bin, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("%s: %w", execGuardedCmdName, err)
	}

	// 1. no_new_privs - the crucial lock, set before the build's execve.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}

	// Clear any ambient capabilities (kernel >= 4.3). Ambient caps are the one cap
	// set that survives a non-root execve, so clear them explicitly rather than
	// trusting the launch environment never set PR_CAP_AMBIENT. Best-effort:
	// absent on old kernels. (netsec F-A finding #3.)
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, uintptr(unix.PR_CAP_AMBIENT_CLEAR_ALL), 0, 0, 0)

	// 2. Empty the capability bounding set (needs CAP_SETPCAP, which we still hold
	//    as root - must run before the uid drop). Bound the loop by the RUNNING
	//    kernel's cap_last_cap (not the build-time constant), so a kernel newer than
	//    our build still has its full set emptied; the EINVAL break is the backstop.
	//    (netsec F-A finding #2.)
	last := runtimeCapLastCap()
	for capNum := 0; capNum <= last; capNum++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capNum), 0, 0, 0); err != nil {
			if errors.Is(err, unix.EINVAL) {
				break
			}
			return fmt.Errorf("drop cap bounding set (cap %d): %w", capNum, err)
		}
	}

	// 3. Drop group memberships, then gid, then uid. Order matters: once uid is
	//    non-root the setgid/setgroups calls would fail. Use the stdlib syscall
	//    wrappers, which apply the change to EVERY OS thread (Go 1.16+), not just
	//    this one - so no sibling runtime thread lingers as root.
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}

	// Defence in depth: confirm root is truly gone (real + effective) before we
	// hand control to the build. If the drop somehow did not stick, fail closed.
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 {
		return fmt.Errorf("%s: still privileged after drop (uid=%d euid=%d) - refusing to exec",
			execGuardedCmdName, os.Getuid(), os.Geteuid())
	}

	// 4. Become the build. Inherits the cgroup + no_new_privs + empty bounding set.
	if err := syscall.Exec(bin, command, os.Environ()); err != nil {
		return fmt.Errorf("%s: exec %s: %w", execGuardedCmdName, bin, err)
	}
	return nil // unreachable on success
}
