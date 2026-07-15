//go:build linux

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/NX1X/Egret/internal/enforcer"
	"github.com/spf13/cobra"
)

// selfProbeCmdName is the hidden subcommand egret re-execs INTO the build cgroup to
// send one canary packet, so the parent can read the nft counter and confirm the
// cgroup egress filter is confining the build.
const selfProbeCmdName = "__selfprobe"

// newSelfProbeCmd dials the canary once and exits. Being dropped is the EXPECTED
// outcome (that's the whole point) — we ignore the dial result; the parent decides
// confinement from the nft counter, not from this process's exit.
func newSelfProbeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    selfProbeCmdName,
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			conn, err := net.DialTimeout("tcp", args[0], 2*time.Second)
			if err == nil {
				_ = conn.Close()
			}
			return nil
		},
	}
}

// runSelfProbe verifies, BEFORE the build runs, that the cgroup egress filter
// actually confines the build cgroup — the F-C fail-open check. It forks a probe
// into the build cgroup that sends a packet to a non-allowlisted canary, then reads
// the cgroup-scoped drop counter. If the counter did not increment, the build's
// traffic is NOT being matched by Egret's rules (e.g. a namespace-relative cgroup
// match miss on a container runner) — so block mode is silently fail-OPEN. We return
// an error; executeRun aborts fail-CLOSED (teardown restores the host) rather than
// run a build that believes it is confined when it is not.
func runSelfProbe(ctx context.Context, enf *enforcer.Enforcer) error {
	canary := enf.ProbeCanary()
	if canary == "" {
		return nil // no firewall (audit mode)
	}
	before, err := enf.ProbeDropCount(ctx)
	if err != nil {
		return fmt.Errorf("self-probe: reading drop counter: %w", err)
	}

	// Fork the probe into the build cgroup (same placement the build gets), as root
	// — this is Egret's own probe, it does not drop privilege. A 5s bound so a
	// dropped SYN can't hang setup.
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c := exec.CommandContext(pctx, "/proc/self/exe", selfProbeCmdName, canary)
	c.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: enf.BuildCgroupFD()}
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	_ = c.Run() // the dial is expected to be dropped; we read the counter, not the exit

	after, err := enf.ProbeDropCount(ctx)
	if err != nil {
		return fmt.Errorf("self-probe: reading drop counter: %w", err)
	}
	if after <= before {
		// The counter not moving means the cgroup-scoped drop did not fire for the
		// probe's packet. The dominant cause is the F-C fail-open (the `socket
		// cgroupv2` match missed on a cgroup-namespaced/container runner). A few
		// benign causes are also possible (all fail-SAFE — we refuse block mode
		// either way): no route to the canary so no packet was emitted, the canary
		// routed via `lo`, or allowed-ips happening to cover it. We name them so an
		// operator can disambiguate rather than assume a bug.
		return fmt.Errorf("block-mode self-probe FAILED: a canary packet (%s) from the build "+
			"cgroup was NOT dropped by Egret's egress filter (drop counter did not move). Most "+
			"likely the cgroup match is not confining this runner — a cgroup-namespaced/container "+
			"topology where `socket cgroupv2` misses (F-C fail-open). Less likely (all fail-safe): "+
			"no route to the canary, it routes via lo, or your allowed-ips covers it. Refusing block "+
			"mode fail-closed; use audit mode on this runner. (netsec F-C)", canary)
	}
	return nil
}
