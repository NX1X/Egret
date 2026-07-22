//go:build !linux

package cli

import (
	"fmt"
	"runtime"

	"github.com/NX1X/Egret/internal/policy"
	"github.com/spf13/cobra"
)

// addPlatformCommands is a no-op off Linux - the guarded privilege-drop
// trampoline is a Linux-only path (block mode requires eBPF + a Linux kernel).
func addPlatformCommands(_ *cobra.Command) {}

// executeRun on non-Linux platforms cannot load eBPF. We fail clearly rather
// than pretend to monitor. Development of the cross-platform packages (policy,
// report, audit) still works here; running the agent needs a Linux kernel.
func executeRun(_ *cobra.Command, _ *policy.Policy, _ []string, _ bool) error {
	return fmt.Errorf("egret run requires Linux (eBPF); this is %s/%s. "+
		"Run inside a Linux host or CI runner with kernel 5.8+ and CAP_BPF",
		runtime.GOOS, runtime.GOARCH)
}
