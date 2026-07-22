// Package cli wires up the Cobra command tree for the egret binary.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "egret",
		Short: "Runtime security agent for CI/CD and Linux hosts",
		Long: `Egret monitors and enforces the runtime behaviour of a command:
network egress (default-deny domain allowlist), process tree, and writes to
protected paths - then emits a report. Zero infrastructure, no phone-home.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newRunCmd())
	root.AddCommand(newAuditCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newReportCmd())
	root.AddCommand(newGithubCmd())
	addPlatformCommands(root)
	return root
}

// Execute runs the root command and returns a process exit code. A cancellable
// context (Ctrl-C / SIGTERM) is threaded to commands via cmd.Context() so
// in-flight work (e.g. GitHub API calls) can be interrupted. `egret run`
// propagates the wrapped command's exit code via *exitError.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		var ee *exitError
		if asExit(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, "egret:", ee.msg)
			}
			return ee.code
		}
		fmt.Fprintln(os.Stderr, "egret:", err)
		return 1
	}
	return 0
}

// exitError carries a specific process exit code up to Execute. It is used to
// forward the monitored command's exit status from `egret run`.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return fmt.Sprintf("exit status %d", e.code)
}

func asExit(err error, target **exitError) bool {
	for err != nil {
		if ee, ok := err.(*exitError); ok {
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
