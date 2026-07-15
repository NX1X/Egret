package cli

import (
	"fmt"

	"github.com/NX1X/Egret/internal/policy"
	"github.com/spf13/cobra"
)

// runOptions holds the parsed flags + the command to monitor.
type runOptions struct {
	configPath  string
	modeFlag    string // optional override of policy.mode
	outputDir   string // optional override of report.output-dir
	disableSudo bool   // revoke the build user's sudo before running (block mode)
	command     []string
}

func newRunCmd() *cobra.Command {
	opts := &runOptions{}
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Monitor (and optionally enforce on) a command",
		Long: `Run wraps a command under Egret's eBPF monitors. It records every
outbound connection, the process tree, and writes to protected paths, evaluates
them against the policy, and writes a report. In block mode it enforces a
default-deny egress allowlist.

The command to monitor must follow a "--" separator:

  sudo egret run --config policy.yaml -- ./build.sh --release`,
		// We parse args ourselves around the "--" so cobra doesn't try to
		// interpret the wrapped command's flags.
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 0 || dash > len(args) {
				return fmt.Errorf("missing command: use `egret run [flags] -- <command> [args...]`")
			}
			opts.command = args[dash:]
			if len(opts.command) == 0 {
				return fmt.Errorf("no command given after `--`")
			}

			cfg, err := loadPolicy(opts.configPath)
			if err != nil {
				return err
			}
			if opts.modeFlag != "" {
				cfg.Mode = policy.Mode(opts.modeFlag)
				if err := cfg.Validate(); err != nil {
					return err
				}
			}
			if opts.outputDir != "" {
				cfg.Report.OutputDir = opts.outputDir
			}
			return executeRun(cmd, cfg, opts.command, opts.disableSudo)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.configPath, "config", "c", "", "path to policy.yaml (defaults applied if omitted)")
	f.StringVar(&opts.modeFlag, "mode", "", "override policy mode: audit|block")
	f.StringVar(&opts.outputDir, "output-dir", "", "override report output directory")
	f.BoolVar(&opts.disableSudo, "disable-sudo", false, "revoke the build user's passwordless sudo for the run (block mode; defence-in-depth on top of no_new_privs)")
	return cmd
}

// loadPolicy loads from path, or returns safe defaults when path is empty.
// Remote `extends: org://...` refs are resolved via GitHub (GITHUB_TOKEN).
func loadPolicy(path string) (*policy.Policy, error) {
	if path == "" {
		return policy.Default(), nil
	}
	return policy.LoadWithResolver(path, orgPolicyResolver())
}
