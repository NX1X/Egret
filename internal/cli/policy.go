package cli

import (
	"fmt"
	"strings"

	"github.com/NX1X/Egret/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect and validate policy files",
	}
	cmd.AddCommand(newPolicyLintCmd())
	return cmd
}

func newPolicyLintCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "lint --config <policy.yaml>",
		Short: "Validate a policy.yaml and expand its egress wildcards",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configPath == "" {
				return fmt.Errorf("--config <policy.yaml> is required")
			}
			pol, err := policy.Load(configPath)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "✓ %s is valid\n", configPath)
			fmt.Fprintf(out, "  mode: %s\n", pol.Mode)
			fmt.Fprintf(out, "  block-raw-ip: %v\n", pol.Egress.BlockRawIP)
			fmt.Fprintf(out, "  allowed-endpoints (%d):\n", len(pol.Egress.AllowedEndpoints))
			for _, e := range pol.Egress.AllowedEndpoints {
				fmt.Fprintf(out, "    - %s%s\n", e, wildcardHint(e))
			}
			if len(pol.File.ProtectedPaths) > 0 {
				fmt.Fprintf(out, "  protected-paths (%d):\n", len(pol.File.ProtectedPaths))
				for _, p := range pol.File.ProtectedPaths {
					fmt.Fprintf(out, "    - %s\n", p)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to policy.yaml")
	return cmd
}

func wildcardHint(endpoint string) string {
	if suffix, ok := strings.CutPrefix(endpoint, "*."); ok {
		return fmt.Sprintf("  → matches any.subdomain.%s (not %s itself)", suffix, suffix)
	}
	return ""
}
