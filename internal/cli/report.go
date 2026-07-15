package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/report"
	"github.com/NX1X/Egret/internal/sarif"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var (
		from       string
		format     string
		out        string
		policyPath string
	)
	cmd := &cobra.Command{
		Use:   "report --from <report.json> --format <markdown|json|sarif>",
		Short: "Convert a run's report.json into another format",
		Long: `Report re-renders a prior run's JSON report. Its main use is producing
SARIF for GitHub Code Scanning after a run:

  egret run --config policy.yaml -- ./build.sh
  egret report --from hardened-report/report.json --format sarif --out egret.sarif
  # then upload egret.sarif with github/codeql-action/upload-sarif`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" {
				return fmt.Errorf("--from <report.json> is required")
			}
			raw, err := os.ReadFile(from)
			if err != nil {
				return fmt.Errorf("reading report: %w", err)
			}
			var s event.Session
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("parsing report %q: %w", from, err)
			}

			var data []byte
			switch format {
			case "json":
				b, err := json.MarshalIndent(&s, "", "  ")
				if err != nil {
					return err
				}
				data = append(b, '\n')
			case "markdown", "md":
				data = []byte(report.Markdown(&s))
			case "sarif":
				b, err := json.MarshalIndent(sarif.FromSession(&s, policyPath, version), "", "  ")
				if err != nil {
					return err
				}
				data = append(b, '\n')
			default:
				return fmt.Errorf("unsupported --format %q (want markdown|json|sarif)", format)
			}

			if out == "" || out == "-" {
				_, err := cmd.OutOrStdout().Write(data)
				return err
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return fmt.Errorf("writing %q: %w", out, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s)\n", out, format)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "path to a report.json produced by `egret run`")
	f.StringVar(&format, "format", "sarif", "output format: markdown|json|sarif")
	f.StringVar(&out, "out", "", "output file (default: stdout)")
	f.StringVar(&policyPath, "policy-path", "", "policy file to attribute SARIF findings to (optional)")
	return cmd
}
