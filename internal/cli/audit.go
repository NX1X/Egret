package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/NX1X/Egret/internal/audit"
	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/github"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

func newAuditCmd() *cobra.Command {
	var (
		from       string
		emit       string
		configPath string
		openPR     bool
		repo       string
		policyPath string
		branch     string
		base       string
		token      string
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Turn an observed run into a suggested egress allowlist",
		Long: `Audit analyzes the JSON report of a prior monitored run and emits a
suggested egress allowlist — printed, written to a file, and/or opened as a PR.

  1. Observe:  sudo egret run --mode audit --config policy.yaml -- ./build.sh
  2. Suggest:  egret audit --from hardened-report/report.json --emit policy.suggested.yaml
  3. Or PR:    egret audit --from hardened-report/report.json --open-pr \
                 --repo owner/repo --policy-path .github/egret-policy.yaml`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" {
				return fmt.Errorf("--from <report.json> is required (produce it with `egret run`)")
			}
			raw, err := os.ReadFile(from)
			if err != nil {
				return fmt.Errorf("reading report: %w", err)
			}
			var session event.Session
			if err := json.Unmarshal(raw, &session); err != nil {
				return fmt.Errorf("parsing report %q: %w", from, err)
			}

			sug := audit.Analyze(&session)
			out := cmd.OutOrStdout()
			fmt.Fprint(out, sug.Markdown())

			// Build the suggested policy YAML once (used by --emit and --open-pr).
			var suggestedYAML []byte
			if emit != "" || openPR {
				bp, err := loadPolicy(configPath)
				if err != nil {
					return err
				}
				suggestedYAML, err = yaml.Marshal(sug.Policy(bp))
				if err != nil {
					return fmt.Errorf("marshalling suggested policy: %w", err)
				}
			}

			if emit != "" {
				if err := os.WriteFile(emit, suggestedYAML, 0o644); err != nil {
					return fmt.Errorf("writing %q: %w", emit, err)
				}
				fmt.Fprintf(out, "wrote suggested policy to %s\n", emit)
			}

			if openPR {
				tok, err := resolveToken(token)
				if err != nil {
					return err
				}
				owner, r, err := resolveRepo(repo)
				if err != nil {
					return err
				}
				prBody := "Egret observed the endpoints below and suggests this egress allowlist.\n\n" + sug.Markdown()
				num, err := github.NewClient(tok).OpenFilePR(cmd.Context(), owner, r,
					policyPath, branch, base,
					"Egret: update egress allowlist", prBody,
					"chore(egret): update suggested egress allowlist", suggestedYAML)
				if err != nil {
					return fmt.Errorf("opening PR: %w", err)
				}
				fmt.Fprintf(out, "opened/updated PR %s/%s#%d (%s)\n", owner, r, num, policyPath)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "path to a report.json produced by `egret run`")
	f.StringVar(&emit, "emit", "", "write the suggested policy.yaml to this path")
	f.StringVarP(&configPath, "config", "c", "", "base policy to layer the suggestion onto")
	f.BoolVar(&openPR, "open-pr", false, "open a pull request adding the suggested allowlist")
	f.StringVar(&repo, "repo", "", "owner/repo for --open-pr (default: $GITHUB_REPOSITORY)")
	f.StringVar(&policyPath, "policy-path", ".github/egret-policy.yaml", "policy file path to write in the PR")
	f.StringVar(&branch, "branch", "egret/update-allowlist", "branch name for the PR")
	f.StringVar(&base, "base", "", "base branch (default: the repo's default branch)")
	f.StringVar(&token, "github-token", "", "GitHub token (default: $GITHUB_TOKEN)")
	return cmd
}
