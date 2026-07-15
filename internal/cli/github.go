package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/github"
	"github.com/NX1X/Egret/internal/report"
	"github.com/spf13/cobra"
)

const (
	reportMarker    = "<!-- egret-report -->"
	dashboardMarker = "<!-- egret-dashboard -->"
	dashboardTitle  = "🪶 Egret Security Dashboard"
)

func newGithubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github",
		Short: "Publish Egret results to GitHub (check runs, PR comments, dashboard issue)",
		Long: `Post a run's report to GitHub using a token (a GitHub App installation
token or the Actions GITHUB_TOKEN). All subcommands read a report.json produced
by 'egret run' and infer repo/sha/PR from the GITHUB_* environment when flags
are omitted. Every feature works with the default GITHUB_TOKEN; a GitHub App
token additionally lets created PRs trigger downstream workflows.`,
	}
	cmd.AddCommand(newGithubCheckCmd(), newGithubCommentCmd(), newGithubDashboardCmd())
	return cmd
}

// --- shared helpers ---

func resolveToken(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("no token: pass --github-token or set GITHUB_TOKEN")
}

func resolveRepo(flag string) (owner, repo string, err error) {
	v := flag
	if v == "" {
		v = os.Getenv("GITHUB_REPOSITORY") // "owner/repo"
	}
	o, r, ok := strings.Cut(v, "/")
	if !ok || o == "" || r == "" {
		return "", "", fmt.Errorf("repo must be owner/repo: pass --repo or set GITHUB_REPOSITORY")
	}
	return o, r, nil
}

func loadReportSession(from string) (*event.Session, error) {
	if from == "" {
		return nil, fmt.Errorf("--from <report.json> is required")
	}
	raw, err := os.ReadFile(from)
	if err != nil {
		return nil, fmt.Errorf("reading report: %w", err)
	}
	var s event.Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parsing report %q: %w", from, err)
	}
	return &s, nil
}

func resolvePR(flag int) (int, error) {
	if flag > 0 {
		return flag, nil
	}
	// GITHUB_REF for a pull_request event looks like "refs/pull/123/merge".
	ref := os.Getenv("GITHUB_REF")
	if rest, ok := strings.CutPrefix(ref, "refs/pull/"); ok {
		if num, _, ok := strings.Cut(rest, "/"); ok {
			if n, err := strconv.Atoi(num); err == nil && n > 0 {
				return n, nil
			}
		}
	}
	return 0, fmt.Errorf("no PR number: pass --pr (not a pull_request context)")
}

// --- check ---

func newGithubCheckCmd() *cobra.Command {
	var from, repo, sha, name, token string
	cmd := &cobra.Command{
		Use:   "check --from <report.json>",
		Short: "Publish a check run summarizing the report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := loadReportSession(from)
			if err != nil {
				return err
			}
			tok, err := resolveToken(token)
			if err != nil {
				return err
			}
			owner, r, err := resolveRepo(repo)
			if err != nil {
				return err
			}
			if sha == "" {
				sha = os.Getenv("GITHUB_SHA")
			}
			if sha == "" {
				return fmt.Errorf("no commit sha: pass --sha or set GITHUB_SHA")
			}

			conclusion := "success"
			if len(s.Violations) > 0 {
				conclusion = "failure"
			}
			title := fmt.Sprintf("%d violation(s), %d connection(s)", len(s.Violations), len(s.Connections))

			err = github.NewClient(tok).CreateCheckRun(cmd.Context(), owner, r, github.CheckRun{
				Name:       name,
				HeadSHA:    sha,
				Conclusion: conclusion,
				Title:      title,
				Summary:    report.Markdown(s),
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "check run posted: %s (%s)\n", name, conclusion)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "path to report.json")
	f.StringVar(&repo, "repo", "", "owner/repo (default: $GITHUB_REPOSITORY)")
	f.StringVar(&sha, "sha", "", "commit sha (default: $GITHUB_SHA)")
	f.StringVar(&name, "name", "Egret", "check run name")
	f.StringVar(&token, "github-token", "", "GitHub token (default: $GITHUB_TOKEN)")
	return cmd
}

// --- comment ---

func newGithubCommentCmd() *cobra.Command {
	var from, repo, token string
	var pr int
	cmd := &cobra.Command{
		Use:   "comment --from <report.json> [--pr N]",
		Short: "Post/update a sticky PR comment with the report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := loadReportSession(from)
			if err != nil {
				return err
			}
			tok, err := resolveToken(token)
			if err != nil {
				return err
			}
			owner, r, err := resolveRepo(repo)
			if err != nil {
				return err
			}
			num, err := resolvePR(pr)
			if err != nil {
				return err
			}
			if err := github.NewClient(tok).UpsertStickyComment(
				cmd.Context(), owner, r, num, reportMarker, report.Markdown(s)); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "comment posted to %s/%s#%d\n", owner, r, num)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "path to report.json")
	f.StringVar(&repo, "repo", "", "owner/repo (default: $GITHUB_REPOSITORY)")
	f.IntVar(&pr, "pr", 0, "pull request number (default: inferred from $GITHUB_REF)")
	f.StringVar(&token, "github-token", "", "GitHub token (default: $GITHUB_TOKEN)")
	return cmd
}

// --- dashboard ---

func newGithubDashboardCmd() *cobra.Command {
	var from, repo, token string
	cmd := &cobra.Command{
		Use:   "dashboard --from <report.json>",
		Short: "Create/update the Egret Security Dashboard issue",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := loadReportSession(from)
			if err != nil {
				return err
			}
			tok, err := resolveToken(token)
			if err != nil {
				return err
			}
			owner, r, err := resolveRepo(repo)
			if err != nil {
				return err
			}
			num, err := github.NewClient(tok).UpsertDashboardIssue(
				cmd.Context(), owner, r, dashboardTitle, dashboardMarker, report.Markdown(s))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "dashboard updated: %s/%s#%d\n", owner, r, num)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "path to report.json")
	f.StringVar(&repo, "repo", "", "owner/repo (default: $GITHUB_REPOSITORY)")
	f.StringVar(&token, "github-token", "", "GitHub token (default: $GITHUB_TOKEN)")
	return cmd
}
