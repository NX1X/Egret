// Package report renders an event.Session as Markdown and/or JSON, writes them
// to the policy's output directory, and (when running under GitHub Actions)
// appends the Markdown to the job summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
	"github.com/NX1X/Egret/internal/sarif"
)

// Write emits the configured report formats for the session.
func Write(s *event.Session, pol *policy.Policy) error {
	if err := os.MkdirAll(pol.Report.OutputDir, 0o755); err != nil {
		return fmt.Errorf("creating report dir: %w", err)
	}

	formats := map[string]bool{}
	for _, f := range pol.Report.Format {
		formats[f] = true
	}

	if formats["json"] {
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling json report: %w", err)
		}
		path := filepath.Join(pol.Report.OutputDir, "report.json")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing json report: %w", err)
		}
	}

	if formats["markdown"] {
		md := Markdown(s)
		path := filepath.Join(pol.Report.OutputDir, "report.md")
		if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
			return fmt.Errorf("writing markdown report: %w", err)
		}
		if pol.Report.GitHubJobSummary {
			if err := appendJobSummary(md); err != nil {
				return fmt.Errorf("writing job summary: %w", err)
			}
		}
	}

	if formats["sarif"] {
		b, err := json.MarshalIndent(sarif.FromSession(s, "", ""), "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling sarif report: %w", err)
		}
		path := filepath.Join(pol.Report.OutputDir, "report.sarif")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing sarif report: %w", err)
		}
	}
	return nil
}

// appendJobSummary appends md to $GITHUB_STEP_SUMMARY when present (no-op off CI).
func appendJobSummary(md string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(md + "\n")
	return err
}

// Markdown renders the session as a GitHub-flavoured Markdown report.
func Markdown(s *event.Session) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 🪶 Egret report\n\n")
	// Redact arguments: this Markdown is appended to $GITHUB_STEP_SUMMARY, which
	// is written by the runner and is NOT reliably secret-masked (and is public on
	// public repos). A `command:` input commonly inlines a token as an argument,
	// so we show only the program name + an argument count, never the raw argv.
	// (report.json keeps the full command for the operator's own records.)
	fmt.Fprintf(&b, "- **Command:** %s\n", redactCommand(s.Command))
	fmt.Fprintf(&b, "- **Mode:** %s\n", s.Mode)
	fmt.Fprintf(&b, "- **Exit code:** %d\n", s.ExitCode)
	fmt.Fprintf(&b, "- **Duration:** %s\n", s.Duration().Round(time.Millisecond))
	fmt.Fprintf(&b, "- **Connections:** %d · **Processes:** %d · **File writes:** %d · **Violations:** %d\n\n",
		len(s.Connections), len(s.Processes), len(s.FileWrites), len(s.Violations))

	// Violations first — the headline.
	if len(s.Violations) > 0 {
		blocked := s.Mode == string(policy.ModeBlock)
		verb := "Flagged"
		if blocked {
			verb = "Blocked / flagged"
		}
		fmt.Fprintf(&b, "## ⚠️ %s\n\n", verb)
		fmt.Fprintf(&b, "| Kind | Reason | Detail | Blocked |\n|---|---|---|:--:|\n")
		for _, v := range s.Violations {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				v.Kind, v.Reason, mdEscape(v.Detail), checkbox(v.Blocked))
		}
		b.WriteString("\n")
	} else {
		fmt.Fprintf(&b, "## ✅ No violations\n\n")
	}

	if len(s.Connections) > 0 {
		fmt.Fprintf(&b, "## 🌐 Connections\n\n")
		fmt.Fprintf(&b, "| PID | Process | Destination | Port | Proto |\n|---|---|---|---|---|\n")
		for _, c := range s.Connections {
			dst := c.Daddr.String()
			if c.Domain != "" {
				dst = fmt.Sprintf("%s (%s)", c.Domain, c.Daddr)
			}
			fmt.Fprintf(&b, "| %d | %s | %s | %d | %s |\n",
				c.PID, mdEscape(c.Comm), mdEscape(dst), c.Dport, c.Proto)
		}
		b.WriteString("\n")
	}

	if len(s.FileWrites) > 0 {
		fmt.Fprintf(&b, "## 📝 File writes\n\n")
		fmt.Fprintf(&b, "| PID | Process | Op | Path |\n|---|---|---|---|\n")
		for _, w := range s.FileWrites {
			fmt.Fprintf(&b, "| %d | %s | %s | %s |\n",
				w.PID, mdEscape(w.Comm), w.Op, mdEscape(w.Path))
		}
		b.WriteString("\n")
	}

	if len(s.Processes) > 0 {
		fmt.Fprintf(&b, "## 🧬 Processes\n\n")
		fmt.Fprintf(&b, "| PID | PPID | Process | Filename |\n|---|---|---|---|\n")
		for _, p := range s.Processes {
			fmt.Fprintf(&b, "| %d | %d | %s | %s |\n",
				p.PID, p.PPID, mdEscape(p.Comm), mdEscape(p.Filename))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// redactCommand renders the program name plus an argument count, so a token
// inlined as a command argument never lands in the (public, unmasked) job summary.
func redactCommand(argv []string) string {
	if len(argv) == 0 {
		return "_(none)_"
	}
	prog := "`" + mdEscape(argv[0]) + "`"
	if len(argv) == 1 {
		return prog
	}
	return fmt.Sprintf("%s _(+%d argument(s) omitted)_", prog, len(argv)-1)
}

func checkbox(b bool) string {
	if b {
		return "✅"
	}
	return "—"
}

// mdEscape neutralises pipe and backtick so table cells don't break.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "'")
	return s
}
