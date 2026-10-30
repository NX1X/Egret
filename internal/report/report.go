// Package report renders an event.Session as Markdown and/or JSON, writes them
// to the policy's output directory, and (when running under GitHub Actions)
// appends the Markdown to the job summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
	"github.com/NX1X/Egret/internal/sarif"
)

// Write emits the configured report formats for the session.
func Write(s *event.Session, pol *policy.Policy) error {
	// Open the report directory without following any symlink a non-root user
	// could have planted, in ANY component of the path (not only the last one),
	// and write every file relative to that handle. The monitored build may own
	// part of this path; see safewrite_unix.go.
	dir, err := openDirNoFollow(pol.Report.OutputDir, true)
	if err != nil {
		return fmt.Errorf("opening report dir: %w", err)
	}
	defer dir.Close()

	formats := map[string]bool{}
	for _, f := range pol.Report.Format {
		formats[f] = true
	}

	// report.json is ALWAYS written, whatever report.format lists: it is the
	// machine-readable verdict that the action counts violations from and publishes
	// from. Without it, a policy with `format: [markdown]` read as zero violations.
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling json report: %w", err)
	}
	if err := writeFileAt(dir, "report.json", append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing json report: %w", err)
	}

	if formats["markdown"] {
		md := Markdown(s)
		if err := writeFileAt(dir, "report.md", []byte(md), 0o644); err != nil {
			return fmt.Errorf("writing markdown report: %w", err)
		}
		// The job summary is best effort. It is a convenience view, not the verdict
		// (report.json is), and it lives in a runner-owned path that legitimate
		// setups can make unusable (container jobs, symlinked work dirs). A refusal
		// to write through an unsafe path must not fail an otherwise clean run.
		if pol.Report.GitHubJobSummary {
			if err := appendJobSummary(capSummary(md)); err != nil {
				fmt.Fprintln(os.Stderr, "egret: warning: job summary not written:", err)
			}
		}
	}

	if formats["sarif"] {
		b, err := json.MarshalIndent(sarif.FromSession(s, "", ""), "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling sarif report: %w", err)
		}
		if err := writeFileAt(dir, "report.sarif", append(b, '\n'), 0o644); err != nil {
			return fmt.Errorf("writing sarif report: %w", err)
		}
	}
	return nil
}

// maxSummaryBytes caps what Egret appends to the job summary. GitHub refuses a
// step summary above 1024 KiB in total and then shows none of it, so a busy
// build (thousands of connections) lost its whole summary. Half the limit
// leaves room for anything else the same step writes.
const maxSummaryBytes = 512 << 10

// capSummary returns md unchanged when it fits in maxSummaryBytes. Otherwise it
// cuts md at the last line break that fits and appends a note that points to
// the full report. report.md and report.json are always written in full.
func capSummary(md string) string {
	if len(md) <= maxSummaryBytes {
		return md
	}
	note := fmt.Sprintf("\n\n> **Summary truncated.** The full report is %d KiB, above what a GitHub job summary can show. "+
		"Read `report.md` or `report.json` in the report directory for every entry.\n", len(md)>>10)
	cut := maxSummaryBytes - len(note)
	// Cut at a line break, so no Markdown row or multi-byte character is split.
	if i := strings.LastIndexByte(md[:cut], '\n'); i > 0 {
		cut = i
	}
	return md[:cut] + note
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

	// Violations first - the headline.
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

	// Coverage notes: facts about what this report can and cannot show.
	if len(s.Notes) > 0 {
		fmt.Fprintf(&b, "## ℹ️ Notes\n\n")
		for _, n := range s.Notes {
			fmt.Fprintf(&b, "- %s\n", mdEscape(n))
		}
		b.WriteString("\n")
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
	prog := "`" + mdEscapeCode(argv[0]) + "`"
	if len(argv) == 1 {
		return prog
	}
	return fmt.Sprintf("%s _(+%d argument(s) omitted)_", prog, len(argv)-1)
}

func checkbox(b bool) string {
	if b {
		return "✅"
	}
	return "-"
}

// mdEscapeMaxLen caps a single table cell so an attacker-controlled field
// (e.g. a hostile filename captured from the monitored build) can't bloat the
// report or the job summary.
const mdEscapeMaxLen = 512

// mdEscape neutralises an attacker-controlled string (a filename, comm, or
// destination captured from the untrusted build) before it goes into the
// report. The same Markdown is posted as the job summary, the PR comment and
// the dashboard issue, so it must not:
//   - break out of a table cell: pipe, backtick, CR/LF and tab. Linux
//     filenames may contain any byte except NUL and '/', so a value like
//     "evil\n\n## ✅ No violations\n| ... |" would otherwise inject rows or
//     headers into the report reviewers trust;
//   - render as HTML, a link or an image: < > & and [ ];
//   - change formatting: backslash, * _ ~;
//   - notify people or link issues: an @mention or a #123 reference gets a
//     zero-width space after the @ or #;
//   - become a clickable link: "://" and "www." get a zero-width space too.
//
// The zero-width spaces are invisible but are copied with the text.
func mdEscape(s string) string {
	return mdEscaper.Replace(capCell(s))
}

// mdEscapeCode escapes a string shown inside a code span. Mentions, links and
// HTML are inert there, and backslash escapes would show literally, so only
// what can end the span or the table cell is handled.
func mdEscapeCode(s string) string {
	return codeEscaper.Replace(capCell(s))
}

// capCell cuts s to mdEscapeMaxLen bytes at a character boundary, so a cut
// never leaves half of a multi-byte character.
func capCell(s string) string {
	if len(s) <= mdEscapeMaxLen {
		return s
	}
	cut := mdEscapeMaxLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

const zwsp = "\u200b"

var mdEscaper = strings.NewReplacer(
	"\\", "\\\\",
	"|", "\\|",
	"`", "'",
	"\r", "␍",
	"\n", "␊",
	"\t", " ",
	"<", "&lt;",
	">", "&gt;",
	"&", "&amp;",
	"[", "\\[",
	"]", "\\]",
	"*", "\\*",
	"_", "\\_",
	"~", "\\~",
	"@", "@"+zwsp,
	"#", "#"+zwsp,
	"://", ":"+zwsp+"//",
	"www.", "www"+zwsp+".",
)

var codeEscaper = strings.NewReplacer(
	"|", "\\|",
	"`", "'",
	"\r", "␍",
	"\n", "␊",
	"\t", " ",
)
