package report

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

func sampleSession() *event.Session {
	return &event.Session{
		StartedAt:  time.Unix(1000, 0),
		FinishedAt: time.Unix(1003, 0),
		Command:    []string{"./build.sh"},
		Mode:       "block",
		ExitCode:   0,
		Connections: []event.Connection{
			{PID: 1, Comm: "curl", Daddr: net.IPv4(140, 82, 121, 4), Dport: 443, Proto: "tcp", Domain: "github.com"},
			{PID: 2, Comm: "ev|il", Daddr: net.IPv4(8, 8, 8, 8), Dport: 53, Proto: "udp"},
		},
		FileWrites: []event.FileWrite{{PID: 3, Comm: "sh", Path: "/etc/passwd", Op: "open-write"}},
		Processes:  []event.Process{{PID: 3, PPID: 1, Comm: "sh", Filename: "/bin/sh"}},
		Violations: []event.Violation{
			{Kind: event.KindConnection, Reason: "raw-ip egress", Detail: "8.8.8.8:53", Blocked: true},
		},
	}
}

func TestMarkdownWithViolations(t *testing.T) {
	md := Markdown(sampleSession())
	for _, want := range []string{
		"# 🪶 Egret report",
		"`./build.sh`",
		"github.com (140.82.121.4)",
		"/etc/passwd",
		"/bin/sh",
		"raw-ip egress",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, md)
		}
	}
	// Pipe in a comm must be escaped so the table isn't broken.
	if strings.Contains(md, "| ev|il |") {
		t.Error("unescaped pipe leaked into a table cell")
	}
	if !strings.Contains(md, "ev\\|il") {
		t.Error("expected escaped pipe in cell")
	}
}

func TestMarkdownRedactsCommandArgs(t *testing.T) {
	// A token inlined as a command argument must NOT appear in the report Markdown
	// (which is appended to the unmasked, possibly-public job summary).
	s := &event.Session{Mode: "audit", Command: []string{"deploy", "--token", "s3cr3t-TOKEN"}}
	md := Markdown(s)
	if strings.Contains(md, "s3cr3t-TOKEN") {
		t.Errorf("secret argument leaked into report markdown:\n%s", md)
	}
	if !strings.Contains(md, "`deploy`") {
		t.Errorf("program name should still be shown:\n%s", md)
	}
	if !strings.Contains(md, "argument(s) omitted") {
		t.Errorf("expected redaction note:\n%s", md)
	}
}

func TestMarkdownNoViolations(t *testing.T) {
	s := &event.Session{Mode: "audit", Command: []string{"true"}}
	md := Markdown(s)
	if !strings.Contains(md, "✅ No violations") {
		t.Errorf("expected clean banner, got:\n%s", md)
	}
}

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.md")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)

	pol := policy.Default()
	pol.Report.OutputDir = filepath.Join(dir, "out")

	if err := Write(sampleSession(), pol); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// JSON report must exist and round-trip.
	jb, err := os.ReadFile(filepath.Join(pol.Report.OutputDir, "report.json"))
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	var got event.Session
	if err := json.Unmarshal(jb, &got); err != nil {
		t.Fatalf("json not valid: %v", err)
	}
	if len(got.Connections) != 2 {
		t.Errorf("round-tripped connections = %d, want 2", len(got.Connections))
	}

	// Markdown report exists.
	if _, err := os.Stat(filepath.Join(pol.Report.OutputDir, "report.md")); err != nil {
		t.Errorf("report.md missing: %v", err)
	}

	// Job summary was appended.
	sb, err := os.ReadFile(summary)
	if err != nil || !strings.Contains(string(sb), "Egret report") {
		t.Errorf("job summary not written: %v / %q", err, string(sb))
	}
}

func TestWriteJSONOnly(t *testing.T) {
	dir := t.TempDir()
	pol := policy.Default()
	pol.Report.OutputDir = dir
	pol.Report.Format = []string{"json"}
	pol.Report.GitHubJobSummary = false

	if err := Write(sampleSession(), pol); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.md")); !os.IsNotExist(err) {
		t.Error("report.md should NOT be written when format is json-only")
	}
}

func TestMdEscape(t *testing.T) {
	if got := mdEscape("a|b`c"); got != "a\\|b'c" {
		t.Errorf("mdEscape = %q", got)
	}
}

func TestMdEscapeNeutralizesNewlines(t *testing.T) {
	// A hostile filename injecting a fake table row/header must not survive with
	// real newlines - otherwise it forges rows in the report reviewers trust.
	in := "evil\n\n## ✅ No violations\n| a | b |"
	got := mdEscape(in)
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("mdEscape left a raw newline in %q", got)
	}
}

func TestMdEscapeCapsLength(t *testing.T) {
	got := mdEscape(strings.Repeat("x", mdEscapeMaxLen+100))
	if len([]rune(got)) > mdEscapeMaxLen+1 { // +1 for the ellipsis
		t.Errorf("mdEscape did not cap length: got %d runes", len([]rune(got)))
	}
}

func TestCapSummary(t *testing.T) {
	small := "# Egret\n\nshort\n"
	if got := capSummary(small); got != small {
		t.Errorf("a small summary must pass unchanged, got %q", got)
	}

	// About 1.5 MiB of table rows, like the website job that GitHub refused.
	var b strings.Builder
	b.WriteString("# Egret report\n\n| proc | dst |\n|---|---|\n")
	for b.Len() < 1536<<10 {
		b.WriteString("| curl | 104.20.23.154:443 é |\n")
	}
	big := b.String()
	got := capSummary(big)
	if len(got) > maxSummaryBytes {
		t.Fatalf("capped summary is %d bytes, want at most %d", len(got), maxSummaryBytes)
	}
	if !strings.Contains(got, "Summary truncated") || !strings.Contains(got, "report.json") {
		t.Errorf("capped summary must say it was truncated and point to the full report")
	}
	if !utf8.ValidString(got) {
		t.Error("capped summary is not valid UTF-8 (a multi-byte character was split)")
	}
	body := strings.SplitN(got, "\n\n> **Summary truncated.**", 2)[0]
	if !strings.HasPrefix(big, body) || !strings.HasSuffix(body, "|") {
		t.Errorf("the summary must be cut after a whole row, got tail %q", body[len(body)-30:])
	}
}

func TestMarkdownRendersNotes(t *testing.T) {
	s := &event.Session{Mode: "audit", Notes: []string{"The build used a container client."}}
	md := Markdown(s)
	if !strings.Contains(md, "## ℹ️ Notes") || !strings.Contains(md, "- The build used a container client.") {
		t.Fatalf("notes section missing:\n%s", md)
	}
	if strings.Contains(Markdown(&event.Session{Mode: "audit"}), "Notes") {
		t.Error("a session without notes must not render a Notes section")
	}
}

func TestMdEscapeNeutralisesMarkdown(t *testing.T) {
	cases := map[string]string{
		"a|b":                    `a\|b`,
		"x\n## ✅ No violations":  "x␊#\u200b#\u200b ✅ No violations",
		"<img src=x onerror=1>":  "&lt;img src=x onerror=1&gt;",
		"[click](https://evil)":  `\[click\](https:` + "\u200b" + `//evil)`,
		"ping @NX1X":             "ping @\u200bNX1X",
		"fixes #1":               "fixes #\u200b1",
		"www.evil.example":       "www\u200b.evil.example",
		`back\slash *b* _i_ ~s~`: `back\\slash \*b\* \_i\_ \~s\~`,
		"a&b":                    "a&amp;b",
		"`code`":                 "'code'",
	}
	for in, want := range cases {
		if got := mdEscape(in); got != want {
			t.Errorf("mdEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMdEscapeCutsAtCharacterBoundary(t *testing.T) {
	s := strings.Repeat("a", mdEscapeMaxLen-1) + "é" // é is 2 bytes and straddles the cap
	got := mdEscape(s)
	if !utf8.ValidString(got) {
		t.Fatalf("cut produced invalid UTF-8: %q", got[len(got)-8:])
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("a cut value must end with …")
	}
}

func TestRedactCommandKeepsCodeSpanReadable(t *testing.T) {
	if got := redactCommand([]string{"my_tool[1]"}); got != "`my_tool[1]`" {
		t.Errorf("code span got backslash escapes: %q", got)
	}
}
