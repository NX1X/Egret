package report

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
