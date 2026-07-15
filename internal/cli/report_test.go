package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/sarif"
)

func writeReportJSON(t *testing.T, dir string) string {
	t.Helper()
	s := event.Session{
		Mode: "block",
		Violations: []event.Violation{
			{Kind: event.KindConnection, Reason: "domain not in allowlist", Detail: "evil.com", Blocked: true},
		},
	}
	p := filepath.Join(dir, "report.json")
	b, _ := json.Marshal(s)
	os.WriteFile(p, b, 0o644)
	return p
}

func TestReportSarif(t *testing.T) {
	dir := t.TempDir()
	from := writeReportJSON(t, dir)
	out := filepath.Join(dir, "egret.sarif")

	if _, err := run(t, "report", "--from", from, "--format", "sarif",
		"--out", out, "--policy-path", "policy.yaml"); err != nil {
		t.Fatalf("report sarif: %v", err)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading sarif: %v", err)
	}
	var log sarif.Log
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("sarif not valid json: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("sarif version = %q", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %+v", log.Runs)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("blocked violation should be error, got %q", log.Runs[0].Results[0].Level)
	}
}

func TestReportMarkdownToStdout(t *testing.T) {
	dir := t.TempDir()
	from := writeReportJSON(t, dir)

	out, err := run(t, "report", "--from", from, "--format", "markdown")
	if err != nil {
		t.Fatalf("report markdown: %v", err)
	}
	if !strings.Contains(out, "Egret report") {
		t.Errorf("markdown output = %q", out)
	}
}

func TestReportMissingFrom(t *testing.T) {
	if _, err := run(t, "report", "--format", "sarif"); err == nil {
		t.Error("expected error when --from is missing")
	}
}
