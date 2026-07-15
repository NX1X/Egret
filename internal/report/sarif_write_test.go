package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NX1X/Egret/internal/event"
	"github.com/NX1X/Egret/internal/policy"
)

func TestWriteSARIF(t *testing.T) {
	dir := t.TempDir()
	pol := policy.Default()
	pol.Report.OutputDir = dir
	pol.Report.Format = []string{"sarif"}
	pol.Report.GitHubJobSummary = false

	s := &event.Session{
		Mode:       "block",
		Violations: []event.Violation{{Kind: event.KindConnection, Reason: "raw-ip egress", Detail: "8.8.8.8", Blocked: true}},
	}
	if err := Write(s, pol); err != nil {
		t.Fatalf("Write: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "report.sarif"))
	if err != nil {
		t.Fatalf("report.sarif missing: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("sarif not valid json: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("sarif version = %v", doc["version"])
	}
}
