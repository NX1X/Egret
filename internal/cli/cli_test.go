package cli

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/event"
)

// run executes the root command with args, returning combined output and error.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestVersionCmd(t *testing.T) {
	out, err := run(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(out, "egret") {
		t.Errorf("version output = %q", out)
	}
}

func TestPolicyLint(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "p.yaml")
	os.WriteFile(good, []byte("version: 1\nmode: block\negress:\n  allowed-endpoints: [\"*.example.com\"]\n"), 0o644)

	out, err := run(t, "policy", "lint", "--config", good)
	if err != nil {
		t.Fatalf("lint valid: %v", err)
	}
	if !strings.Contains(out, "is valid") || !strings.Contains(out, "matches any.subdomain.example.com") {
		t.Errorf("lint output = %q", out)
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte("version: 5\n"), 0o644)
	if _, err := run(t, "policy", "lint", "--config", bad); err == nil {
		t.Error("expected error linting invalid policy")
	}

	if _, err := run(t, "policy", "lint"); err == nil {
		t.Error("expected error when --config is missing")
	}
}

func TestAuditCmd(t *testing.T) {
	dir := t.TempDir()
	session := event.Session{
		Connections: []event.Connection{
			{Domain: "github.com", Daddr: net.IPv4(1, 1, 1, 1)},
			{Daddr: net.IPv4(8, 8, 8, 8)},
		},
	}
	rep := filepath.Join(dir, "report.json")
	b, _ := json.Marshal(session)
	os.WriteFile(rep, b, 0o644)

	emit := filepath.Join(dir, "suggested.yaml")
	out, err := run(t, "audit", "--from", rep, "--emit", emit)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !strings.Contains(out, "github.com") {
		t.Errorf("audit output = %q", out)
	}
	yb, err := os.ReadFile(emit)
	if err != nil {
		t.Fatalf("emit not written: %v", err)
	}
	if !strings.Contains(string(yb), "github.com") || !strings.Contains(string(yb), "block") {
		t.Errorf("emitted policy = %q", string(yb))
	}

	if _, err := run(t, "audit"); err == nil {
		t.Error("expected error when --from is missing")
	}
}

func TestRunArgValidation(t *testing.T) {
	// No command at all.
	if _, err := run(t, "run"); err == nil {
		t.Error("expected error when no command given to run")
	}
	// Separator but nothing after it.
	if _, err := run(t, "run", "--"); err == nil {
		t.Error("expected error when nothing follows --")
	}
}
