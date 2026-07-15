//go:build e2e

// Package e2e exercises the built egret binary end to end against a real kernel.
//
// These tests require Linux 5.8+, root (eBPF + nftables), and a prior
// `make generate` so the eBPF objects are embedded. Run them explicitly:
//
//	sudo -E env "PATH=$PATH" go test -tags e2e ./test/...
//
// They are excluded from the default build by the e2e tag.
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/NX1X/Egret/internal/event"
)

func requireRootLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("e2e requires Linux, have %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("e2e requires root (eBPF + nftables); re-run under sudo")
	}
}

// buildEgret compiles the binary into a temp dir and returns its path.
func buildEgret(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "egret")
	cmd := exec.Command("go", "build", "-o", bin, "../cmd/egret")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("building egret (did you run `make generate`?): %v", err)
	}
	return bin
}

// TestAuditRecordsEgress runs a workload that makes an outbound connection and
// asserts egret recorded it in the JSON report.
func TestAuditRecordsEgress(t *testing.T) {
	requireRootLinux(t)
	bin := buildEgret(t)

	workdir := t.TempDir()
	policyPath := filepath.Join(workdir, "policy.yaml")
	os.WriteFile(policyPath, []byte(`
version: 1
mode: audit
egress:
  allowed-endpoints: [github.com]
  block-raw-ip: true
report:
  format: [json]
  output-dir: `+filepath.Join(workdir, "report")+`
  github-job-summary: false
`), 0o644)

	ctx, cancel := contextTimeout(60 * time.Second)
	defer cancel()

	// A workload that resolves + connects out. `|| true` so a network hiccup
	// doesn't fail the build under test; we assert on what egret observed.
	cmd := exec.CommandContext(ctx, bin, "run",
		"--config", policyPath, "--mode", "audit",
		"--", "/bin/sh", "-c", "getent hosts github.com >/dev/null; curl -sS -m 20 https://github.com >/dev/null || true")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("egret run: %v", err)
	}

	report := readReport(t, filepath.Join(workdir, "report", "report.json"))
	if len(report.Connections) == 0 {
		t.Fatal("expected at least one recorded connection")
	}
	t.Logf("recorded %d connections, %d violations",
		len(report.Connections), len(report.Violations))
}

// TestExitCodePropagates asserts egret forwards the wrapped command's exit code.
func TestExitCodePropagates(t *testing.T) {
	requireRootLinux(t)
	bin := buildEgret(t)

	cmd := exec.Command(bin, "run", "--mode", "audit", "--", "/bin/sh", "-c", "exit 7")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err := cmd.Run()

	var ee *exec.ExitError
	if !asExit(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("expected exit code 7 to propagate, got %v", err)
	}
}

func readReport(t *testing.T, path string) event.Session {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading report %s: %v", path, err)
	}
	var s event.Session
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("parsing report: %v", err)
	}
	return s
}
