//go:build linux

package cli

import (
	"os"
	"strings"
	"testing"
)

// TestSudoersDenyContent: the rendered drop-in denies the named user all sudo and
// is a single valid-shape sudoers line (user + host=(runas) + !ALL).
func TestSudoersDenyContent(t *testing.T) {
	got := sudoersDenyContent("runner")
	if !strings.Contains(got, "runner ALL=(ALL:ALL) !ALL") {
		t.Errorf("deny line missing or wrong shape:\n%s", got)
	}
	// Every non-comment line must reference the user (no stray directives).
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "runner ") {
			t.Errorf("unexpected sudoers directive: %q", line)
		}
	}
}

// TestApplyDisableSudoRefusesNonRoot: fail-closed - without root (the normal test
// context) applyDisableSudo must error and NOT leave a sudoers drop-in behind.
func TestApplyDisableSudoRefusesNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; this test checks the non-root refusal path")
	}
	restore, err := applyDisableSudo(1000)
	if err == nil {
		if restore != nil {
			restore()
		}
		t.Fatal("expected refusal without root")
	}
	if _, statErr := os.Stat(disableSudoDropIn); statErr == nil {
		os.Remove(disableSudoDropIn)
		t.Fatal("a sudoers drop-in was left behind on the failure path")
	}
}

// TestApplyDisableSudoRefusesRootTarget: never target uid 0.
func TestApplyDisableSudoRefusesRootTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to reach the uid-0 guard (non-root fails earlier)")
	}
	if _, err := applyDisableSudo(0); err == nil {
		t.Error("expected refusal to target uid 0")
	}
}
