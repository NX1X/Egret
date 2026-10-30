//go:build linux

package cli

import (
	"os"
	"strings"
	"testing"
)

// The wrapped build is untrusted by construction. If either of these ever reaches
// it, a hostile dependency can read the caller's credentials straight out of its
// own environment - no /proc walk, no privilege needed.
func TestSanitizedEnvironDropsEgretCredentials(t *testing.T) {
	t.Setenv("EGRET_INGEST_TOKEN", "ingest-secret")
	t.Setenv("EGRET_GITHUB_TOKEN", "github-secret")
	t.Setenv("EGRET_INGEST_URL", "https://dashboard.example/ingest")
	t.Setenv("PATH", "/usr/bin")

	got := sanitizedEnviron()

	for _, kv := range got {
		if strings.HasPrefix(kv, "EGRET_INGEST_TOKEN=") || strings.HasPrefix(kv, "EGRET_GITHUB_TOKEN=") {
			t.Errorf("credential leaked into the child environment: %q", kv)
		}
		if strings.Contains(kv, "ingest-secret") || strings.Contains(kv, "github-secret") {
			t.Errorf("secret VALUE leaked under another key: %q", kv)
		}
	}

	// Non-credential variables must survive - including EGRET_INGEST_URL, which is
	// not itself a secret and which the build is allowed to see.
	want := map[string]bool{
		"EGRET_INGEST_URL=https://dashboard.example/ingest": false,
		"PATH=/usr/bin": false,
	}
	for _, kv := range got {
		if _, ok := want[kv]; ok {
			want[kv] = true
		}
	}
	for kv, seen := range want {
		if !seen {
			t.Errorf("sanitizedEnviron dropped a non-credential variable: %q", kv)
		}
	}
}

// Egret reads the token from its OWN environment after the build exits, so
// filtering the child must not disturb the parent.
func TestSanitizedEnvironLeavesParentIntact(t *testing.T) {
	t.Setenv("EGRET_INGEST_TOKEN", "ingest-secret")

	_ = sanitizedEnviron()

	if got := os.Getenv("EGRET_INGEST_TOKEN"); got != "ingest-secret" {
		t.Errorf("parent environment was mutated: EGRET_INGEST_TOKEN = %q, want %q", got, "ingest-secret")
	}
}

func TestIsSecretEnv(t *testing.T) {
	cases := []struct {
		kv   string
		want bool
	}{
		{"EGRET_INGEST_TOKEN=x", true},
		{"EGRET_GITHUB_TOKEN=x", true},
		{"EGRET_INGEST_TOKEN=", true}, // empty value is still the credential key
		{"EGRET_INGEST_URL=https", false},
		{"EGRET_MODE=block", false},
		{"PATH=/usr/bin", false},
		// Prefix matching is on "KEY=", so a longer name that merely starts with a
		// credential name must not be swallowed.
		{"EGRET_INGEST_TOKEN_FILE=/tmp/t", false},
	}
	for _, c := range cases {
		if got := isSecretEnv(c.kv); got != c.want {
			t.Errorf("isSecretEnv(%q) = %v, want %v", c.kv, got, c.want)
		}
	}
}

func TestGuardedEnvironDropsSessionBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1001/bus")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1001")
	t.Setenv("EGRET_INGEST_TOKEN", "secret")
	t.Setenv("KEEP_ME", "1")
	got := strings.Join(guardedEnviron(), "\n")
	for _, gone := range []string{"DBUS_SESSION_BUS_ADDRESS=", "XDG_RUNTIME_DIR=", "EGRET_INGEST_TOKEN="} {
		if strings.Contains(got, gone) {
			t.Errorf("guardedEnviron kept %s", gone)
		}
	}
	if !strings.Contains(got, "KEEP_ME=1") {
		t.Error("guardedEnviron dropped an ordinary variable")
	}
}
