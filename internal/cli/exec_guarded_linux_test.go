//go:build linux

package cli

import (
	"strings"
	"testing"
)

// TestExecGuardedRefusesRootTarget verifies the fail-closed guard: the trampoline
// must refuse to "drop" to uid 0 or gid 0 (which would defeat the whole boundary),
// returning an error BEFORE it touches any privilege syscall or execs anything.
func TestExecGuardedRefusesRootTarget(t *testing.T) {
	cases := []struct {
		name     string
		uid, gid int
	}{
		{"uid zero", 0, 1000},
		{"gid zero", 1000, 0},
		{"both zero", 0, 0},
		{"negative uid", -1, 1000},
		{"negative gid", 1000, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A harmless command; the guard must reject before it is ever reached.
			err := execGuarded(tc.uid, tc.gid, []string{"/bin/true"})
			if err == nil {
				t.Fatalf("execGuarded(uid=%d, gid=%d) = nil, want refusal", tc.uid, tc.gid)
			}
			if !strings.Contains(err.Error(), "non-root") {
				t.Errorf("error = %q, want a non-root refusal", err)
			}
		})
	}
}

// TestExecGuardedRegistered confirms the hidden trampoline command is wired into
// the root command tree on Linux (so `egret run` can re-exec into it).
func TestExecGuardedRegistered(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == execGuardedCmdName {
			found = true
			if !c.Hidden {
				t.Error("guarded trampoline should be a hidden command")
			}
		}
	}
	if !found {
		t.Errorf("%s not registered on the root command", execGuardedCmdName)
	}
}

// TestSelfProbeRegistered confirms the hidden F-C self-probe command is wired in.
func TestSelfProbeRegistered(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == selfProbeCmdName {
			found = true
			if !c.Hidden {
				t.Error("self-probe should be a hidden command")
			}
		}
	}
	if !found {
		t.Errorf("%s not registered on the root command", selfProbeCmdName)
	}
}
