//go:build linux

package cli

import "testing"

func TestBuildCredentialFromSudoUID(t *testing.T) {
	t.Setenv("SUDO_UID", "1000")
	t.Setenv("SUDO_GID", "1001")
	cred, warn := buildCredential()
	if cred == nil {
		t.Fatalf("expected a credential, got warn=%q", warn)
	}
	if cred.Uid != 1000 || cred.Gid != 1001 {
		t.Errorf("cred = uid %d gid %d, want 1000/1001", cred.Uid, cred.Gid)
	}
	if !cred.NoSetGroups {
		t.Error("NoSetGroups should be set to avoid inheriting root's supplementary groups")
	}
}

func TestBuildCredentialRefusesRootAndMissing(t *testing.T) {
	// uid 0 must not be accepted (running the build as root defeats confinement).
	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "0")
	t.Setenv("EGRET_BUILD_UID", "")
	if cred, warn := buildCredential(); cred != nil {
		t.Errorf("uid 0 accepted (%+v); must warn instead", cred)
	} else if warn == "" {
		t.Error("expected a warning when no non-root uid is available")
	}

	// No env at all -> warn, no credential.
	t.Setenv("SUDO_UID", "")
	if cred, warn := buildCredential(); cred != nil || warn == "" {
		t.Errorf("no uid env should warn; got cred=%v warn=%q", cred, warn)
	}
}

func TestBuildCredentialExplicitOverride(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("EGRET_BUILD_UID", "1500")
	t.Setenv("EGRET_BUILD_GID", "1600")
	cred, _ := buildCredential()
	if cred == nil || cred.Uid != 1500 || cred.Gid != 1600 {
		t.Errorf("explicit override cred = %+v, want uid 1500 gid 1600", cred)
	}
}
