//go:build linux

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
)

// disableSudoDropIn is the sudoers.d path Egret writes to revoke the build user's
// sudo. The "zz-" prefix sorts it LAST in sudoers.d so its deny is the final match
// (sudoers is last-match-wins), overriding an earlier NOPASSWD grant for the user.
const disableSudoDropIn = "/etc/sudoers.d/zz-egret-no-sudo"

// sudoersDenyContent returns the sudoers drop-in that denies username every sudo
// command. Kept pure so the exact rendered policy is unit-testable. `!ALL` as the
// command list is an explicit deny; being the last-matching rule, it wins.
func sudoersDenyContent(username string) string {
	return fmt.Sprintf("# egret --disable-sudo: revoke sudo for the build user during this run.\n"+
		"# Auto-removed at teardown. Sorts last in sudoers.d so this deny is the final match.\n"+
		"%s ALL=(ALL:ALL) !ALL\n", username)
}

// applyDisableSudo revokes passwordless sudo for the build uid by writing a
// validated sudoers drop-in, and returns a restore func that removes it. Egret
// must be root (it is, in block mode). Fail-closed: if the file can't be written
// or does not pass `visudo -cf`, it is removed and an error returned so the caller
// aborts - the build never runs with the sudo the operator asked to remove.
//
// NOTE (needs the live re-gate): sudoers precedence (last-match / sudoers.d lexical
// order) and the exact grant location vary by distro/runner. This is validated with
// visudo, but the *effectiveness* of the deny (that `sudo -n` actually fails for the
// build user afterwards) must be confirmed on a real runner before it's relied on.
func applyDisableSudo(uid int) (restore func(), err error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("must be root to modify sudoers (got euid %d)", os.Geteuid())
	}
	if uid == 0 {
		return nil, fmt.Errorf("refusing to target uid 0")
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("resolving build uid %d: %w", uid, err)
	}

	content := sudoersDenyContent(u.Username)
	// Write 0440 root:root (sudoers refuses group/world-writable drop-ins).
	if err := os.WriteFile(disableSudoDropIn, []byte(content), 0o440); err != nil {
		return nil, fmt.Errorf("writing %s: %w", disableSudoDropIn, err)
	}
	cleanup := func() { _ = os.Remove(disableSudoDropIn) }

	// Validate: a malformed drop-in would make ALL sudo fail, so never leave an
	// unvalidated file in place. visudo -cf checks just this file.
	if _, lookErr := exec.LookPath("visudo"); lookErr == nil {
		if out, verr := exec.Command("visudo", "-cf", disableSudoDropIn).CombinedOutput(); verr != nil {
			cleanup()
			return nil, fmt.Errorf("visudo rejected the drop-in (%v): %s", verr, out)
		}
	} else {
		// No visudo to validate with: refuse rather than risk a bad sudoers file.
		cleanup()
		return nil, fmt.Errorf("visudo not found; refusing to edit sudoers unvalidated")
	}
	return cleanup, nil
}
