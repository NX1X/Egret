//go:build unix

package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/policy"
)

// These tests plant what a hostile, non-root build can plant in the directories
// it owns, and check that Egret's writes (root in production) never land on the
// victim file. They need no root: the property is about which file is written.

const victimContent = "victim must not change\n"

func newVictim(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(p, []byte(victimContent), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertVictimUnchanged(t *testing.T, victim string) {
	t.Helper()
	b, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(b) != victimContent {
		t.Errorf("victim file was written through: %q", string(b))
	}
}

func polWithOutput(dir string) *policy.Policy {
	p := policy.Default()
	p.Report.OutputDir = dir
	p.Report.GitHubJobSummary = false
	return p
}

// Regression: only the LAST path component was checked, so a symlinked parent
// directory redirected root's report writes anywhere.
func TestWriteRefusesASymlinkedParentDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "egret")); err != nil {
		t.Fatal(err)
	}
	err := Write(sampleSession(), polWithOutput(filepath.Join(base, "egret", "report")))
	if err == nil {
		t.Fatal("Write succeeded through a symlinked parent directory")
	}
	if _, serr := os.Stat(filepath.Join(target, "report")); !os.IsNotExist(serr) {
		t.Errorf("Write created a directory inside the symlink target (stat err %v)", serr)
	}
}

func TestWriteRefusesASymlinkedOutputDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(base, "report")
	if err := os.Symlink(target, out); err != nil {
		t.Fatal(err)
	}
	if err := Write(sampleSession(), polWithOutput(out)); err == nil {
		t.Fatal("Write succeeded through a symlinked output directory")
	}
	if _, serr := os.Stat(filepath.Join(target, "report.json")); !os.IsNotExist(serr) {
		t.Error("report.json was written into the symlink target")
	}
}

// Regression: a build that creates a DIRECTORY named report.json made the write
// fail; the error was only logged, the violation count then read as 0, and
// fail-on-violations passed. Write must return the error.
func TestWriteFailsWhenReportJSONIsADirectory(t *testing.T) {
	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "report.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(sampleSession(), polWithOutput(out)); err == nil {
		t.Fatal("Write reported success although report.json could not be written")
	}
}

// A symlink planted at report.json must be REPLACED by the real report, never
// written through.
func TestWriteReplacesAPlantedReportSymlink(t *testing.T) {
	victim := newVictim(t)
	out := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(out, "report.json")); err != nil {
		t.Fatal(err)
	}
	if err := Write(sampleSession(), polWithOutput(out)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertVictimUnchanged(t, victim)
	fi, err := os.Lstat(filepath.Join(out, "report.json"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Errorf("report.json is not a regular file after Write (mode %v, err %v)", fi.Mode(), err)
	}
}

// Regression: the job summary was opened with O_CREATE and followed symlinks. As
// root, that let a build point the summary at /etc/ld.so.preload.
func TestJobSummaryRefusesASymlink(t *testing.T) {
	victim := newVictim(t)
	summary := filepath.Join(t.TempDir(), "step_summary")
	if err := os.Symlink(victim, summary); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("SUDO_UID", "")
	if err := appendJobSummary("injected"); err == nil {
		t.Error("appendJobSummary wrote through a symlink")
	}
	assertVictimUnchanged(t, victim)
}

func TestJobSummaryRefusesAHardLink(t *testing.T) {
	victim := newVictim(t)
	summary := filepath.Join(filepath.Dir(victim), "step_summary")
	if err := os.Link(victim, summary); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("SUDO_UID", "")
	if err := appendJobSummary("injected"); err == nil {
		t.Error("appendJobSummary wrote through a hard link")
	}
	assertVictimUnchanged(t, victim)
}

func TestJobSummaryRefusesASymlinkedParentDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(real, "step_summary")
	if err := os.WriteFile(victim, []byte(victimContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "file_commands")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(base, "file_commands", "step_summary"))
	t.Setenv("SUDO_UID", "")
	if err := appendJobSummary("injected"); err == nil {
		t.Error("appendJobSummary wrote through a symlinked parent directory")
	}
	assertVictimUnchanged(t, victim)
}

// Under sudo, the summary must belong to the user who started Egret. A file
// owned by anyone else (for example a root file the build got linked in) is
// refused. Simulated by claiming a different SUDO_UID.
func TestJobSummaryRefusesAFileNotOwnedByTheInvokingUser(t *testing.T) {
	summary := filepath.Join(t.TempDir(), "step_summary")
	if err := os.WriteFile(summary, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("SUDO_UID", strconv.Itoa(os.Geteuid()+4242))
	if err := appendJobSummary("injected"); err == nil {
		t.Error("appendJobSummary wrote to a file owned by another user")
	}
}

func TestJobSummaryAppendsToTheInvokingUsersFile(t *testing.T) {
	summary := filepath.Join(t.TempDir(), "step_summary")
	if err := os.WriteFile(summary, []byte("earlier step\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	t.Setenv("SUDO_UID", strconv.Itoa(os.Geteuid()))
	if err := appendJobSummary("egret report"); err != nil {
		t.Fatalf("appendJobSummary: %v", err)
	}
	b, _ := os.ReadFile(summary)
	if !strings.HasPrefix(string(b), "earlier step\n") || !strings.Contains(string(b), "egret report") {
		t.Errorf("summary content = %q", string(b))
	}
}
