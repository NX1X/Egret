//go:build unix

package report

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

// buildWritableDir returns a temp directory that a non-root build could write
// (mode 0777, like /tmp without the sticky bit), which is where an attacker
// plants symlinks. A plain t.TempDir() is not enough: when the tests run as root
// (CI runs them under the action, through sudo) it is root-owned 0700, and a
// symlink there is correctly TRUSTED, because only root could have planted it.
func buildWritableDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatal(err)
	}
	return d
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
	base := buildWritableDir(t)
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
	base := buildWritableDir(t)
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
	base := buildWritableDir(t)
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

// The owner rule, as a pure function (a file owned by a third uid cannot be
// created without root, so the refusal case is tested here).
func TestSummaryOwnerAllowed(t *testing.T) {
	u := func(n uint32) *uint32 { return &n }
	for _, tc := range []struct {
		name                  string
		owner, dirOwner, euid uint32
		sudo                  *uint32
		want                  bool
	}{
		{"sudo user's own file (hosted runner)", 1001, 1001, 0, u(1001), true},
		{"container job: root egret, runner-owned dir", 1001, 1001, 0, nil, true},
		{"rootful run, root-owned file", 0, 0, 0, nil, true},
		{"third user's file in the runner's dir", 2002, 1001, 0, u(1001), false},
		{"third user's file, no sudo, non-root egret", 2002, 1001, 1001, nil, false},
	} {
		if got := summaryOwnerAllowed(tc.owner, tc.dirOwner, tc.sudo, tc.euid); got != tc.want {
			t.Errorf("%s: summaryOwnerAllowed = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Review finding: a FIFO at the summary path blocked the open forever, because
// the build is dead and no reader exists. It must fail at once instead.
func TestJobSummaryDoesNotHangOnAFIFO(t *testing.T) {
	summary := filepath.Join(t.TempDir(), "step_summary")
	if err := unix.Mkfifo(summary, 0o644); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	done := make(chan error, 1)
	go func() { done <- appendJobSummary("x") }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("appendJobSummary reported success writing to a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("appendJobSummary blocked on a FIFO")
	}
}

// Review finding: report.json is the verdict the action counts. A policy whose
// report.format omits json must still produce it.
func TestWriteAlwaysWritesReportJSON(t *testing.T) {
	out := t.TempDir()
	pol := polWithOutput(out)
	pol.Report.Format = []string{"markdown"}
	if err := Write(sampleSession(), pol); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "report.json")); err != nil {
		t.Errorf("report.json missing with format [markdown]: %v", err)
	}
}

// Review finding: the job summary is a convenience view, not the verdict. An
// unsafe summary path must be refused WITHOUT failing an otherwise clean run.
func TestWriteSucceedsWhenTheJobSummaryIsRefused(t *testing.T) {
	victim := newVictim(t)
	summary := filepath.Join(t.TempDir(), "step_summary")
	if err := os.Symlink(victim, summary); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	out := t.TempDir()
	pol := polWithOutput(out)
	pol.Report.GitHubJobSummary = true
	if err := Write(sampleSession(), pol); err != nil {
		t.Fatalf("Write failed because of the job summary: %v", err)
	}
	assertVictimUnchanged(t, victim)
	if _, err := os.Stat(filepath.Join(out, "report.json")); err != nil {
		t.Errorf("report.json missing: %v", err)
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
