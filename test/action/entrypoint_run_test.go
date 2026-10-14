//go:build linux

package action

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the real `entrypoint.sh run` with two stand-ins on PATH, so
// they need no root, no eBPF and no network:
//   - sudo: runs the command as the current user (and drops `install -o/-g`,
//     which an unprivileged test cannot honor);
//   - egret: writes a report like the real binary, and can also act as the
//     hostile build (replace the runner-owned binary, write no report).

const fakeSudo = `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  case "$1" in
    --) shift; break ;;
    -*) shift ;;
    *) break ;;
  esac
done
if [[ "$1" == install ]]; then
  shift; a=()
  while [[ $# -gt 0 ]]; do case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done
  exec install "${a[@]}"
fi
exec "$@"
`

const fakeEgret = `#!/usr/bin/env bash
sub="$1"; shift
case "$sub" in
  run)
    out=""
    while [[ $# -gt 0 ]]; do
      case "$1" in --output-dir) out="$2"; shift 2 ;; --) shift; break ;; *) shift ;; esac
    done
    if [[ -n "${FAKE_ENV_LOG:-}" ]]; then env > "${FAKE_ENV_LOG}"; fi
    if [[ -n "${FAKE_TAMPER_BIN:-}" ]]; then
      printf '#!/bin/sh\ntouch %s\n' "${FAKE_TAMPER_MARKER}" > "${FAKE_TAMPER_BIN}.new"
      chmod +x "${FAKE_TAMPER_BIN}.new"
      mv -f "${FAKE_TAMPER_BIN}.new" "${FAKE_TAMPER_BIN}"
    fi
    if [[ "${FAKE_WRITE_REPORT:-1}" == 1 ]]; then
      mkdir -p "${out}"
      v=""
      for ((i = 0; i < ${FAKE_VIOLATIONS:-0}; i++)); do v+="${v:+,}{\"kind\":\"connection\"}"; done
      printf '{"violations":[%s]}\n' "${v}" > "${out}/report.json"
    fi
    exit "${FAKE_RC:-0}"
    ;;
  report)
    o=""
    while [[ $# -gt 0 ]]; do case "$1" in --out) o="$2"; shift 2 ;; *) shift ;; esac; done
    echo '{}' > "${o}"
    ;;
  github) exit 0 ;;
  version) exit "${FAKE_VERSION_RC:-0}" ;;
esac
`

type runEnv struct {
	dir, shim, runnerTemp, bin, outdir, outputs string
}

func newRunEnv(t *testing.T) *runEnv {
	t.Helper()
	dir := t.TempDir()
	e := &runEnv{
		dir:        dir,
		shim:       filepath.Join(dir, "shim"),
		runnerTemp: filepath.Join(dir, "runner_temp"),
		outputs:    filepath.Join(dir, "github_output"),
	}
	e.bin = filepath.Join(e.runnerTemp, "egret", "egret")
	e.outdir = filepath.Join(e.runnerTemp, "egret", "report")
	for _, d := range []string{e.shim, e.outdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{filepath.Join(e.shim, "sudo"): fakeSudo, e.bin: fakeEgret} {
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(e.outputs, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *runEnv) run(t *testing.T, extra ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", entrypointPath(t), "run")
	cmd.Env = append([]string{
		"PATH=" + e.shim + ":" + os.Getenv("PATH"),
		"HOME=" + e.dir,
		"RUNNER_TEMP=" + e.runnerTemp,
		"GITHUB_OUTPUT=" + e.outputs,
		"EGRET_COMMAND=true",
		"EGRET_MODE=audit",
	}, extra...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		t.Fatalf("running entrypoint: %v", err)
		return "", -1
	}
}

// Regression: when no report was written, the old flow read the report.json in
// the build-writable output directory, or counted 0 violations, and exited with
// the build's own code. A build that planted a clean report and broke Egret's
// write passed fail-on-violations. The run must now fail closed.
func TestRunFailsClosedWhenEgretWritesNoReport(t *testing.T) {
	e := newRunEnv(t)
	planted := filepath.Join(e.outdir, "report.json")
	if err := os.WriteFile(planted, []byte(`{"violations":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := e.run(t, "FAKE_WRITE_REPORT=0", "FAKE_RC=0", "EGRET_FAIL_ON_VIOLATIONS=true")
	if code == 0 {
		t.Fatalf("run passed although Egret wrote no report:\n%s", out)
	}
	if !strings.Contains(out, "wrote no report") {
		t.Errorf("missing the fail-closed message:\n%s", out)
	}
}

// The violation count comes from the trusted report, and the caller still gets
// a copy in the usual report directory.
func TestRunCountsViolationsFromTheTrustedReport(t *testing.T) {
	e := newRunEnv(t)
	out, code := e.run(t, "FAKE_VIOLATIONS=2", "EGRET_FAIL_ON_VIOLATIONS=true")
	if code != 1 || !strings.Contains(out, "recorded 2 policy violation") {
		t.Fatalf("exit %d, want 1 with 2 violations:\n%s", code, out)
	}
	copied, err := os.ReadFile(filepath.Join(e.outdir, "report.json"))
	if err != nil || strings.Count(string(copied), `"kind"`) != 2 {
		t.Errorf("report-dir copy is wrong (err %v): %s", err, copied)
	}
	outputs, _ := os.ReadFile(e.outputs)
	if !strings.Contains(string(outputs), e.outdir) {
		t.Errorf("report-dir output does not point at %s:\n%s", e.outdir, outputs)
	}
}

// Regression: the post-run steps (SARIF, GitHub publishing with the caller's
// token) executed the binary in the runner-owned install directory, which a
// block-mode build can replace. They must run the root-owned copy instead.
func TestRunNeverExecutesABinaryTheBuildReplaced(t *testing.T) {
	e := newRunEnv(t)
	marker := filepath.Join(e.dir, "tampered-binary-ran")
	out, _ := e.run(t,
		"FAKE_TAMPER_BIN="+e.bin, "FAKE_TAMPER_MARKER="+marker,
		"EGRET_SARIF=true", "EGRET_CHECK_RUN=true", "EGRET_GITHUB_TOKEN=ghs_test",
	)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("a post-run step executed the binary the build replaced:\n%s", out)
	}
}

// Review finding: on a host whose temp dirs are mounted noexec, the copied
// binary cannot run. The action must say so clearly, not claim "wrote no report".
// (126 is what the shell returns for a binary it cannot execute.)
func TestRunExplainsWhenNoTrustedDirectoryCanExecute(t *testing.T) {
	e := newRunEnv(t)
	out, code := e.run(t, "FAKE_VERSION_RC=126")
	if code == 0 {
		t.Fatalf("run passed although the binary could not execute anywhere:\n%s", out)
	}
	if !strings.Contains(out, "no root-owned directory where its binary can execute") {
		t.Errorf("missing the noexec explanation:\n%s", out)
	}
	if strings.Contains(out, "wrote no report") {
		t.Errorf("shows the misleading no-report message:\n%s", out)
	}
}

func TestRunDoesNotPassTheGitHubTokenToTheBuild(t *testing.T) {
	e := newRunEnv(t)
	envLog := filepath.Join(e.dir, "run-env")
	if out, code := e.run(t, "EGRET_GITHUB_TOKEN=ghs_secret_value", "FAKE_ENV_LOG="+envLog); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	b, err := os.ReadFile(envLog)
	if err != nil {
		t.Fatalf("no env log: %v", err)
	}
	if strings.Contains(string(b), "ghs_secret_value") {
		t.Error("the run (and so the wrapped build) received the GitHub token")
	}
}
