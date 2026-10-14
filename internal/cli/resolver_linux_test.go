//go:build linux

package cli

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestBuildResolvConf(t *testing.T) {
	host := `# managed by systemd-resolved
nameserver 127.0.0.53
nameserver 10.0.0.2
options edns0 trust-ad
search abc.internal.cloudapp.net
domain example.internal
sortlist 10.0.0.0/8
`
	got := buildResolvConf(strings.NewReader(host), "127.53.1.2")
	want := resolvConfLabel +
		"nameserver 127.53.1.2\n" +
		"options edns0 trust-ad\n" +
		"search abc.internal.cloudapp.net\n" +
		"domain example.internal\n"
	if got != want {
		t.Errorf("buildResolvConf =\n%s\nwant\n%s", got, want)
	}
	if n := strings.Count(got, "nameserver"); n != 1 {
		t.Errorf("got %d nameserver lines, want exactly the proxy", n)
	}
	if got := buildResolvConf(nil, "127.53.1.2"); got != resolvConfLabel+"nameserver 127.53.1.2\n" {
		t.Errorf("buildResolvConf(nil) = %q", got)
	}
}

func TestWriteRunResolvConf(t *testing.T) {
	path, cleanup, err := writeRunResolvConf("127.53.1.2:53")
	if err != nil {
		t.Fatalf("writeRunResolvConf: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644 (readable by the build, writable by Egret only)", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "nameserver 127.53.1.2\n") {
		t.Errorf("content = %q, want the proxy as nameserver", b)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup left %s", path)
	}

	for _, bad := range []string{"10.0.0.1:53", "nope", "example.com:53"} {
		if _, _, err := writeRunResolvConf(bad); err == nil {
			t.Errorf("writeRunResolvConf(%q) = nil error, want refusal", bad)
		}
	}
}

// pinResolver must refuse to touch mounts in the host's namespace. Without a
// prior unshare, the test process shares its parent's mount namespace.
func TestPinResolverRefusesHostNamespace(t *testing.T) {
	self, err1 := os.Readlink("/proc/self/ns/mnt")
	parent, err2 := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/mnt")
	if err1 != nil || err2 != nil || self != parent {
		t.Skip("cannot compare mount namespaces with the parent here")
	}
	err := pinResolver("/nonexistent")
	if err == nil || !strings.Contains(err.Error(), "not in a private mount namespace") {
		t.Fatalf("pinResolver in the host namespace = %v, want refusal", err)
	}
}
