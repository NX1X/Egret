//go:build linux

package cli

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// The build's resolver is pinned to Egret's DNS proxy inside a private mount
// namespace that only the build sees:
//
//   - /etc/resolv.conf is bind-mounted over by a per-run file that names the
//     proxy as the only nameserver.
//   - /run/systemd/resolve is covered by an empty tmpfs, so the build cannot
//     reach systemd-resolved through its varlink socket (nss-resolve) and the
//     stub-resolv.conf symlink target also names the proxy.
//   - /run/nscd is covered the same way. glibc asks nscd before it reads
//     resolv.conf, and a host nscd resolves any name.
//
// Without this, a GitHub-hosted runner resolves through systemd-resolved at
// 127.0.0.53, the proxy sees no query, every connection is reported as raw-IP
// egress, and block mode drops allowlisted hosts. The host's own mounts are
// never changed: the mounts happen after unshare(CLONE_NEWNS), and the Go
// runtime marks / as MS_PRIVATE there, so nothing propagates back.
//
// D-Bus is left alone (decided 2026-10-14): a tool that calls resolved over
// the system bus (resolvectl) still bypasses the proxy. Block mode's
// default-deny still stops the connection to a name the proxy never resolved,
// but the query itself can carry data out (a known residual). So can a
// connect() to resolved's socket through /proc/<pid>/root of a same-uid
// process outside the namespace.

// runFileBase is where the per-run resolv.conf is written: root-owned and not
// writable by the build user. Not $TMPDIR, which a caller may point into a
// directory a same-uid process controls. A var so tests can use a temp dir.
var runFileBase = "/run"

const (
	etcResolvConf   = "/etc/resolv.conf"
	resolvedRunDir  = "/run/systemd/resolve"
	nscdRunDir      = "/run/nscd"
	resolvConfFlag  = "resolv-conf"
	execPinnedName  = "__exec-pinned"
	resolvConfLabel = "# Written by Egret for this run: every DNS query goes to Egret's proxy.\n"
)

// buildResolvConf returns the resolv.conf the build sees: the proxy as the only
// nameserver, plus the host's search, domain and options lines so short names
// and resolver options keep working. Host nameserver lines are dropped.
func buildResolvConf(host io.Reader, proxyIP string) string {
	var b strings.Builder
	b.WriteString(resolvConfLabel)
	fmt.Fprintf(&b, "nameserver %s\n", proxyIP)
	if host == nil {
		return b.String()
	}
	sc := bufio.NewScanner(host)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "search", "domain", "options":
			b.WriteString(strings.Join(fields, " "))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// writeRunResolvConf writes the build's resolv.conf to a new root-owned 0700
// directory and returns its path and a cleanup func. The file is 0644 so the
// non-root build user can read it through the bind mount; the build cannot
// change it.
func writeRunResolvConf(dnsAddr string) (string, func(), error) {
	host, _, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		return "", nil, fmt.Errorf("dns proxy address %q: %w", dnsAddr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", nil, fmt.Errorf("dns proxy address %q is not a loopback address", dnsAddr)
	}
	var content string
	if f, err := os.Open(etcResolvConf); err == nil {
		content = buildResolvConf(f, host)
		_ = f.Close()
	} else {
		content = buildResolvConf(nil, host)
	}
	dir, err := os.MkdirTemp(runFileBase, "egret-dns-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		cleanup()
		return "", nil, err
	}
	// WriteFile applies the umask; set the mode explicitly.
	if err := os.Chmod(path, 0o644); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// pinResolver applies the mounts described above. It must run as root, in the
// trampoline, after unshare(CLONE_NEWNS) and before the privilege drop.
func pinResolver(resolvConf string) error {
	// Never change mounts in the host's namespace. The trampoline's parent is
	// the egret process, which stays in the host namespace; if ours is the same,
	// the unshare did not happen and the mounts would hit the whole host.
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("reading own mount namespace: %w", err)
	}
	parent, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", os.Getppid()))
	if err != nil {
		return fmt.Errorf("reading parent mount namespace: %w", err)
	}
	if self == parent {
		return fmt.Errorf("not in a private mount namespace (%s); refusing to change mounts", self)
	}
	// Also compare with pid 1, in case the parent is gone and this process was
	// reparented. Egret never runs as pid 1 of the namespace it guards.
	if init, err := os.Readlink("/proc/1/ns/mnt"); err != nil || init == self {
		return fmt.Errorf("cannot confirm a private mount namespace (%s); refusing to change mounts", self)
	}

	content, err := os.ReadFile(resolvConf)
	if err != nil {
		return fmt.Errorf("reading %s: %w", resolvConf, err)
	}

	// Lstat, not Stat: only cover a real directory, never follow a symlink.
	if fi, err := os.Lstat(resolvedRunDir); err == nil && fi.IsDir() {
		if err := unix.Mount("tmpfs", resolvedRunDir, "tmpfs",
			unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=64k"); err != nil {
			return fmt.Errorf("covering %s: %w", resolvedRunDir, err)
		}
		// /etc/resolv.conf is usually a symlink to one of these. Create both, so
		// the symlink resolves inside the tmpfs and the bind mount below has a
		// target.
		for _, name := range []string{"stub-resolv.conf", "resolv.conf"} {
			if err := os.WriteFile(filepath.Join(resolvedRunDir, name), content, 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", name, err)
			}
		}
	}

	if fi, err := os.Lstat(nscdRunDir); err == nil && fi.IsDir() {
		if err := unix.Mount("tmpfs", nscdRunDir, "tmpfs",
			unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=16k"); err != nil {
			return fmt.Errorf("covering %s: %w", nscdRunDir, err)
		}
	}

	// mount(2) follows a symlink at the target, so this covers the file that
	// /etc/resolv.conf points to, in this namespace only.
	if err := unix.Mount(resolvConf, etcResolvConf, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind-mounting over %s: %w", etcResolvConf, err)
	}
	if err := unix.Mount("", etcResolvConf, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("making %s read-only: %w", etcResolvConf, err)
	}

	// Confirm what the build will read.
	got, err := os.ReadFile(etcResolvConf)
	if err != nil {
		return fmt.Errorf("reading back %s: %w", etcResolvConf, err)
	}
	if string(got) != string(content) {
		return fmt.Errorf("%s does not show Egret's resolver after the mount", etcResolvConf)
	}
	return nil
}
