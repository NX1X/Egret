//go:build linux

package enforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// cgroupRoot is the cgroup-v2 unified mount.
const cgroupRoot = "/sys/fs/cgroup"

// buildCgroup is a dedicated cgroup-v2 the monitored command is placed into, so
// the nftables egress filter can scope to the build (via `socket cgroupv2`) and
// leave Egret's own traffic - notably the DNS proxy's upstream query - unfiltered.
//
// Placement is guaranteed by the kernel: the build is created directly inside this
// cgroup via clone3(CLONE_INTO_CGROUP) (SysProcAttr.UseCgroupFD). If that fails the
// exec fails and the run aborts - fail-closed, no unconfined build ever runs.
//
// The nft match is computed from the cgroup's ACTUAL path/depth (not a hardcoded
// level), so it is correct whether the cgroup sits at the v2 root or under a
// delegated/nested subtree (netsec re-gate F3).
type buildCgroup struct {
	relPath string   // path from the v2 root, e.g. "egret-run-42" or "user.slice/…/egret-run-42"
	absPath string   // cgroupRoot + relPath
	level   int      // number of path components (nft `socket cgroupv2 level N`)
	dir     *os.File // kept open so .Fd() stays valid for SysProcAttr.UseCgroupFD
}

// newBuildCgroup creates the cgroup and opens its directory fd. Prefers a
// v2-root-level cgroup (simple, level 1); falls back to a child of Egret's own
// cgroup when the root is not writable (delegated/containerized). Requires cgroup
// v2 and root - both hold when block mode is active.
func newBuildCgroup() (*buildCgroup, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return nil, fmt.Errorf("cgroup v2 unified hierarchy not found at %s (block mode needs it): %w", cgroupRoot, err)
	}
	name := fmt.Sprintf("egret-run-%d", os.Getpid())

	candidates := []string{name} // v2-root level 1
	if own := ownCgroupRelPath(); own != "" {
		candidates = append(candidates, filepath.Join(own, name)) // delegation-safe fallback
	}

	var lastErr error
	for _, rel := range candidates {
		abs := filepath.Join(cgroupRoot, rel)
		if err := os.MkdirAll(abs, 0o755); err != nil {
			lastErr = err
			continue
		}
		dir, err := os.Open(abs)
		if err != nil {
			_ = os.Remove(abs)
			lastErr = err
			continue
		}
		return &buildCgroup{
			relPath: rel,
			absPath: abs,
			level:   len(strings.Split(strings.Trim(rel, "/"), "/")),
			dir:     dir,
		}, nil
	}
	return nil, fmt.Errorf("creating build cgroup: %w", lastErr)
}

// ownCgroupRelPath returns Egret's own cgroup path relative to the v2 root, from
// the unified ("0::") line of /proc/self/cgroup, or "" if it can't be determined.
func ownCgroupRelPath() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.Trim(strings.TrimPrefix(line, "0::"), "/")
		}
	}
	return ""
}

// nftMatch is the `socket cgroupv2 level N "path"` expression that matches sockets
// owned by processes in this cgroup, computed from its real depth.
func (c *buildCgroup) nftMatch() string {
	return fmt.Sprintf(`socket cgroupv2 level %d "%s"`, c.level, c.relPath)
}

// fd is the directory fd for SysProcAttr.UseCgroupFD.
func (c *buildCgroup) fd() int { return int(c.dir.Fd()) }

// Kill SIGKILLs every process still in the cgroup, so anything the build forked
// or daemonized that outlived the monitored command can't linger with a live
// socket after teardown. It writes "1" to cgroup.kill (kernel 5.14+), which kills
// the whole subtree atomically; on older kernels cgroup.kill is absent, so it
// falls back to SIGKILLing each pid listed in cgroup.procs. Best-effort - teardown
// continues regardless. (netsec F-E.)
func (c *buildCgroup) Kill() {
	if c == nil {
		return
	}
	// Preferred path (kernel 5.14+): atomic, race-free subtree kill.
	if err := os.WriteFile(filepath.Join(c.absPath, "cgroup.kill"), []byte("1"), 0); err == nil {
		return
	}
	// Pre-5.14 fallback: no cgroup.kill. Freeze the subtree FIRST so a task can't
	// fork a new (unlisted) child while we're killing - a plain read-then-kill would
	// let a build that re-forks during teardown leave a survivor. Freezing is
	// asynchronous, so we then loop read+SIGKILL until cgroup.procs is empty (each
	// pass kills anything that slipped in before the freeze fully took), and thaw at
	// the end so the killed tasks can exit and be reaped. Best-effort - a genuinely
	// race-free kill needs the 5.14 cgroup.kill above; this closes most of the
	// window on old kernels. (netsec F-E fallback finding.)
	freeze := filepath.Join(c.absPath, "cgroup.freeze")
	_ = os.WriteFile(freeze, []byte("1"), 0)
	defer func() { _ = os.WriteFile(freeze, []byte("0"), 0) }()
	for i := 0; i < 100; i++ {
		b, err := os.ReadFile(filepath.Join(c.absPath, "cgroup.procs"))
		if err != nil {
			return
		}
		pids := strings.Fields(strings.TrimSpace(string(b)))
		if len(pids) == 0 {
			return
		}
		for _, s := range pids {
			if pid, err := strconv.Atoi(s); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Close kills any lingering processes in the cgroup, then releases the fd and
// removes the directory. Called at teardown, after the monitored process exited.
// rmdir needs the cgroup empty, so we Kill first and briefly retry the remove
// while the kernel reaps the killed tasks.
func (c *buildCgroup) Close() error {
	if c == nil {
		return nil
	}
	c.Kill()
	_ = c.dir.Close()
	var err error
	for i := 0; i < 20; i++ {
		if err = os.Remove(c.absPath); err == nil || os.IsNotExist(err) {
			return nil
		}
		// EBUSY: tasks not yet reaped after the kill - give the kernel a moment.
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("removing build cgroup %s: %w", c.absPath, err)
}
