//go:build !linux

package enforcer

import (
	"fmt"
	"runtime"

	"github.com/NX1X/Egret/internal/policy"
)

// newFirewall on non-Linux returns an error: block-mode enforcement needs
// nftables. The CLI blocks before reaching here, but the symbol must exist for
// the package to compile cross-platform.
func newFirewall(_ *policy.Policy, _ string, _ *buildCgroup) (firewall, error) {
	return nil, fmt.Errorf("egress enforcement requires Linux/nftables; this is %s", runtime.GOOS)
}

// buildCgroup does not exist off Linux. These methods let the Enforcer treat a
// nil cgroup the same on every platform.
type buildCgroup struct{}

func newBuildCgroup(string) (*buildCgroup, error) {
	return nil, fmt.Errorf("a build cgroup requires Linux cgroup v2; this is %s", runtime.GOOS)
}

func (*buildCgroup) fd() int      { return -1 }
func (*buildCgroup) id() uint64   { return 0 }
func (*buildCgroup) Kill()        {}
func (*buildCgroup) Close() error { return nil }
