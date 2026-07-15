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
func newFirewall(_ *policy.Policy) (firewall, error) {
	return nil, fmt.Errorf("egress enforcement requires Linux/nftables; this is %s", runtime.GOOS)
}
