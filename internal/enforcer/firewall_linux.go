//go:build linux

package enforcer

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/NX1X/Egret/internal/policy"
)

// selfProbeCanaryIP is an RFC 5737 TEST-NET-1 address - never a real destination,
// never allowlisted. A cgroup-scoped rule drops+counts packets to it; the self-probe
// sends one from the build cgroup and reads the counter to confirm the cgroup egress
// match actually fires for the build (fail-closed if it doesn't). (netsec F-C.)
//
// The probe is IPv4-only. That still validates the thing F-C is about - whether the
// `socket cgroupv2` match fires for THIS cgroup - because that match keys on the
// socket's cgroup, not the packet's L3 family (it is family-agnostic). IPv6
// non-allowlisted egress is denied by the same family-agnostic terminal `counter
// drop`. A v6-specific cgroup-match anomaly is a documented low-likelihood residual
// the container re-gate spot-checks (a v6 canary probe would false-abort on the many
// v4-only runners, so it is not required inline). (netsec self-probe #2.)
const selfProbeCanaryIP = "192.0.2.1"

// nftFirewall enforces default-deny egress by shelling out to `nft` (a native
// netlink library is a possible later optimization). It creates a dedicated
// inet table `egret` with v4+v6 allow sets so teardown is a single table drop.
//
// The filter is SCOPED to the monitored build's cgroup via `socket cgroupv2`, so
// Egret's own traffic - critically the DNS proxy's upstream query - is never
// filtered (otherwise block mode deadlocks: it can't resolve anything). The build
// is placed into that cgroup by run_linux.go via SysProcAttr.UseCgroupFD.
//
// Allow-set entries carry a TTL (from the DNS answer, clamped) so a stale or
// rebinding IP does not stay permitted for the whole run.
type nftFirewall struct {
	pol    *policy.Policy
	mu     sync.Mutex
	upDone bool
	table  string
	cg     *buildCgroup
}

func newFirewall(pol *policy.Policy) (firewall, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft not found in PATH (install nftables): %w", err)
	}
	cg, err := newBuildCgroup()
	if err != nil {
		return nil, err
	}
	return &nftFirewall{pol: pol, table: "egret", cg: cg}, nil
}

// BuildCgroupFD is the cgroup-v2 dir fd the monitored command joins.
func (f *nftFirewall) BuildCgroupFD() int { return f.cg.fd() }

// Setup installs the egret table: TTL-capable allow sets plus an output chain that
// subjects ONLY the build cgroup to default-deny (accept loopback + established +
// allow-set members, drop the rest); all other traffic falls through to accept.
func (f *nftFirewall) Setup(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// `sc` = the per-rule cgroup scope: match only the build's cgroup, at its real
	// depth (computed, not hardcoded) so it holds under delegated/nested cgroups.
	sc := f.cg.nftMatch()

	// A single nft script keeps the install atomic. The dynamic allow4/allow6 sets
	// (DNS-resolved IPs) use `flags timeout` + a bounded `size` so a rebinding/
	// flooding answer can't pin IPs or grow unbounded. The STATIC allow4cidr/
	// allow6cidr sets (`flags interval`) hold the operator's allowed-ips CIDRs; they
	// have no timeout (they're policy, not resolved) and are populated below. Their
	// accept rules sit before `counter drop`, so an allowed-ips destination is
	// permitted even with no DNS lookup.
	script := fmt.Sprintf(`
add table inet %[1]s
add set inet %[1]s allow4 { type ipv4_addr; flags timeout; size 4096; }
add set inet %[1]s allow6 { type ipv6_addr; flags timeout; size 4096; }
add set inet %[1]s allow4cidr { type ipv4_addr; flags interval; auto-merge; size 4096; }
add set inet %[1]s allow6cidr { type ipv6_addr; flags interval; auto-merge; size 4096; }
add counter inet %[1]s selfprobe
add chain inet %[1]s output { type filter hook output priority 0; policy accept; }
add rule inet %[1]s output %[2]s ct state established,related accept
add rule inet %[1]s output %[2]s oifname "lo" accept
add rule inet %[1]s output %[2]s udp dport 53 ip daddr 127.0.0.1 accept
add rule inet %[1]s output %[2]s ip daddr @allow4 accept
add rule inet %[1]s output %[2]s ip6 daddr @allow6 accept
add rule inet %[1]s output %[2]s ip daddr @allow4cidr accept
add rule inet %[1]s output %[2]s ip6 daddr @allow6cidr accept
add rule inet %[1]s output %[2]s ip daddr %[3]s counter name selfprobe drop
add rule inet %[1]s output %[2]s counter drop
`, f.table, sc, selfProbeCanaryIP)

	// Populate the static CIDR sets from the policy's allowed-ips. A bad CIDR here
	// would be caught at policy.Validate() long before this; each net stringifies to
	// canonical CIDR form (e.g. "10.0.0.0/8", "192.0.2.10/32").
	var v4, v6 []string
	for _, n := range f.pol.AllowedIPNets() {
		if n.IP.To4() != nil {
			v4 = append(v4, n.String())
		} else {
			v6 = append(v6, n.String())
		}
	}
	if len(v4) > 0 {
		script += fmt.Sprintf("add element inet %s allow4cidr { %s }\n", f.table, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		script += fmt.Sprintf("add element inet %s allow6cidr { %s }\n", f.table, strings.Join(v6, ", "))
	}

	if err := f.runNft(ctx, script); err != nil {
		return err
	}
	f.upDone = true
	return nil
}

// AllowIPs inserts resolved IPs into the appropriate (v4/v6) allow set with the
// given expiry. Re-resolution re-adds and thus refreshes the timeout.
func (f *nftFirewall) AllowIPs(domain string, ips []net.IP, ttlSeconds uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.upDone {
		return fmt.Errorf("firewall not set up")
	}
	if ttlSeconds == 0 {
		ttlSeconds = minAllowTTL
	}

	var v4, v6 []string
	for _, ip := range ips {
		elem := fmt.Sprintf("%s timeout %ds", ip.String(), ttlSeconds)
		if ip.To4() != nil {
			v4 = append(v4, elem)
		} else {
			v6 = append(v6, elem)
		}
	}

	var b strings.Builder
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add element inet %s allow4 { %s }\n", f.table, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add element inet %s allow6 { %s }\n", f.table, strings.Join(v6, ", "))
	}
	if b.Len() == 0 {
		return nil
	}
	return f.runNft(context.Background(), b.String())
}

// ProbeCanary is the host:port the self-probe dials (port 9/discard on the TEST-NET
// canary). A packet to it from the build cgroup must hit the cgroup-scoped drop rule.
func (f *nftFirewall) ProbeCanary() string { return net.JoinHostPort(selfProbeCanaryIP, "9") }

// ProbeDropCount reads the `selfprobe` named counter (packets matched by the
// cgroup-scoped canary drop rule). The self-probe compares before/after: no
// increment means the cgroup match did not catch the build's traffic (fail-open).
func (f *nftFirewall) ProbeDropCount(ctx context.Context) (uint64, error) {
	out, err := exec.CommandContext(ctx, "nft", "list", "counter", "inet", f.table, "selfprobe").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("nft list counter: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// Output: `... counter selfprobe { packets N bytes M }`.
	fields := strings.Fields(string(out))
	for i, w := range fields {
		if w == "packets" && i+1 < len(fields) {
			return strconv.ParseUint(fields[i+1], 10, 64)
		}
	}
	return 0, fmt.Errorf("no packet count in: %s", strings.TrimSpace(string(out)))
}

// Teardown drops the whole egret table and removes the build cgroup. Idempotent.
//
// Order is fail-closed: kill anything still in the build cgroup BEFORE removing
// the nft table, so a lingering/daemonized build process is never left alive with
// the egress filter already gone (an unconfined window). Only then delete the
// table (restoring the host) and remove the now-empty cgroup directory.
func (f *nftFirewall) Teardown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Kill the build cgroup BEFORE deleting the table (fail-closed order). Close()
	// below calls Kill() again, but that second call is a no-op once cgroup.procs is
	// empty - this explicit one is here only to precede the table delete.
	f.cg.Kill()
	var firstErr error
	if f.upDone {
		f.upDone = false
		if err := f.runNft(context.Background(), fmt.Sprintf("delete table inet %s\n", f.table)); err != nil &&
			!strings.Contains(err.Error(), "No such file or directory") {
			firstErr = err
		}
	}
	if err := f.cg.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// KillBuild reaps the build cgroup without tearing down the egress rules, so it
// can be called after the monitored command exits and before the report is
// written. Teardown calls the same reaper again (idempotent once the cgroup is
// empty).
func (f *nftFirewall) KillBuild() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cg.Kill()
}

// runNft feeds a script to `nft -f -`.
func (f *nftFirewall) runNft(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
