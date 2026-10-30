// Package enforcer implements Egret's egress enforcement: a local DNS proxy
// that correlates allowlisted domains to resolved IPs, and a firewall backend
// (nftables default-deny + a dynamic allow set) that those IPs are inserted
// into (the key flow for domain-based egress).
//
// The DNS proxy is cross-platform (it is also used in audit mode purely for
// domain↔IP correlation). The firewall is Linux-only; non-Linux builds get a
// no-op firewall so the package compiles, but executeRun blocks off-Linux
// before an Enforcer is ever constructed in block mode.
package enforcer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"github.com/NX1X/Egret/internal/policy"
)

// firewall is the platform-specific egress backend. newFirewall picks the impl.
type firewall interface {
	// Setup installs the default-deny egress rules and the (empty) allow set.
	// dnsAddr is the run's DNS proxy (ip:port): the only DNS destination on
	// loopback the build may reach.
	Setup(ctx context.Context, dnsAddr string) error
	// AllowIPs adds resolved IPs for an allowlisted domain to the allow set with
	// an expiry (ttlSeconds) so a stale/rebinding answer does not stay allowed
	// for the whole run.
	AllowIPs(domain string, ips []net.IP, ttlSeconds uint32) error
	// Teardown removes all rules/sets Egret installed, restoring the host. It
	// kills the build cgroup first, so no build process outlives the filter.
	// Must be idempotent and safe to call from a signal handler.
	Teardown() error
	// ProbeCanary is a non-allowlisted destination (host:port) the self-probe
	// targets to check the cgroup egress filter is actually confining the build.
	// Empty when there is no firewall (audit mode).
	ProbeCanary() string
	// ProbeDropCount reports how many packets the cgroup-scoped canary drop rule
	// has matched - the signal the self-probe reads to confirm the cgroup match works.
	ProbeDropCount(ctx context.Context) (uint64, error)
}

// Enforcer ties the DNS proxy to the firewall backend, and owns the build
// cgroup that scopes both the egress filter (block mode) and the eBPF probes
// (both modes).
type Enforcer struct {
	pol *policy.Policy
	dns *DNSProxy
	fw  firewall
	cg  *buildCgroup // nil only in audit mode when no cgroup could be made
}

// New constructs an Enforcer for the given policy. It creates the build cgroup
// in both modes. Block mode requires it (the filter matches on it). Audit mode
// only uses it to scope the probes, so a failure there is a warning and the
// probes record the whole host. In audit mode the firewall is a no-op.
func New(pol *policy.Policy) (*Enforcer, error) {
	runID, err := newRunID()
	if err != nil {
		return nil, err
	}
	cg, cgErr := newBuildCgroup(runID)
	if cgErr != nil {
		if pol.IsBlocking() {
			return nil, fmt.Errorf("initialising firewall: %w", cgErr)
		}
		fmt.Fprintln(os.Stderr, "egret: warning: no build cgroup, so the report includes every process on the host:", cgErr)
		cg = nil
	}

	var fw firewall
	if pol.IsBlocking() {
		f, err := newFirewall(pol, runID, cg)
		if err != nil {
			_ = cg.Close()
			return nil, fmt.Errorf("initialising firewall: %w", err)
		}
		fw = f
	} else {
		fw = noopFirewall{}
	}

	e := &Enforcer{pol: pol, fw: fw, cg: cg}
	e.dns = NewDNSProxy(pol, e.onResolved)
	return e, nil
}

// newRunID returns 16 random hex characters that name this run's nft table and
// build cgroup. Not the pid: nft tables are per network namespace but pids are
// per pid namespace, so two privileged host-network containers can both run
// Egret as the same pid, and a shared name would let one run delete the
// other's live filter.
func newRunID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating a run id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Start starts the DNS proxy, then installs firewall rules (block mode) that
// allow the build DNS to that proxy only. The proxy starts first because its
// per-run address is known only once it is bound; no query can arrive before
// the build starts, so the firewall is up before the proxy is used. The
// returned function must be deferred to restore the host network.
func (e *Enforcer) Start(ctx context.Context) (stop func() error, err error) {
	if err := e.dns.Start(ctx); err != nil {
		// The build cgroup exists since New, so release it to avoid a leak.
		_ = e.fw.Teardown()
		_ = e.cg.Close()
		return nil, fmt.Errorf("dns proxy: %w", err)
	}
	if err := e.fw.Setup(ctx, e.dns.ListenAddr()); err != nil {
		// Roll back so we never leave the host wedged. Teardown only deletes the
		// nft table if it was actually installed.
		_ = e.dns.Stop()
		_ = e.fw.Teardown()
		_ = e.cg.Close()
		return nil, fmt.Errorf("firewall setup: %w", err)
	}
	return func() error {
		dnsErr := e.dns.Stop()
		fwErr := e.fw.Teardown() // kills the build cgroup before the table goes
		cgErr := e.cg.Close()
		for _, err := range []error{fwErr, cgErr, dnsErr} {
			if err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// onResolved is the DNS proxy callback: when an allowlisted domain resolves, we
// insert its IPs into the firewall allow set (with the answer's TTL as expiry).
// Non-allowlisted domains never reach here (the proxy refuses them in block mode).
func (e *Enforcer) onResolved(domain string, ips []net.IP, ttlSeconds uint32) {
	if len(ips) == 0 {
		return
	}
	if err := e.fw.AllowIPs(domain, ips, ttlSeconds); err != nil {
		// Best-effort: a failed insert means the connection will be denied,
		// which is fail-closed and safe. Surface it on stderr (this is the DNS hot
		// path; stdout may carry the report/job-summary and must not be corrupted).
		fmt.Fprintf(os.Stderr, "egret: failed to allow %s %v: %v\n", domain, ips, err)
	}
}

// BuildCgroupFD is the cgroup-v2 fd the monitored command must join, so the
// egress filter and the probes scope to the build. -1 when there is no build
// cgroup (audit mode only).
func (e *Enforcer) BuildCgroupFD() int { return e.cg.fd() }

// ScopeID is the build cgroup's id for the eBPF probes. 0 means no scope.
func (e *Enforcer) ScopeID() uint64 { return e.cg.id() }

// KillBuild reaps any process still alive in the build cgroup. Call it once the
// monitored command has returned and before writing the report, so a detached
// build process can't keep overwriting the report file after Egret writes it.
func (e *Enforcer) KillBuild() { e.cg.Kill() }

// ProbeCanary + ProbeDropCount expose the self-probe hooks so the CLI can, after
// setup, fork a probe into the build cgroup toward the canary and confirm the
// cgroup-scoped drop actually fired (fail-closed if it didn't). (netsec F-C.)
func (e *Enforcer) ProbeCanary() string { return e.fw.ProbeCanary() }
func (e *Enforcer) ProbeDropCount(ctx context.Context) (uint64, error) {
	return e.fw.ProbeDropCount(ctx)
}

// DomainForIP returns the domain observed to resolve to ip, or "" if none. Used
// to label connection events by domain in the report.
func (e *Enforcer) DomainForIP(ip net.IP) string { return e.dns.DomainForIP(ip) }

// ListenAddr is the address the build's resolver should point at.
func (e *Enforcer) ListenAddr() string { return e.dns.ListenAddr() }

// noopFirewall is used in audit mode: correlate, never block.
type noopFirewall struct{}

func (noopFirewall) Setup(context.Context, string) error            { return nil }
func (noopFirewall) AllowIPs(string, []net.IP, uint32) error        { return nil }
func (noopFirewall) Teardown() error                                { return nil }
func (noopFirewall) ProbeCanary() string                            { return "" }
func (noopFirewall) ProbeDropCount(context.Context) (uint64, error) { return 0, nil }
