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
	"fmt"
	"net"
	"os"

	"github.com/NX1X/Egret/internal/policy"
)

// firewall is the platform-specific egress backend. newFirewall picks the impl.
type firewall interface {
	// Setup installs the default-deny egress rules and the (empty) allow set.
	Setup(ctx context.Context) error
	// AllowIPs adds resolved IPs for an allowlisted domain to the allow set with
	// an expiry (ttlSeconds) so a stale/rebinding answer does not stay allowed
	// for the whole run.
	AllowIPs(domain string, ips []net.IP, ttlSeconds uint32) error
	// BuildCgroupFD returns a cgroup-v2 directory fd the monitored command must be
	// placed into (via SysProcAttr.UseCgroupFD) so the egress filter applies to
	// the build — and NOT to Egret's own DNS-proxy upstream. -1 = no scoping
	// (audit mode / no firewall).
	BuildCgroupFD() int
	// Teardown removes all rules/sets Egret installed, restoring the host.
	// Must be idempotent and safe to call from a signal handler.
	Teardown() error
	// ProbeCanary is a non-allowlisted destination (host:port) the self-probe
	// targets to check the cgroup egress filter is actually confining the build.
	// Empty when there is no firewall (audit mode).
	ProbeCanary() string
	// ProbeDropCount reports how many packets the cgroup-scoped canary drop rule
	// has matched — the signal the self-probe reads to confirm the cgroup match works.
	ProbeDropCount(ctx context.Context) (uint64, error)
}

// Enforcer ties the DNS proxy to the firewall backend.
type Enforcer struct {
	pol *policy.Policy
	dns *DNSProxy
	fw  firewall
}

// New constructs an Enforcer for the given policy. In audit mode the firewall
// is a no-op (correlation only); in block mode it is the platform firewall.
func New(pol *policy.Policy) (*Enforcer, error) {
	var fw firewall
	if pol.IsBlocking() {
		f, err := newFirewall(pol)
		if err != nil {
			return nil, fmt.Errorf("initialising firewall: %w", err)
		}
		fw = f
	} else {
		fw = noopFirewall{}
	}

	e := &Enforcer{pol: pol, fw: fw}
	e.dns = NewDNSProxy(pol, e.onResolved)
	return e, nil
}

// Start installs firewall rules (block mode) and starts the DNS proxy. The
// returned function must be deferred to restore the host network.
func (e *Enforcer) Start(ctx context.Context) (stop func() error, err error) {
	if err := e.fw.Setup(ctx); err != nil {
		// Setup failure can still leave the build cgroup created (it's made when the
		// firewall is constructed, before rules go up). Tear down so it doesn't leak;
		// Teardown only deletes the nft table if it was actually installed.
		_ = e.fw.Teardown()
		return nil, fmt.Errorf("firewall setup: %w", err)
	}
	if err := e.dns.Start(ctx); err != nil {
		// Roll back firewall so we never leave the host wedged.
		_ = e.fw.Teardown()
		return nil, fmt.Errorf("dns proxy: %w", err)
	}
	return func() error {
		dnsErr := e.dns.Stop()
		fwErr := e.fw.Teardown()
		if fwErr != nil {
			return fwErr
		}
		return dnsErr
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

// BuildCgroupFD is the cgroup-v2 fd the monitored command must join so the egress
// filter scopes to the build (not Egret itself). -1 in audit mode.
func (e *Enforcer) BuildCgroupFD() int { return e.fw.BuildCgroupFD() }

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

func (noopFirewall) Setup(context.Context) error                    { return nil }
func (noopFirewall) AllowIPs(string, []net.IP, uint32) error        { return nil }
func (noopFirewall) BuildCgroupFD() int                             { return -1 }
func (noopFirewall) Teardown() error                                { return nil }
func (noopFirewall) ProbeCanary() string                            { return "" }
func (noopFirewall) ProbeDropCount(context.Context) (uint64, error) { return 0, nil }
