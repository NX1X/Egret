package enforcer

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/NX1X/Egret/internal/policy"
	"github.com/miekg/dns"
)

// defaultUpstream is the resolver the proxy forwards allowed queries to. It is
// deliberately a public resolver so the proxy works even when the host's
// /etc/resolv.conf points back at us.
const defaultUpstream = "1.1.1.1:53"

// defaultListen is where the proxy listens. The build's resolver is pointed
// here (e.g. by rewriting /etc/resolv.conf for the monitored process).
const defaultListen = "127.0.0.1:53"

// resolvedFunc is called when an allowlisted domain resolves to one or more IPs.
// ttlSeconds is the (clamped) minimum answer TTL, used as the allow-set expiry.
type resolvedFunc func(domain string, ips []net.IP, ttlSeconds uint32)

// DNSProxy is a forwarding resolver that (a) records domain↔IP correlations for
// reporting and (b) in block mode refuses non-allowlisted names and reports
// allowlisted resolutions to the firewall via onResolved.
type DNSProxy struct {
	pol        *policy.Policy
	upstream   string
	listenAddr string
	onResolved resolvedFunc

	srv    *dns.Server
	client *dns.Client

	mu       sync.RWMutex
	ipDomain map[string]string // ip -> domain (most recent wins)
}

// NewDNSProxy builds a proxy bound to defaults. onResolved may be nil.
func NewDNSProxy(pol *policy.Policy, onResolved resolvedFunc) *DNSProxy {
	return &DNSProxy{
		pol:        pol,
		upstream:   defaultUpstream,
		listenAddr: defaultListen,
		onResolved: onResolved,
		client:     &dns.Client{Net: "udp", Timeout: 5 * time.Second},
		ipDomain:   make(map[string]string),
	}
}

// Start binds the UDP listener and serves in the background.
func (p *DNSProxy) Start(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handle)
	p.srv = &dns.Server{Addr: p.listenAddr, Net: "udp", Handler: mux}

	started := make(chan error, 1)
	p.srv.NotifyStartedFunc = func() { started <- nil }

	go func() {
		if err := p.srv.ListenAndServe(); err != nil {
			// ListenAndServe returns after Shutdown; only report bind errors.
			select {
			case started <- err:
			default:
			}
		}
	}()

	select {
	case err := <-started:
		if err != nil {
			return fmt.Errorf("dns listen on %s: %w", p.listenAddr, err)
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("dns proxy did not start within 5s")
	}
	return nil
}

// Stop shuts the listener down.
func (p *DNSProxy) Stop() error {
	if p.srv == nil {
		return nil
	}
	return p.srv.Shutdown()
}

// ListenAddr is where clients should send queries.
func (p *DNSProxy) ListenAddr() string { return p.listenAddr }

// DomainForIP returns the domain ip was last seen to resolve to.
func (p *DNSProxy) DomainForIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ipDomain[ip.String()]
}

// handle processes one DNS query.
func (p *DNSProxy) handle(w dns.ResponseWriter, req *dns.Msg) {
	// Real resolvers send exactly one question per packet (QDCOUNT==1). Refuse
	// anything else: a multi-question query could carry an allowlisted name in
	// Question[0] to pass the block-mode check below while a denied name rides
	// along in Question[1..] and still gets forwarded to (and answered by)
	// upstream. Only the first question is ever inspected, so reject the rest
	// outright rather than resolve names that were never checked.
	if len(req.Question) != 1 {
		p.refuse(w, req)
		return
	}
	qname := strings.TrimSuffix(req.Question[0].Name, ".")

	// In block mode, refuse names that are not allowlisted. (Audit mode lets
	// everything resolve so the report is complete.)
	if p.pol.IsBlocking() && !p.pol.AllowsDomain(qname) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	resp, _, err := p.client.Exchange(req, p.upstream)
	if err != nil || resp == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}

	ips, ttl := p.recordAnswers(qname, resp)
	if len(ips) > 0 && p.onResolved != nil && p.pol.AllowsDomain(qname) {
		p.onResolved(qname, ips, ttl)
	}
	_ = w.WriteMsg(resp)
}

// allow-set expiry bounds: floor so a TTL-0 rebinding answer can't grant a
// perpetually-refreshable 0s window, cap so a huge TTL can't pin an IP all run.
const (
	minAllowTTL = 30   // seconds
	maxAllowTTL = 3600 // seconds
)

// recordAnswers extracts A/AAAA IPs from a response, stores the reverse map, and
// returns the IPs plus the clamped minimum TTL across the answer records.
func (p *DNSProxy) recordAnswers(qname string, resp *dns.Msg) ([]net.IP, uint32) {
	var ips []net.IP
	minTTL := uint32(maxAllowTTL)
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		if t := rr.Header().Ttl; t < minTTL {
			minTTL = t
		}
		ips = append(ips, ip)
		p.mu.Lock()
		p.ipDomain[ip.String()] = qname
		p.mu.Unlock()
	}
	if minTTL < minAllowTTL {
		minTTL = minAllowTTL
	}
	if minTTL > maxAllowTTL {
		minTTL = maxAllowTTL
	}
	return ips, minTTL
}

func (p *DNSProxy) refuse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}
