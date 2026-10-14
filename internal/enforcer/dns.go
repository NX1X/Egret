package enforcer

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NX1X/Egret/internal/policy"
	"github.com/miekg/dns"
)

// fallbackUpstream is the resolver the proxy forwards allowed queries to when
// the host's /etc/resolv.conf names no usable nameserver.
const fallbackUpstream = "1.1.1.1:53"

// hostResolvConf is the host's resolver config. Egret reads it from its OWN
// mount namespace, which the build's resolv.conf pinning never touches.
const hostResolvConf = "/etc/resolv.conf"

// listenAttempts bounds how many per-run addresses Start tries before giving up.
const listenAttempts = 16

// resolvedFunc is called when an allowlisted domain resolves to one or more IPs.
// ttlSeconds is the (clamped) minimum answer TTL, used as the allow-set expiry.
type resolvedFunc func(domain string, ips []net.IP, ttlSeconds uint32)

// DNSProxy is a forwarding resolver that (a) records domain↔IP correlations for
// reporting and (b) in block mode refuses non-allowlisted names and reports
// allowlisted resolutions to the firewall via onResolved.
//
// It listens on a per-run loopback address (127.53.x.y:53, UDP and TCP), so two
// Egret runs on one host never share a proxy, and the firewall can allow DNS
// to exactly this address and drop every other DNS destination on loopback.
// Port 53 is fixed because resolv.conf cannot name a port.
type DNSProxy struct {
	pol        *policy.Policy
	upstream   string
	listenAddr string
	onResolved resolvedFunc

	udpSrv *dns.Server
	tcpSrv *dns.Server
	client *dns.Client
	tcp    *dns.Client

	mu       sync.RWMutex
	ipDomain map[string]string // ip -> domain (most recent wins)
}

// NewDNSProxy builds a proxy with a random per-run listen address (Start picks
// another if that one is taken) and the host's own resolver as upstream.
// onResolved may be nil.
func NewDNSProxy(pol *policy.Policy, onResolved resolvedFunc) *DNSProxy {
	return &DNSProxy{
		pol:        pol,
		upstream:   hostUpstream(hostResolvConf),
		listenAddr: randomListenAddr(),
		onResolved: onResolved,
		client:     &dns.Client{Net: "udp", Timeout: 5 * time.Second},
		tcp:        &dns.Client{Net: "tcp", Timeout: 5 * time.Second},
		ipDomain:   make(map[string]string),
	}
}

// randomListenAddr returns 127.53.a.b:53 with random a and b (b in 1..254).
// All of 127.0.0.0/8 is local on Linux, so no address needs to be configured.
func randomListenAddr() string {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on Linux; keep a valid address regardless.
		b = [2]byte{0, 1}
	}
	return net.JoinHostPort(fmt.Sprintf("127.53.%d.%d", b[0], 1+int(b[1])%254), "53")
}

// hostUpstream returns the first usable nameserver in the resolv.conf at path,
// as host:53. Using the host's own resolver keeps split DNS and internal names
// working on self-hosted runners; on GitHub-hosted runners it is the
// systemd-resolved stub. The proxy runs outside the build cgroup, so the
// firewall does not filter its upstream query. Falls back to fallbackUpstream.
func hostUpstream(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return fallbackUpstream
	}
	defer f.Close()
	return parseUpstream(f)
}

// parseUpstream reads resolv.conf content and returns its first usable
// nameserver as host:53, or fallbackUpstream. An unspecified address or one
// of Egret's own per-run proxy addresses (127.53.0.0/16, for example when
// Egret runs inside another Egret run) is skipped, so the proxy never forwards
// to itself.
func parseUpstream(r io.Reader) string {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		// Drop an IPv6 zone ("fe80::1%eth0"); net.ParseIP rejects it.
		host, _, _ := strings.Cut(fields[1], "%")
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		if v4 := ip.To4(); v4 != nil && v4[0] == 127 && v4[1] == 53 {
			continue
		}
		return net.JoinHostPort(fields[1], "53")
	}
	return fallbackUpstream
}

// Start binds the UDP and TCP listeners and serves in the background. When the
// chosen address is already in use (another Egret run), it tries another.
func (p *DNSProxy) Start(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handle)

	var lastErr error
	for i := 0; i < listenAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			p.listenAddr = randomListenAddr()
		}
		pc, err := net.ListenPacket("udp", p.listenAddr)
		if err != nil {
			lastErr = err
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			break
		}
		ln, err := net.Listen("tcp", p.listenAddr)
		if err != nil {
			_ = pc.Close()
			lastErr = err
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			break
		}
		p.udpSrv = &dns.Server{PacketConn: pc, Handler: mux}
		p.tcpSrv = &dns.Server{Listener: ln, Handler: mux}
		go func() { _ = p.udpSrv.ActivateAndServe() }()
		go func() { _ = p.tcpSrv.ActivateAndServe() }()
		return nil
	}
	return fmt.Errorf("dns listen on %s: %w", p.listenAddr, lastErr)
}

// Stop shuts both listeners down.
func (p *DNSProxy) Stop() error {
	var firstErr error
	for _, srv := range []*dns.Server{p.udpSrv, p.tcpSrv} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
	if err == nil && resp != nil && resp.Truncated {
		// The answer did not fit in UDP. Ask again over TCP, so a client that
		// retries over TCP to this proxy gets the full answer, not the same
		// truncated one.
		resp, _, err = p.tcp.Exchange(req, p.upstream)
	}
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
