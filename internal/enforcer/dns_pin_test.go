package enforcer

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/NX1X/Egret/internal/policy"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		name, conf, want string
	}{
		{"resolved stub", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch x.internal\n", "127.0.0.53:53"},
		{"first usable wins", "# c\nnameserver 0.0.0.0\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n", "10.0.0.2:53"},
		{"ipv6", "nameserver 2001:db8::1\n", "[2001:db8::1]:53"},
		{"ipv6 zone", "nameserver fe80::1%eth0\n", "[fe80::1%eth0]:53"},
		// An outer Egret run's proxy: forwarding to it would loop back to us.
		{"skip egret proxy", "nameserver 127.53.4.9\nnameserver 10.1.1.1\n", "10.1.1.1:53"},
		{"garbage", "nameserver not-an-ip\n", fallbackUpstream},
		{"empty", "", fallbackUpstream},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseUpstream(strings.NewReader(tc.conf)); got != tc.want {
				t.Errorf("parseUpstream = %q, want %q", got, tc.want)
			}
		})
	}
	if got := hostUpstream("/nonexistent/resolv.conf"); got != fallbackUpstream {
		t.Errorf("hostUpstream(missing) = %q, want %q", got, fallbackUpstream)
	}
}

func TestRandomListenAddr(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		a := randomListenAddr()
		host, port, err := net.SplitHostPort(a)
		if err != nil || port != "53" {
			t.Fatalf("randomListenAddr() = %q, want host:53", a)
		}
		ip := net.ParseIP(host).To4()
		if ip == nil || ip[0] != 127 || ip[1] != 53 || ip[3] == 0 || ip[3] == 255 {
			t.Fatalf("randomListenAddr() = %q, want 127.53.x.y with y in 1..254", a)
		}
		seen[a] = true
	}
	// 200 draws from ~65k addresses: a constant result would mean no per-run
	// address at all.
	if len(seen) < 150 {
		t.Errorf("only %d distinct addresses in 200 draws", len(seen))
	}
}

// TestProxyStartsOnPerRunAddress binds the real listeners, so it needs the
// right to bind port 53 (root in CI).
func TestProxyStartsOnPerRunAddress(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("binding port 53 needs root")
	}
	a := NewDNSProxy(policy.Default(), nil)
	b := NewDNSProxy(policy.Default(), nil)
	b.listenAddr = a.listenAddr // force a clash: b must move to another address
	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()
	if a.ListenAddr() == b.ListenAddr() {
		t.Fatalf("two proxies share %s", a.ListenAddr())
	}
	for _, p := range []*DNSProxy{a, b} {
		c, err := net.Dial("tcp", p.ListenAddr())
		if err != nil {
			t.Errorf("TCP listener on %s: %v", p.ListenAddr(), err)
			continue
		}
		_ = c.Close()
	}
}
