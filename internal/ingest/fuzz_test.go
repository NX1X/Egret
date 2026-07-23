package ingest

import (
	"net"
	"net/url"
	"testing"
)

// FuzzRequireSecureEndpoint fuzzes the gate that stops the ingest bearer token
// from being sent in cleartext. Two invariants must hold for every input:
//   - it never panics, and
//   - if it approves (returns nil), the endpoint is either https, or http to a
//     loopback host. It must never approve plaintext http to a non-loopback host.
func FuzzRequireSecureEndpoint(f *testing.F) {
	type seed struct {
		endpoint, token string
	}
	for _, s := range []seed{
		{"https://dash.example.com/ingest", "tok"},
		{"http://localhost:8080/ingest", "tok"},
		{"http://127.0.0.1/ingest", ""},
		{"http://[::1]/ingest", "tok"},
		{"http://evil.example.com/ingest", "tok"},
		{"ftp://x", "tok"},
		{"://", ""},
		{"https:example.com", ""},
	} {
		f.Add(s.endpoint, s.token)
	}
	f.Fuzz(func(t *testing.T, endpoint, token string) {
		if err := requireSecureEndpoint(endpoint, token); err != nil {
			return // rejected: fine
		}
		// Approved: prove the security invariant it exists to guarantee.
		u, perr := url.Parse(endpoint)
		if perr != nil {
			t.Fatalf("approved an unparseable endpoint %q", endpoint)
		}
		switch u.Scheme {
		case "https":
			return
		case "http":
			host := u.Hostname()
			if host == "localhost" {
				return
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				return
			}
			t.Fatalf("approved cleartext http to non-loopback host %q", endpoint)
		default:
			t.Fatalf("approved non-http/https scheme %q in %q", u.Scheme, endpoint)
		}
	})
}
