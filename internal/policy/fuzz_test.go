package policy

import "testing"

// FuzzParsePolicy drives the policy parser with arbitrary bytes - the exact
// untrusted-input path a CI job hits when it supplies a `policy.yaml`. The parser
// must never panic: it may only return an error, or a Policy that Validate() then
// accepts or rejects. resolve is nil, so any `extends:` ref must error (not panic).
func FuzzParsePolicy(f *testing.F) {
	seeds := [][]byte{
		[]byte("version: 1\nmode: block\n"),
		[]byte("mode: audit\negress:\n  allowed-endpoints: [example.com, \"*.internal\"]\n  block-raw-ip: true\n"),
		[]byte("egress:\n  allowed-ips: [10.0.0.0/8, 1.2.3.4]\n"),
		[]byte("file:\n  protected-paths: [/etc/shadow]\nprocess:\n  disallowed: [nc]\n"),
		[]byte("extends: ./base.yaml\nmode: block\n"),
		[]byte("extends: org://team/base\n"),
		[]byte(""),
		[]byte("\x00\x01\x02not yaml"),
		[]byte("mode: 12345\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		// baseDir is empty and resolve is nil: file/remote extends must fail
		// closed with an error, never panic.
		p, err := parsePolicy(raw, "", nil, 0)
		if err != nil {
			return
		}
		// A parsed policy must survive Validate() without panicking. It may be
		// rejected - that is a valid outcome, not a crash.
		_ = p.Validate()
	})
}
