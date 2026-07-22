# Security Policy

Egret is a security tool that runs as root with `CAP_BPF` / `CAP_NET_ADMIN`
and enforces egress. A bug in the enforcer can mean a silent bypass, so we
take reports seriously and disclose responsibly.

## Reporting a vulnerability

**Do not open a public issue for security bugs.**

Report privately via either:

- GitHub Security Advisories:
  <https://github.com/NX1X/Egret/security/advisories/new> (preferred), or
- Email: **support@nx1xlab.dev** with subject `SECURITY: Egret`, or
- Contact form: <https://nx1xlab.dev/contact>.

For non-security bugs and questions, open a public issue at
<https://github.com/nx1x/egret/issues>.

Please include:

- Affected version / commit (`egret version`) and mode (`audit` / `block`).
- Kernel and distro (`uname -r`) - eBPF behavior is kernel-sensitive.
- A minimal reproduction: policy snippet + the command being wrapped.
- The impact you believe it has (e.g. "egress to a denied domain succeeds via
  DoH", "enforcer fails open on teardown").

## What counts as a vulnerability

High-value classes for Egret specifically:

- **Egress-enforcement bypass** - reaching a denied destination in `block`
  mode (DoH/DoT, raw IP, IPv6, QUIC, DNS rebinding, CDN IP rotation, etc.).
  Some residual gaps are *known* (DoH/DoT, raw IP, QUIC, CDN IP rotation) - a
  report that matches a known limitation is still welcome but may already be
  tracked.
- **Fail-open teardown** - the enforcer leaving traffic allowed after a crash
  or exit when it should fail closed.
- **Privilege / capability misuse**, path traversal in report writing, or
  policy-parser issues that lead to code execution.
- **Secret/PII leakage** in reports, logs, or the Action job summary.

## Our commitment

- We acknowledge reports within **3 business days**.
- We aim to ship a fix or mitigation within **90 days**, faster for actively
  exploited issues.
- We credit reporters in the release notes unless you ask us not to.
- Fixes follow our hotfix process: rotate first if a credential is involved,
  ship a regression test, and complete a network-security review before release.

## Supported versions

Egret is pre-1.0 and under active development. Only the latest tagged release
receives security fixes until 1.0.

## Scope

In scope: the `egret` binary, the eBPF programs, the `action/` wrapper, and
the release/CI workflows in this repository. Out of scope: third-party
dependencies (report those upstream; we track them via `govulncheck` +
Renovate) and self-hosted deployments you modify.
