# Security Policy

Egret runs as root with `CAP_BPF` / `CAP_NET_ADMIN` and enforces egress. A bug
in the enforcer can mean a silent bypass, so every report genuinely matters -
and we want reporting one to be easy and safe.

**You will never get in trouble for reporting a vulnerability to us in good
faith.** See [Safe harbor](#safe-harbor) below.

## TL;DR

- Found something? Report it **privately** - please don't open a public issue.
- Fastest channel: **[open a private security advisory](https://github.com/NX1X/Egret/security/advisories/new)**.
- We reply within **3 business days**, keep you updated, fix it, and credit you
  (unless you'd rather stay anonymous).

## How to report

Pick whichever is easiest - all three are private:

| Channel | Where |
|---|---|
| GitHub private advisory *(preferred)* | <https://github.com/NX1X/Egret/security/advisories/new> |
| Email | **support@nx1xlab.dev**, subject `SECURITY: Egret` |
| Contact form | <https://nx1xlab.dev/contact> |

Anonymous reports are welcome, and plain email is completely fine - no PGP or
special tooling required.

For non-security bugs and questions, please use a public issue instead:
<https://github.com/NX1X/Egret/issues>.

## Safe harbor

We consider security research and vulnerability disclosure carried out in good
faith to be **authorized conduct**, and we will not pursue or support legal
action against you for it. If you make a genuine effort to follow this policy,
we will treat you as an ally, not an adversary - and we'll work with you if
someone else raises a concern about your research.

In return, we ask that you:

- Make a good-faith effort to avoid privacy violations, data loss, and service
  disruption.
- Only test against your **own** installations - never another user's data or a
  third party's infrastructure.
- Don't access, modify, or exfiltrate more data than needed to demonstrate the
  issue.
- Give us a reasonable chance to ship a fix before disclosing publicly.

If you're unsure whether something is in bounds, just ask first at
**support@nx1xlab.dev** - we'd much rather answer a question than have you hold
back a report.

## What to include

The more of this you can share, the faster we can confirm and fix - but a clear
description is enough to get started, even without a polished write-up:

- Affected version / commit (`egret version`) and mode (`audit` / `block`).
- Kernel and distro (`uname -r`) - eBPF behavior is kernel-sensitive.
- A minimal reproduction: policy snippet plus the command being wrapped.
- The impact you believe it has (e.g. "egress to a denied domain succeeds via
  DoH", "enforcer fails open on teardown").
- Any proof-of-concept, logs, or screenshots (redact your own secrets).

## What to expect

| Stage | Our target |
|---|---|
| Acknowledgement that we received it | within **3 business days** |
| Triage + our severity assessment | within **7 days** |
| Fix or documented mitigation | within **90 days** (sooner for critical / actively exploited) |
| Public disclosure | coordinated with you, after a fix or mitigation ships |

We'll keep you in the loop at each step, share how we're rating severity, and
tell you when a fix lands. In the rare case we need longer than 90 days, we'll
explain why and agree a timeline with you.

## Coordinated disclosure & credit

- We disclose through **GitHub Security Advisories** and request a **CVE** where
  it's warranted.
- We coordinate disclosure timing with you and honor a reasonable embargo.
- We **credit you by name or handle** in the advisory and release notes, unless
  you ask to remain anonymous.
- There is no paid bug-bounty program - Egret is independent open source - but
  we take acknowledgement seriously: your name goes on the fix.

## What we're especially interested in

High-value classes for Egret specifically:

- **Egress-enforcement bypass** - reaching a denied destination in `block` mode
  (DoH/DoT, raw IP, IPv6, QUIC, DNS rebinding, CDN IP rotation, etc.). Some
  residual gaps are *known* (DoH/DoT, raw IP, QUIC, CDN IP rotation) - a report
  that matches a known limitation is still welcome but may already be tracked.
- **Fail-open teardown** - the enforcer leaving traffic allowed after a crash or
  exit when it should fail closed.
- **Privilege / capability misuse**, path traversal in report writing, or
  policy-parser issues that lead to code execution.
- **Secret / PII leakage** in reports, logs, or the Action job summary.
- **Supply-chain / CI issues** in the release and Action workflows - e.g. an
  injection that could tamper with a published binary.

## Supported versions

Egret is pre-1.0 and under active development. Only the latest tagged release
receives security fixes until 1.0. If you're on an older tag, please try to
reproduce on the latest release where you can - but report it either way.

## Scope

**In scope:** the `egret` binary, the eBPF programs, the `action/` wrapper, and
the release / CI workflows in this repository.

**Out of scope:** third-party dependencies (please report those upstream; we
track them via `govulncheck` + Renovate) and self-hosted deployments you've
modified. If a dependency issue affects Egret, tell us anyway - we'll help
coordinate.

## Thank you

Researchers who take the time to report issues make Egret safer for everyone who
relies on it. We're grateful, and we'll treat your report - and you - with
respect.
