# Egret Roadmap

Egret is an open-source runtime security agent for CI/CD and Linux hosts:
eBPF-based egress filtering, network/process/file monitoring, and audit-mode
policy generation. It ships as a **CLI** and a **GitHub Action**, with an
**optional** self-hosted dashboard. No server, no account, no phone-home.

> This is the user-facing roadmap: what Egret is, what works today, and where it's
> going. Released changes are in [CHANGELOG.md](../CHANGELOG.md).

## The core promise

The agent (CLI + eBPF) is **server-agnostic**, and every layer above it is
**optional**. No headline feature ever *requires* the GitHub App or the dashboard.
Egret talks outward only through (1) the files it writes (`report.json`, SARIF, a
signed attestation) and (2) an optional `POST` to a dashboard you run. Setting
`EGRET_INGEST_URL` is the entire "use the self-hosted part" switch - leave it unset
and everything stays local.

## The three tiers (all additive, all optional)

| Tier | What | Where it runs |
|---|---|---|
| **1 - Agent** | eBPF CLI + GitHub Action: monitor & enforce a job's egress/process/file behaviour, emit a report + SARIF | your runner, zero infra |
| **2 - GitHub App** | Server-less PR checks, sticky comments, a Renovate-style "allowlist this endpoint" dashboard issue | GitHub, no server |
| **3 - Egret Nest** | Optional self-hosted dashboard: history, drift, fleet view, multi-tenant RBAC | a box you run |

Tiers 2 and 3 are pure Go + web (no eBPF) and run on any OS. Only the agent's kernel
probes need Linux.

## What works today

**Agent (Tier 1)**
- **Monitoring (audit mode) - production-ready.** eBPF probes capture every outbound
  connection (IPv4 + IPv6, real dest + port), the process tree, and writes to
  protected paths, evaluate them against a `policy.yaml`, and write a Markdown/JSON
  report + a GitHub job summary. Audit mode never blocks - it's the safe default and
  is fully validated.
- **Enforcement (block mode) - a live-validated boundary on bare/VM hosts.** A DNS
  proxy + cgroup-scoped nftables default-deny confines the build to an allowlist.
  The build runs de-privileged (`no_new_privs` + dropped capabilities, so it can't
  `sudo` its way out), lingering processes are killed at teardown, and a built-in
  self-probe refuses to run if it can't confirm confinement (fail-closed). This is
  **security-reviewed and live-validated on a bare/VM host** and confines correctly in
  a namespaced container in testing. On GitHub-hosted `container:` runners it's still
  being validated across topologies - **audit mode is the recommendation there for
  now**.
- **Policy**: domain allowlist (`allowed-endpoints`, with `*.` wildcards), raw
  **IP/CIDR allowlist** (`allowed-ips`), `block-raw-ip`, protected paths, disallowed
  processes, and `extends:` for a shared base policy (local or `org://`).
- **Action inputs**: `command`, `policy`, `mode`, SARIF upload, `fail-on-violations`,
  optional `ingest-url`/`ingest-token` (POST to your dashboard), `disable-sudo`.

**GitHub App (Tier 2)** - `egret github check` / `comment` / `dashboard`, the
audit→allowlist-PR loop, and `extends: org://…` all work with a plain `GITHUB_TOKEN`
or an App token.

**Egret Nest dashboard (Tier 3)** - at **v0.1.0**, feature-complete and
security-reviewed: run ingest + SQLite storage, per-repo egress-over-time, new-endpoint
drift, org fleet view, and enterprise auth (GitHub OAuth / OIDC / local + TOTP),
org→repo→run RBAC, scoped ingest tokens, audit log, TLS. Configurable via env or an
admin UI. The dashboard has its own repository and roadmap
(`NX1X/Egret-Nest-Dashboard`).

**Supply chain** - releases ship `SHA256SUMS`, SLSA build provenance, and a keyless
cosign signature; the Action verifies the binary before use.

## What's next (toward v1.0)

The whole product (agent + Action + dashboard) reaches **v1.0 together**. The
remaining work is on the agent:

- **Block mode as a confinement boundary on every CI platform** - finish validating
  it on GitHub-hosted `container:` / cgroup-namespaced runners (the self-probe already
  fails closed if it can't confirm confinement), and pin the build's resolver.
- **Kernel coverage** - verify the eBPF probes across ≥2 kernel versions.
- **Whole-job tracing** - trace every step transparently, without wrapping a
  `command`.
- **Release polish** - App-Manifest one-click install, Marketplace listing, arm64
  builds.

Until the agent hits its v1.0 bar, it is **not tagged**; the dashboard is already at
`v0.1.0`.

## Beyond v1.0

- **Deeper egress coverage** - UDP/DoH/DoT/QUIC and CDN/SNI-fronting cases that
  connect()-based probes don't see.
- **Per-step attribution**, a bundled versioned block-list, and **dogfooding** (Egret
  guarding its own CI).
- Deliberately **out of the core** (dashboard-tier or never): cross-run anomaly
  detection, web analytics, and any live phone-home threat feed - the zero-infra,
  no-phone-home promise is permanent.

Egret's scope is deliberately narrow: runtime egress control + monitoring, not CI
workflow static-analysis. That boundary is a settled design decision.

## Distribution

Open-core: the agent, Action, and App stay OSS (Apache-2.0). Optional paid layers
later (hosted Nest, support, curated allowlists) never change the core promise. The
GitHub App can be published by any account; a paid Marketplace listing would need an
org-owned, verified App.
