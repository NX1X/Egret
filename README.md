<p align="center">
  <img src="branding/logo.svg" alt="Egret - runtime egress security" width="440">
</p>

# 🪶 Egret

> An open-source runtime security agent for CI/CD and generic Linux hosts.
> Egress filtering, network/process/file monitoring, and audit-mode policy
> generation - fully OSS, zero-infrastructure.

The name plays on **egress** (its core job) and the egret bird. CLI:
`egret run -- ./build.sh`.

[![CI](https://github.com/NX1X/Egret/actions/workflows/ci.yml/badge.svg)](https://github.com/NX1X/Egret/actions/workflows/ci.yml)
[![Security](https://github.com/NX1X/Egret/actions/workflows/security.yml/badge.svg)](https://github.com/NX1X/Egret/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/NX1X/Egret?logo=github&logoColor=white&sort=semver)](https://github.com/NX1X/Egret/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/NX1X/Egret)](https://goreportcard.com/report/github.com/NX1X/Egret)
[![Go](https://img.shields.io/github/go-mod/go-version/NX1X/Egret?logo=go&logoColor=white)](go.mod)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub - NX1X/Egret](https://img.shields.io/badge/GitHub-NX1X%2FEgret-181717?logo=github&logoColor=white)](https://github.com/NX1X/Egret)

- **Status:** pre-MVP / active development (see [docs/ROADMAP.md](docs/ROADMAP.md))
- **Repository:** [github.com/NX1X/Egret](https://github.com/NX1X/Egret)
- **License:** [Apache-2.0](LICENSE)
- **Platform:** Linux 5.8+ (eBPF CO-RE). Builds of the non-eBPF packages run on
  any OS; the agent itself runs on Linux.

---

## What it does

Egret wraps a command and watches it through eBPF:

- **Network egress** - records every outbound connection (PID, process, IP,
  port; domain when DNS is correlated).
- **Egress enforcement** *(block mode)* - default-deny with a domain allowlist,
  backed by a local DNS proxy + nftables dynamic allow set.
- **Process tree** - `execve`/`fork` observation.
- **File writes** - flags writes to protected paths (`.git/`, `~/.ssh/`, …).
- **Audit mode** - observe a run, then emit a *suggested* allowlist.

Reports are written as Markdown + JSON, and appended to the GitHub Actions job
summary when present. No server, no account, no phone-home.

---

## Quickstart (CLI)

> Requires Linux 5.8+, root or `CAP_BPF`+`CAP_NET_ADMIN`, and (to build the
> eBPF objects) `clang`/`llvm` + kernel BTF.

```bash
# 1. Build (Linux). `generate` compiles the eBPF C via clang + bpf2go.
make generate build

# 2. Observe a build in audit mode (logs, never blocks).
sudo ./bin/egret run --config examples/policy.yaml --mode audit -- ./build.sh

# 3. Turn the observed run into a suggested allowlist.
egret audit --from hardened-report/report.json --emit policy.suggested.yaml

# 4. Enforce it.
sudo ./bin/egret run --config policy.suggested.yaml --mode block -- ./build.sh
```

The report lands in `./hardened-report/` (`report.md`, `report.json`).

### Validate a policy

```bash
egret policy lint --config examples/policy.yaml
```

---

## Quickstart (GitHub Action)

Wrap your build with the `command` input. Egret monitors it, writes a report,
and (by default) uploads a SARIF to **Code Scanning**:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:                 # scope to the job
      contents: read
      security-events: write     # required to upload SARIF to Code Scanning
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      # Pin to a full commit SHA for immutability (recommended). The floating
      # @v0 / @v0.1.0 tags are the convenience alternative.
      - uses: NX1X/Egret@95d7c293cd828369222aa5aec03952a1379e7fe6 # v0.1.3
        with:
          policy: .github/egret-policy.yaml
          mode: audit                 # or: block
          command: make ci            # your whole build - monitored end-to-end
          fail-on-violations: true    # optional: fail the job on any violation
```

> **Untrusted PRs:** on a plain `pull_request` run the checked-out
> `policy: .github/egret-policy.yaml` comes from the PR head, so a PR can weaken
> the policy that judges it. To keep the policy trusted, load it from the base
> branch and/or protect the path with CODEOWNERS + branch protection. See
> [SECURITY.md](SECURITY.md#trust-boundaries-and-known-limitations) for the
> base-branch recipe.

Findings then appear under the repo's **Security → Code scanning** tab. Omit
`command` to only install the binary and call `egret run` yourself around
several steps.

> ⚠️ Don't inline secrets in `command` (it's written to the job summary, where
> masking is unreliable) and never run this action as a `pull_request_target`
> job that checks out the PR head - it runs your command as **root**. See
> [action/README.md](action/README.md) for details.
>
> ⚠️ Never derive `ingest-url` / `ingest-token` from untrusted PR content (title,
> body, branch name) in a `pull_request_target` workflow - that would let a fork
> redirect the report POST (or the token) to an attacker. Use fixed values or
> repo secrets. Egret refuses to send the token over cleartext `http://` (except
> to `localhost`).

| Input | Default | Purpose |
|---|---|---|
| `command` | `""` | command to run under Egret (empty = install only) |
| `policy` | `""` | path to `policy.yaml` (audit-mode defaults if unset) |
| `mode` | `audit` | `audit` or `block` |
| `sarif` / `upload-sarif` | `true` | produce SARIF / upload it to Code Scanning |
| `fail-on-violations` | `false` | fail the job if any policy violation is recorded |
| `version` | `latest` | Egret release to install |
| `disable-sudo` | `false` | block mode: revoke the build user's passwordless sudo for the run (belt to `no_new_privs`) |
| `ingest-url` | `""` | optional self-hosted [Egret Nest](docs/ingest-contract.md) URL to POST the run to (empty = stay local, no phone-home) |
| `ingest-token` | `""` | bearer token for `ingest-url` (pass a secret; sent as a header, never on a command line) |

Outputs: `report-dir`, `sarif-file`, `violations`. See [action/](action/) for
details. Transparent tracing of *every* step without a wrapper needs a pre-job
daemon - a planned enhancement.

---

## `policy.yaml`

```yaml
version: 1
mode: audit            # audit | block

egress:
  allowed-endpoints:
    - github.com
    - api.github.com
    - "*.actions.githubusercontent.com"   # subdomains only
    - registry.npmjs.org
  block-raw-ip: true

filesystem:
  protected-paths:
    - .git/
    - ~/.ssh/
    - /etc/

process:
  disallowed: []        # e.g. ["nc", "/tmp/*"]

report:
  format: [markdown, json]
  output-dir: ./hardened-report
  github-job-summary: true
```

A full example is in [examples/policy.yaml](examples/policy.yaml).

---

## Architecture

```
GitHub Action wrapper ─┐
                       ├─ both wrap the same core →  AGENT BINARY (eBPF + enforcement)
CLI / daemon  ─────────┘
```

The agent decodes eBPF ring-buffer events (`internal/collector`), evaluates them
against the policy (`internal/policy`), enforces egress via a DNS proxy +
nftables (`internal/enforcer`), and writes reports (`internal/report`). Domain-based
egress: an allowlisted name is resolved through Egret's DNS proxy, the resolved IPs
are added to an nftables allow-set, and everything else is default-denied.

### Repo layout

| Path | What |
|---|---|
| `cmd/egret` | CLI entrypoint |
| `internal/event` | platform-neutral event types |
| `internal/policy` | `policy.yaml` parsing + evaluation |
| `internal/bpf` | eBPF C programs (`*.bpf.c`, CO-RE) |
| `internal/collector` | eBPF loader + ring-buffer decode (Linux) |
| `internal/enforcer` | DNS proxy + nftables firewall (Linux) |
| `internal/report` | Markdown/JSON/job-summary writers |
| `internal/audit` | observed run → suggested allowlist |
| `action/` | GitHub Action wrapper |

---

## Development

```bash
make fmt vet      # hygiene (any OS)
make test         # unit tests (any OS)
make generate     # eBPF codegen (Linux + clang)
make build        # build ./bin/egret (Linux)
```

The cross-platform packages (`policy`, `report`, `audit`, `event`) build and
test on any OS. Anything under a `//go:build linux` tag - the collector and
enforcer - needs a Linux kernel; eBPF integration tests run in a kernel VM.

---

## Roadmap

Egret grows in three **strictly additive** tiers - nothing forces the next one:

1. **CLI + Action** (current) - zero infrastructure.
2. **Server-less GitHub App** - org-wide policy, CI-triggering auto-PRs, branded
   checks, and a Renovate-style [issue dashboard](docs/github-app.md). No server.
3. **Optional self-hosted server** (deferred) - history/dashboards you deploy on
   your own infra; your data never leaves it.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full plan and the "server is never
required" invariant, and [docs/github-app.md](docs/github-app.md) to set up the App.

### Docs map (where things live)

| Doc | Owns |
|---|---|
| [docs/ROADMAP.md](docs/ROADMAP.md) | What Egret is, what works, where it's going |
| [CHANGELOG.md](CHANGELOG.md) | Released changes (agent not tagged yet - ships v1.0 with the dashboard) |
| [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) | Dependency policy |
| [docs/github-app.md](docs/github-app.md) | GitHub App setup |
| [docs/ingest-contract.md](docs/ingest-contract.md) | The agent→dashboard envelope (only cross-repo seam) |

## Known limitations (MVP)

Egress enforcement is domain-allowlist based and has some residual gaps (DoH/DoT,
raw-IP, CDN IP rotation). **Block mode is a confinement boundary on bare/VM hosts;
on GitHub-hosted / container runners it is still being validated - use `audit` mode
there for now.** Every change to the enforcer goes through a dedicated
network-security review.

## Contributing

Contributions go through a consistent review process, including a read-only
Go review and a network-security review for enforcer changes. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the details.

## Contact

- **Website:** [nx1xlab.dev](https://nx1xlab.dev)
- **Contact:** [nx1xlab.dev/contact](https://nx1xlab.dev/contact)
- **Bugs / questions:** open an issue at
  [github.com/nx1x/egret/issues](https://github.com/nx1x/egret/issues)
- **Security:** see [SECURITY.md](SECURITY.md) for private disclosure.

## License

Egret is licensed under the [Apache License 2.0](LICENSE) - © 2026 NX1X
([nx1xlab.dev](https://nx1xlab.dev)). See [NOTICE](NOTICE) for attribution.
