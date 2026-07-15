# Changelog

Notable changes to Egret, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — first release

Egret is a runtime security agent for CI/CD and Linux hosts:
eBPF-based egress filtering, network/process/file monitoring, and audit-mode policy
generation — shipped as a CLI and a GitHub Action, with no server and no phone-home.

### Added

- **Runtime monitoring (audit mode).** eBPF probes record every outbound connection
  (IPv4/IPv6), the process tree, and writes to protected paths; evaluate them against
  a `policy.yaml`; and emit a Markdown/JSON report plus SARIF.
- **Egress enforcement (block mode).** A DNS proxy plus cgroup-scoped nftables
  default-deny confine a build to its allowlist, with the build run de-privileged so
  it can't escape the confinement. Validated on bare/VM hosts; on container CI runners,
  audit mode is recommended for now.
- **Policy** (`policy.yaml`): domain allowlist (`allowed-endpoints`, with `*.`
  wildcards), raw IP/CIDR allowlist (`allowed-ips`), `block-raw-ip`, protected paths,
  disallowed processes, and `extends:` for a shared base policy (local or `org://`).
- **GitHub Action.** Wrap a job command, upload SARIF to Code Scanning, and write the
  job summary. Inputs include `command`, `policy`, `mode`, `disable-sudo`, and an
  optional `ingest-url` to POST the run to a self-hosted dashboard.
- **GitHub App integration** (server-less): PR checks, sticky comments, a
  Renovate-style allowlist dashboard issue, and an audit → allowlist-PR loop — all
  work with a plain `GITHUB_TOKEN` or an App token.

### Security

- **Signed, verifiable releases:** each release ships `SHA256SUMS`, SLSA build
  provenance, and a keyless cosign signature; the Action verifies the binary before
  running it.
- **Hardened by default:** no phone-home; egress/event records are metadata only
  (never payloads); block mode is fail-closed on teardown.

[0.1.0]: https://github.com/NX1X/Egret/releases/tag/v0.1.0
