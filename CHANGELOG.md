# Changelog

Notable changes to Egret, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - Pentest hardening

### Security

- **Report artifacts are now tamper-resistant.** `report.json` / `.md` / `.sarif`
  are written atomically (temp file + rename), and the build's descendants are
  reaped (the whole build cgroup in block mode, the command's process group in
  audit mode) BEFORE the report is written - so a process the build detaches can
  no longer race and overwrite the report that the SARIF upload, PR comment, and
  dashboard issue are generated from.
- **Report cells can no longer be forged via hostile filenames.** `mdEscape` now
  strips CR/LF (and caps cell length), so a captured filename like
  `evil\n\n## No violations` can't inject fake rows/headers into the Markdown
  report or job summary.
- **Protected-path matching is canonicalized.** File/process policy now resolves
  `..` and symlinks on both sides before matching, closing the traversal and
  symlink-through bypasses. (Relative-path writes remain best-effort pending
  capture-time cwd resolution - documented in SECURITY.md.)
- **`extends:` is confined to the policy directory.** A local `extends` ref can
  no longer escape its base directory via `..`, an absolute path, or a **symlink**
  (containment is enforced on the symlink-resolved real path), so a crafted policy
  can't pull an arbitrary local file in as its base - which on a root-privileged
  runner would be an arbitrary file read.
- **The report directory can't be a symlink.** Egret refuses to write reports
  through a symlinked `output-dir`, so the monitored build can't swap the report
  directory for a symlink to an attacker-chosen location right before exiting.
- **Policy files are strict-decoded.** An unknown or misspelled key (e.g.
  `allow-endpoints`) now fails fast instead of silently disabling the intended
  rule.
- **The DNS proxy refuses multi-question packets**, closing a path where a denied
  name could ride along in a second question past the allowlist check.
- **The Action installer verifies the release cosign signature.** When `cosign`
  is present, `SHA256SUMS.bundle` is verified (fail closed) before trusting the
  checksum; a new `require-signature` input makes its absence a hard failure.
- **CI/CD hardening:** `harden-runner` (audit) on the release + app-token jobs,
  `concurrency` + per-job `timeout-minutes` across CI/Security workflows, zizmor
  tool-failure no longer hidden behind `|| true`, and `action.yml` uses
  `$GITHUB_ACTION_PATH` instead of interpolating `github.action_path` into `run:`.

### Documentation

- **SECURITY.md** gains a "Trust boundaries and known limitations" section: the
  policy file is read from the checked-out ref (attacker-editable on
  `pull_request` unless loaded from the base branch), and file/process policy is
  best-effort detection, not an enforcement boundary.
- Usage examples pin the Action to a commit SHA (floating tags noted as the
  convenience alternative).

## [0.1.3] - Action rename + Code Scanning cleanup

### Changed

- **Renamed the Marketplace Action to "Egret Security Action"** (was "Egret
  Security"), so the Action is distinguished from the Egret Security App by tool
  type. Reference it unchanged as `NX1X/Egret@v0` or a pinned `@v0.1.3`.
- **Dogfood: our own CI test suites now run under the Egret Action in audit
  mode**, so CI monitors the egress/exec/file behaviour of the toolchain and
  dependency code during the tests (audit never blocks the build).

### Security

- **Closed all CodeQL `go/incorrect-integer-conversion` findings** in the
  block-mode credential path: build uid/gid are parsed as bounded 32-bit values
  and carried as `uint32` end to end, with no unchecked `int` narrowing.
- **Scoped the self-test App installation token to least privilege**
  (checks / issues / pull-requests write, contents read) instead of the App's
  blanket installation permissions (zizmor `github-app`).
- **Removed step-output template injection** in the self-test enforcement
  assertion by passing step outputs through `env` (zizmor `template-injection`).

## [0.1.2] - Brand refresh

### Changed

- **New visual identity.** The mark is now an egret in flight; the icon, app-icon,
  logo (a self-contained dark-card lockup), and social preview were all redrawn.
- **Marketplace branding icon** is now `feather` (the Actions Marketplace supports
  only a named Feather icon + color, so the egret artwork cannot be the listing tile).
- **README** now leads with the logo lockup.

## [0.1.1] - Marketplace listing + App-token publishing

### Added

- **GitHub Marketplace listing.** The Action now lives at the repository root and is
  published as "Egret Security" on the Actions Marketplace. Reference it as
  `NX1X/Egret@v0` (floating major) or a pinned `@v0.1.1`.
- **App-token publish features.** New action inputs `github-token`, `check-run`,
  `pr-comment`, and `dashboard-issue`: pass a GitHub App installation token to publish
  a branded pass/fail check, a sticky PR comment, and the Egret Security Dashboard
  issue as `egret-security-app[bot]` (each opt-in; falls back to `GITHUB_TOKEN`).

### Fixed

- **Action install checksum verification** now hash-compares the downloaded binary
  directly, so `install` no longer fails closed on a valid release (the binary is
  saved under a different on-disk name than the SHA256SUMS entry).
- **SARIF results always carry a location** (fall back to a suggested policy path),
  which GitHub Code Scanning requires - SARIF uploads are no longer rejected.

### Changed

- Go toolchain 1.26.5 (clears the crypto/tls, net/textproto, and x509 stdlib
  advisories); codeql-action v4, checkout v7, setup-go v6, refreshed base-image digests.
- Release notes are now sourced from this CHANGELOG.

## [0.1.0] - first release

Egret is a runtime security agent for CI/CD and Linux hosts:
eBPF-based egress filtering, network/process/file monitoring, and audit-mode policy
generation - shipped as a CLI and a GitHub Action, with no server and no phone-home.

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
  Renovate-style allowlist dashboard issue, and an audit → allowlist-PR loop - all
  work with a plain `GITHUB_TOKEN` or an App token.

### Security

- **Signed, verifiable releases:** each release ships `SHA256SUMS`, SLSA build
  provenance, and a keyless cosign signature; the Action verifies the binary before
  running it.
- **Hardened by default:** no phone-home; egress/event records are metadata only
  (never payloads); block mode is fail-closed on teardown.

[0.1.3]: https://github.com/NX1X/Egret/releases/tag/v0.1.3
[0.1.2]: https://github.com/NX1X/Egret/releases/tag/v0.1.2
[0.1.1]: https://github.com/NX1X/Egret/releases/tag/v0.1.1
[0.1.0]: https://github.com/NX1X/Egret/releases/tag/v0.1.0
