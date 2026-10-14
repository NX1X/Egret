# Changelog

Notable changes to Egret, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

These fixes matter in **block mode**, where the build runs as the ordinary runner
user and Egret runs as root. In audit mode the build already runs as root, so
audit mode is not a security boundary.

### Security

- **Root no longer writes through symlinks the build planted.** Only the last
  component of the report directory was checked, so a symlinked parent redirected
  Egret's root writes anywhere on the host. The job summary was opened with
  `O_CREATE` and followed symlinks and hard links, so a build could point it at a
  root-owned file such as `/etc/ld.so.preload`. On a self-hosted runner this
  could lead to root code execution (traced in code, not run end to end). Paths
  are now opened one component at a time, and a
  symlink is followed only in a directory that root alone controls. Files are
  written relative to the open directory handle. The job summary must be a regular
  file with one link, owned by the user who started Egret.
- **A build can no longer erase or forge its own result.** A build could create a
  directory named `report.json`: the write failed, the error was only logged, the
  violation count read as 0, and `fail-on-violations` passed. A failed report write
  now fails the run. The action also refuses to continue when no report exists.
- **The post-run steps no longer run a binary the build could replace.** SARIF
  generation and GitHub publishing (with your token) ran the binary in the
  runner-owned install directory. The action now copies the verified binary into a
  fresh root-owned directory before the build starts, writes the report there, and
  uses only those afterwards. The report is then copied to the usual `report-dir`.

### Tests

- New hermetic tests run the real `entrypoint.sh run` with stand-in `sudo` and
  `egret` binaries, and plant symlinks, hard links and directories for the report
  writer. The attack tests fail on the previous code.

## [0.3.0] - Install robustness + CI cost and timeout work

### Fixed

- **The installer no longer hangs without a timeout.** Every release download
  (`SHA256SUMS`, `SHA256SUMS.bundle`, the binary, and the `latest` tag lookup) now
  has a connect timeout, a total-transfer ceiling, and bounded retries on transient
  failures. Previously a blackholed connection or a stalled CDN hung *your* job
  until *your* job timeout with no diagnostic, and a single transient 5xx failed the
  install outright. Retries deliberately exclude hard client errors, so a bad token
  or a missing asset still fails on the first response instead of after four.
- **`version: latest` can now be authenticated.** Pass `github-token` (e.g.
  `${{ github.token }}`) and the release lookup uses it. The unauthenticated GitHub
  API allows 60 requests/hour per runner IP, shared across every Actions job on that
  IP; exceeding it previously surfaced as a confusing "release asset not found".
  When the lookup does fail, the error now names the likely cause and the fix.
- **A malformed `github-token` now fails with the real reason.** The token check
  ran inside the pipeline that parses the release tag, so its error message was
  swallowed and you saw a misleading "rate limit" hint instead. The token is now
  checked once, before the lookup, and the install stops with a message that names
  the problem. A regression test (`test/action`) runs the real `entrypoint.sh`
  without root or network.
- **Download retries now have a total time limit.** The per-attempt ceiling applied
  to every retry, so a stalled binary download could take about 20 minutes before it
  failed. `--retry-max-time` stops new retries once the ceiling has passed, which
  halves the worst case.
- **OpenSSF Scorecard runs again.** `ossf/scorecard-action` v2.4.0 pulls its image
  from `gcr.io`, and that pull is now refused. v2.5.0 pulls from `ghcr.io`.

### Security

- **Go toolchain 1.26.9 (GO-2026-6617).** The release binary and CI now build with
  Go 1.26.9, which fixes an HTTP/2 crash caused by a race in the `net/http` HPACK
  encoder. `govulncheck` reported it as reachable, which failed the security
  workflow on `main`.
- **`cilium/ebpf` v0.22.0 (GO-2026-6238).** v0.16.0 had an integer overflow in BTF
  parsing, and `govulncheck` reported it as reachable. The upgrade also moves the
  indirect `cobra`, `pflag`, `x/mod`, `x/sync` and `x/tools` modules forward. The
  committed eBPF bindings build and pass all tests against the new version, and CI
  now loads them into a real kernel on every change (see Changed).
- **The wrapped build no longer inherits `EGRET_INGEST_TOKEN` either.** Egret passed
  its own environment verbatim to your build in both audit and block mode, so a
  hostile dependency could read the dashboard ingest credential straight out of
  `os.Environ()` - and use it to forge or suppress the very findings meant to catch
  it. Egret's credentials are now filtered from the child process in one place, with
  tests. `EGRET_INGEST_URL` and everything else is untouched.
- **`github-token` is validated before use.** It is passed to curl through a config
  file on stdin (to keep it out of `/proc/<pid>/cmdline`), and curl's config format
  is an option grammar rather than a header string - so a token containing a quote
  and a newline could inject arbitrary curl directives, including one that redirects
  the request to another host and sends the bearer header along with it. Real GitHub
  tokens cannot express that, but the input is free text on a published action, so
  the value is now rejected unless it matches `[A-Za-z0-9_.-]+`.
- **Release downloads are pinned to HTTPS and ignore `~/.curlrc`.** `--proto`/
  `--proto-redir` stop a redirect from downgrading the `latest` lookup to plaintext
  (the one leg covered by neither checksum nor signature, so a downgrade could roll
  a consumer back to an older, still-validly-signed release). `-q` stops a root
  build from writing a `~/.curlrc` containing `insecure` and turning every later
  Egret fetch into an unverified-TLS download - which matters most on persistent
  self-hosted runners, where the poisoned file survives into other jobs.
- **No ambient `GITHUB_TOKEN` fallback.** The release lookup uses only a credential
  explicitly passed to the action, matching how the publish path already behaved.
- Documentation now states plainly that stripping the token from the wrapped
  command is **hardening, not isolation**: your build runs as root and can read the
  action's environment via `/proc`. Previous wording implied the risk was closed.
- **The wrapped build no longer inherits `github-token`.** Egret runs your command
  under `sudo -E`, which handed the entire step environment - including an App
  installation token with `checks` / `issues` / `pull-requests` write - to the
  third-party toolchain and dependency code Egret exists to watch. The token is now
  stripped from the child environment; the publish calls that need it set it
  explicitly per invocation. The token is also sent only to `api.github.com`, via
  curl's stdin config rather than argv, so it is not readable from `/proc`.
- **`zizmor` is pinned in the security workflow.** An unpinned installer there was
  both an unreviewed supply-chain input and a source of findings that changed
  between runs with no repo change. Renovate now tracks it, and `govulncheck`'s
  pinned version, via custom managers.
- `govulncheck` is still built from source on every run rather than cached. The
  Actions cache is writable by any run on the same ref, and a restored scanner
  binary that reports "no vulnerabilities" is a worse outcome than a slow one -
  the same reasoning behind `cache: false` on the release trust path.

### Changed

- **CI now loads the eBPF probes from the commit under test.** The `ebpf` job runs
  the freshly built binary under `sudo` in audit mode, monitors a `curl`, and fails
  unless the network probe records the connection. Before, CI only proved that the
  code compiled, and the action self-test used the published release, so a change
  that broke probe loading would first fail for users after a release.
- CI no longer runs the same work twice per commit: `govulncheck` ran as both a
  step in `ci.yml` and a dedicated job in `security.yml`, and the pure packages'
  tests ran in both CI jobs. `govulncheck` is now only the `security.yml` job, and
  the `ebpf` job tests only the packages that need the generated eBPF bindings
  (computed as the complement of `PURE_PKGS`, so a new package is never silently
  dropped from CI).
- OpenSSF Scorecard no longer runs on pull requests. It grades the repository, not
  a diff, and `publish_results` cannot publish from a PR.
- The `enforcer-regate` workflow's `push` trigger had path filters but no branch
  filter, so it fired on release tags, on the floating `v0` tag, and on every branch
  that already had a pull request running it. It now runs on the pull request and on
  `main`. Its container install also dropped `clang`, `llvm` and `libbpf-dev`: the
  job builds from committed bindings and the runtime only needs `nft`, so nothing
  invoked them.
- The action self-test gained a `concurrency` group (the only workflow without one,
  so rapid pushes to a PR piled up parallel runs) and skips docs-only changes.
- Job timeouts were sized against observed runtimes instead of 10-40x them, and the
  network-facing steps gained their own step timeouts, so a hang surfaces in minutes
  rather than at the end of a 20-minute job.

## [0.2.0] - Security hardening (pentest remediation)

### Changed (upgrade impact)

- **A policy file with an unknown or misspelled key now fails to load** instead of
  silently ignoring it. If you were relying on a key that was quietly dropped
  (e.g. a typo'd `allow-endpoints`), the run now errors until you correct it -
  this is intentional: a silently-ignored key meant the rule was never in effect.
- **The Action installer verifies the release signature when `cosign` is present.**
  On a runner that already has cosign, a release whose `SHA256SUMS.bundle`
  signature doesn't verify is now rejected (fail closed). The new
  `require-signature` input additionally makes cosign's absence a hard failure.
- **The report directory may no longer be a symlink**, and a local `extends:` ref
  may no longer resolve (via symlink or `..`) outside the policy directory.

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
- **CI/CD hardening:** `concurrency` + per-job `timeout-minutes` across CI/Security
  workflows, zizmor tool-failure no longer hidden behind `|| true`, and `action.yml`
  uses `$GITHUB_ACTION_PATH` instead of interpolating `github.action_path` into `run:`.

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
  self-updating allowlist dashboard issue, and an audit → allowlist-PR loop - all
  work with a plain `GITHUB_TOKEN` or an App token.

### Security

- **Signed, verifiable releases:** each release ships `SHA256SUMS`, SLSA build
  provenance, and a keyless cosign signature; the Action verifies the binary before
  running it.
- **Hardened by default:** no phone-home; egress/event records are metadata only
  (never payloads); block mode is fail-closed on teardown.

[0.3.0]: https://github.com/NX1X/Egret/releases/tag/v0.3.0
[0.2.0]: https://github.com/NX1X/Egret/releases/tag/v0.2.0
[0.1.3]: https://github.com/NX1X/Egret/releases/tag/v0.1.3
[0.1.2]: https://github.com/NX1X/Egret/releases/tag/v0.1.2
[0.1.1]: https://github.com/NX1X/Egret/releases/tag/v0.1.1
[0.1.0]: https://github.com/NX1X/Egret/releases/tag/v0.1.0
