# OpenSSF Best Practices badge - answer sheet

Working notes for the [OpenSSF Best Practices](https://www.bestpractices.dev/)
**passing** badge self-certification. Most criteria auto-detect from the repo;
this sheet covers the ones that want a written justification, mapped to the
evidence already in-tree. Paste these into the form and adjust the badge/project
URLs once the entry exists.

> Scope: this sheet is for the **agent** repo. The dashboard repo has its own copy
> under `docs/OPENSSF-BADGE.md`.

## Basics

| Criterion | Answer / evidence |
|---|---|
| Project description | eBPF runtime security agent for CI/CD and Linux hosts: egress filtering, network/process/file monitoring, audit-mode policy generation. Shipped as a CLI + GitHub Action. |
| Homepage / repo URL | https://github.com/NX1X/Egret |
| FLOSS license | See `LICENSE` (OSI-approved). Stated in `README.md`. |
| Documentation | `README.md`, `docs/` (ROADMAP, DEPENDENCIES, SECURITY-FOLLOWUPS), `CONTRIBUTING.md`. |
| Interact / bug report | GitHub Issues + Discussions; security reports via `SECURITY.md`. |

## Change control

| Criterion | Answer / evidence |
|---|---|
| Public version-controlled source | Git on GitHub. |
| Unique version numbering | SemVer tags (`vMAJOR.MINOR.PATCH`); floating major `v0`. |
| Release notes | `CHANGELOG.md` (Keep a Changelog); release notes are sourced from it by `release.yml`. |

## Reporting

| Criterion | Answer / evidence |
|---|---|
| Vulnerability report process | `SECURITY.md` - private disclosure channel + expectations. |
| Report responsiveness | Maintainer-monitored; acknowledged within a few days. |

## Quality

| Criterion | Answer / evidence |
|---|---|
| Working build system | `make build` / `make build-static` (Go); eBPF bindings committed. |
| Automated test suite | `go test ./...`; pure-package + kernel-integration tiers. CI runs it on every push/PR (`.github/workflows/ci.yml`). |
| Tests added with new features | Required by `CONTRIBUTING.md` ("every fix ships with a regression test"). |
| Warning flags | `go vet`, `gofmt -l` gate in CI; `golangci`-class review per CONTRIBUTING. |

## Security

| Criterion | Answer / evidence |
|---|---|
| Secure development knowledge | Threat model + fail-closed enforcer design in `docs/SECURITY-FOLLOWUPS.md`; review gates in `CONTRIBUTING.md`. |
| Good cryptography | No home-rolled crypto. Release signing via Sigstore/cosign (keyless) + SLSA provenance; TLS-only ingest (`requireSecureEndpoint`). |
| No hardcoded credentials | Secrets come from env / GitHub App tokens minted in-workflow; none in-tree (enforced by Scorecard + review). |
| Delivery against MITM | Signed releases (`SHA256SUMS` + cosign bundle); the Action verifies the binary hash before running it. |

## Analysis

| Criterion | Answer / evidence |
|---|---|
| Static analysis | CodeQL (security-extended), zizmor (workflow lint), OpenSSF Scorecard - all in `.github/workflows/security.yml`. |
| Dynamic analysis | `govulncheck` in CI; **Go native fuzzing** on the untrusted-input parsers (`internal/policy/fuzz_test.go`, `internal/ingest/fuzz_test.go`). |
| Fix analysis-found issues | Code Scanning alerts triaged/fixed; see the fixed CodeQL/zizmor findings in history. |

## Still to do for a higher tier (silver/gold)

- Two-person review on all changes (needs a second maintainer - see `CONTRIBUTING.md`).
- A published security-hardening / assurance case doc.
- Signed commits required (currently preferred).
