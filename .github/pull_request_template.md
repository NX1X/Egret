<!-- Thanks for contributing to Egret. Keep PRs focused and small. -->

## What & why

<!-- One or two sentences: what this changes and the motivation. Link the issue. -->

Closes #

## Type

- [ ] Feature
- [ ] Fix
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] CI / build / deps
- [ ] Security

## Checklist

- [ ] `make fmt vet` clean; `make test-pure` passes (and `make test` on Linux if eBPF/collector touched)
- [ ] `CHANGELOG.md` updated (category: Added/Changed/Deprecated/Removed/Fixed/Security)
- [ ] New/changed behavior is covered by a test
- [ ] No secrets, tokens, or captured payloads in code, logs, or fixtures

## Security-sensitive paths (tick if touched — extra review required)

- [ ] `internal/enforcer/` or `internal/bpf/network.bpf.c` → **network-security review required** (egress-bypass + fail-closed teardown)
- [ ] `internal/bpf/` or `internal/collector/` → eBPF review (verifier / CO-RE)
- [ ] Dependency change (`go.mod`/`go.sum`) → supply-chain review + `docs/DEPENDENCIES.md` updated
- [ ] `.github/workflows/` or `action/` → CI/CD security review; actions pinned by SHA

## Notes for reviewers

<!-- Anything that helps review: trade-offs, follow-ups, kernel versions tested, etc. -->
