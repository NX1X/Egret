# Contributing to Egret

Thanks for helping build Egret. This project pairs a Go userspace agent with
eBPF C programs, so a few things are stricter than a typical repo — mostly
around the egress enforcer and the build toolchain.

## Ground rules

- Read [docs/ROADMAP.md](docs/ROADMAP.md) first.
- Keep PRs small and focused. One concern per PR.
- Every user-facing change updates [CHANGELOG.md](CHANGELOG.md).
- Be excellent to each other — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

The **cross-platform packages** (`policy`, `report`, `audit`, `event`,
`monitor`, `enforcer`, `sarif`, `ingest`) build and test on any OS. The
**eBPF codegen** and the full Linux build need a Linux host with `clang`,
`llvm`, `libbpf` headers, and kernel BTF.

```bash
make fmt vet          # hygiene (any OS)
make test-pure        # tests that need no eBPF codegen (any OS)

# On a Linux host:
make generate         # compile eBPF C via clang + bpf2go
make build            # build ./bin/egret
make test             # full test tree (needs generated bindings)
make test-e2e         # kernel integration tests (root)
```

If you don't have a Linux box, the eBPF integration tests run in a kernel VM.

## Branching & commits

- Never commit directly to `main` (a hook refuses it). Branch, PR, review.
- Signed commits preferred. Conventional-commit style messages
  (`feat:`, `fix:`, `docs:`, `refactor:`, `ci:`).
- Rebase on `main` before requesting review; keep history readable.

## Review gates (what will get asked of your PR)

| If your change touches… | Then… |
|---|---|
| `internal/enforcer/` or `internal/bpf/network.bpf.c` | **a network-security review must sign off** — egress-bypass + fail-closed teardown |
| `internal/bpf/` or `internal/collector/` | an eBPF review; verifier/CO-RE checks |
| any Go | a Go review (idioms, error handling, resource cleanup) |
| `go.mod` / `go.sum` | a supply-chain audit + a `docs/DEPENDENCIES.md` entry; 7-day cooldown |
| `.github/workflows/` or `action/` | a CI/CD security review; actions pinned by SHA |

Run a full security review before opening a PR that touches auth, crypto,
network, dependencies, or workflows.

## Adding a dependency

Egret keeps its dependency surface **minimal and pure-Go where possible** —
justify every new module in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).

## Tests

- Every fix ships with a regression test.
- Enforcer / probe behavior is verified against a real kernel (`make test-e2e`
  or the kernel VM), not just mocked.
- Pure-package logic (policy evaluation, report rendering) has table tests.

## After a bug fix

Capture the root cause and the fix in your PR description, so reviewers and
future contributors learn from Egret's specific history of pain.
