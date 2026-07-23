# Contributing to Egret

Thanks for helping build Egret. This project pairs a Go userspace agent with
eBPF C programs, so a few things are stricter than a typical repo - mostly
around the egress enforcer and the build toolchain.

## We're looking for contributors

Egret is young and actively maintained, and I'd genuinely like people to build
it with me - not just drive-by patches, but regulars who take an area and own
it. If you care about eBPF, CI/CD supply-chain security, or Go systems code,
there is room for you here.

- **Say hi first if you want:** open a [Discussion](https://github.com/NX1X/Egret/discussions)
  or a draft issue describing what you'd like to work on. No ceremony required -
  a small PR is a perfectly good introduction.
- **How reviews work right now:** while the team is small, the maintainer
  reviews PRs (often async, usually within a few days). The review *gates* below
  aren't gatekeeping - they're the checklist your PR is measured against, and
  they apply to the maintainer's own changes too. As the project grows we move
  to peer review and hand out merge rights to established contributors.
- **Recognition:** sustained contributors get listed as maintainers and, where
  they want it, review/merge rights on their area.

### Good first contributions

Low-context, high-value places to start:

- **More fuzz targets.** We fuzz the untrusted-input parsers (`policy`, `ingest`);
  the DNS proxy, SARIF/report readers, and audit-session decoding are good next
  targets. See `internal/policy/fuzz_test.go` for the pattern.
- **Policy examples** under `examples/` for a stack you know (Node, Python, Rust,
  container builds).
- **Distro/runner coverage:** try `egret run` on a distro or CI runner we don't
  test yet and file what breaks - the enforcer's kernel assumptions vary.
- **Docs:** anything in `docs/` that tripped you up while getting started.

Anything tagged `good first issue` or `help wanted` is fair game - comment to
claim it so we don't double up.

## Ground rules

- Read [docs/ROADMAP.md](docs/ROADMAP.md) first.
- Keep PRs small and focused. One concern per PR.
- Every user-facing change updates [CHANGELOG.md](CHANGELOG.md).
- Be excellent to each other - see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

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
| `internal/enforcer/` or `internal/bpf/network.bpf.c` | **a network-security review must sign off** - egress-bypass + fail-closed teardown |
| `internal/bpf/` or `internal/collector/` | an eBPF review; verifier/CO-RE checks |
| any Go | a Go review (idioms, error handling, resource cleanup) |
| `go.mod` / `go.sum` | a supply-chain audit + a `docs/DEPENDENCIES.md` entry; 7-day cooldown |
| `.github/workflows/` or `action/` | a CI/CD security review; actions pinned by SHA |

Run a full security review before opening a PR that touches auth, crypto,
network, dependencies, or workflows.

## Adding a dependency

Egret keeps its dependency surface **minimal and pure-Go where possible** -
justify every new module in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).

## Tests

- Every fix ships with a regression test.
- Enforcer / probe behavior is verified against a real kernel (`make test-e2e`
  or the kernel VM), not just mocked.
- Pure-package logic (policy evaluation, report rendering) has table tests.

## After a bug fix

Capture the root cause and the fix in your PR description, so reviewers and
future contributors learn from Egret's specific history of pain.
