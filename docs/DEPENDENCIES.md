# Dependency Policy

Egret is a **supply-chain security tool**, so our own dependencies are attack
surface. Every third-party package is vetted **before** adoption, and the
decision is recorded here. This policy governs **both** repos
(`Egret` and `Egret-nest-dashboard`).

> Rule of thumb: a dependency you didn't vet is a vulnerability you didn't audit.
> When in doubt, use the standard library.

## Vetting checklist (all must hold before adding)

- [ ] **Maintained** — commit/release activity within ~12 months; **not archived**.
- [ ] **Reputable** — well-known org/maintainer, meaningful adoption.
- [ ] **No known unpatched CVEs** — check `govulncheck` and the advisory DB.
- [ ] **Permissive license** — MIT / BSD / Apache-2.0 / ISC. No GPL/AGPL in code
      we distribute (agent + Action + App). (The self-hosted server may use a
      copyleft dep only if it stays a separable service — decide case by case.)
- [ ] **Small transitive footprint** — review what it drags in.
- [ ] **Pure-Go / no CGO preferred** — keeps static builds and cross-compilation
      working (important for a single self-hostable binary).
- [ ] **Pinned + checksummed** — exact version in `go.mod`, hash in `go.sum`,
      `go mod verify` clean.

## Process

1. **Search first** (as we did for every entry below); record the decision here.
2. Prefer the **standard library**. Go 1.22+ already covers most needs:
   `net/http` (ServeMux with `METHOD /path` patterns), `html/template`
   (contextual auto-escaping), `go:embed`, `database/sql`, `crypto/*`,
   `encoding/json`.
3. **No npm/Node build chain** for the dashboard UI — vendor a single **pinned,
   SRI-hashed** asset (e.g. `htmx.min.js`) instead of a package manager.
4. **Automated guards (CI):** `govulncheck ./...`, `go mod verify`,
   `go mod tidy` must be clean, and Dependabot for updates.
5. New/changed dependencies are called out explicitly in the PR description.

---

## Allowed — Agent (`Egret`)

| Module | Purpose | Why it passes |
|---|---|---|
| `github.com/cilium/ebpf` | eBPF loader / maps / ringbuf | Cilium project; the reference pure-Go eBPF stack; actively maintained. |
| `github.com/miekg/dns` | DNS proxy | De-facto Go DNS library; ubiquitous; maintained. |
| `github.com/spf13/cobra` (+ `spf13/pflag`) | CLI framework | Industry-standard; huge adoption; maintained. |
| `go.yaml.in/yaml/v3` | policy.yaml parsing | **Replaces `gopkg.in/yaml.v3`** (archived Apr 2025). YAML-org-maintained fork, drop-in API, v3.0.4 (Jun 2025). |
| `golang.org/x/*` (indirect) | sys/net/sync | Go team; first-party. |

## Allowed — Egret Nest Dashboard (`Egret-nest-dashboard`)

| Module | Purpose | Why it passes |
|---|---|---|
| **stdlib** (`net/http`, `html/template`, `database/sql`, `go:embed`, `crypto/*`, `encoding/json`) | server, routing, templating, storage glue, ingest auth | First-party; zero supply-chain risk. Use first. |
| `modernc.org/sqlite` | embedded storage | **Pure-Go** SQLite (no CGO); production-proven (e.g. Gogs, 2+ yrs); enables static single-binary + cross-compile. |
| `github.com/google/go-github/vNN` | GitHub REST client | Google-maintained; widely used. **Optional** — only if hand-rolled `net/http` calls become unwieldy. |
| `github.com/bradleyfalzon/ghinstallation/v2` | App installation auth (JWT→token) | Standard companion to go-github for App auth. **Only if** the server itself authenticates as the App (server-side); not needed when tokens come from the Action. |
| `github.com/golang-jwt/jwt/v5` | JWT | Maintained successor to the abandoned `dgrijalva/jwt-go`. Usually pulled in **via** ghinstallation. |
| **htmx** (`htmx.min.js`, vendored, pinned + SRI) | frontend interactivity | Single JS file, no build step. Safe with `html/template` auto-escaping + `selfRequestsOnly:true`, `allowEval:false`, `allowScriptTags:false`. |

**Preferred defaults:** stdlib `net/http` ServeMux over a third-party router;
raw `net/http` + `encoding/json` for the handful of GitHub calls before reaching
for `go-github`. Add the optional libs only when justified.

---

## Blacklisted / avoid

| Package / class | Reason | Use instead |
|---|---|---|
| `gopkg.in/yaml.v3`, `github.com/go-yaml/yaml` | **Unmaintained / archived** (Apr 2025) | `go.yaml.in/yaml/v3` |
| `github.com/dgrijalva/jwt-go` | Abandoned; access-control CVE (CVE-2020-26160) | `github.com/golang-jwt/jwt/v5` |
| `github.com/mattn/go-sqlite3` | Requires **CGO** — breaks static builds / cross-compile / easy self-hosting (not insecure, but against our goals) | `modernc.org/sqlite` |
| **npm/Node build chains** for the dashboard UI | Large, opaque transitive supply-chain surface | Vendored, pinned, SRI-hashed single assets (htmx) |
| Any **archived / >18-month-stale** package with no security response | Unpatched-risk | find a maintained equivalent, or stdlib |
| Packages with **known unpatched CVEs** | Direct risk | patched version or alternative |
| **GPL/AGPL** deps linked into the agent/Action/App | License incompatible with our Apache-2.0 distribution | permissive-licensed equivalent |
| Obscure/typosquat-risk names, single-maintainer with no adoption | Low trust / hijack risk | vet harder or avoid |

## Pending actions

- ✅ **Migrate `gopkg.in/yaml.v3` → `go.yaml.in/yaml/v3`** (done in the agent; see go.mod).
- ✅ **`govulncheck` in CI** — both repos run it in `.github/workflows/` (ci/security).
- ✅ **Automated dependency updates** — Renovate (`.github/renovate.json5`) in both repos
  (cooldown, manual-merge, digest-pinned images), in lieu of Dependabot.

_Last reviewed: 2026-07-08._
