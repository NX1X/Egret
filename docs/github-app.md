# Egret GitHub App (server-less) - setup guide

Egret can run with **no App at all** (Tier 1). Adding a GitHub App unlocks
org-wide policy, CI-triggering auto-PRs, branded checks/comments, and the issue
dashboard - **without any server**, because the workflow mints the App token and
*is* the compute. A webhook (the only part that would need a server) is **not**
used.

See [ROADMAP.md](ROADMAP.md) Tier 2 for where this fits.

---

## Authentication model (read this first)

**Installing the App does not, by itself, do anything.** Egret is *server-less* -
there is no Egret backend watching for installs or reacting to your repos. The App's
features (a pass/fail **check**, a sticky **PR comment**, and the **dashboard issue**)
run **inside the Egret GitHub Action**, and the Action must mint its own token to post
them. Which token you hand it decides both what identity the posts appear as and how
much setup you need.

| `github-token` you pass | Setup | Posts as | Scope |
|---|---|---|---|
| `${{ github.token }}` (the built-in `GITHUB_TOKEN`) | **none** - already in every workflow | `github-actions[bot]` | the current repo |
| App installation token (from `actions/create-github-app-token`, using `EGRET_APP_ID` + `EGRET_APP_PRIVATE_KEY` secrets) | **owner-only** - needs the App's private key | `egret-security-app[bot]` (branded) | every repo the App is installed on / org-wide policy |

**Most users want the first row.** All three features work with the built-in
`GITHUB_TOKEN` - the only difference is the posts appear as `github-actions[bot]`
instead of a branded `egret-security-app[bot]`. Grant the job the permissions the
features need (`checks: write`, `pull-requests: write`, `issues: write`) and pass
`github-token: ${{ github.token }}`. No App, no secrets, nothing to install:

```yaml
permissions:
  checks: write
  pull-requests: write
  issues: write
steps:
  - uses: NX1X/Egret@v0
    with:
      command: make ci
      github-token: ${{ github.token }}   # built-in; posts as github-actions[bot]
      check-run: true
      pr-comment: true
      dashboard-issue: true
```

> ⚠️ **The App private key is a master credential.** It authenticates *as the App* on
> **every repository the App is installed on** - not just one repo. Only the person who
> owns the App should ever hold or use it. **Never commit it, never share it, and never
> ask (or tell) anyone to paste an App private key they don't own.** If you do not own
> the Egret Security App, use the `GITHUB_TOKEN` path above - it is the supported path
> for everyone else.

Use the branded App-token path (next sections) only when *you own the App* and want the
branded identity or org-wide policy (`extends: org://…`) across repos you control.

### Why branding needs a key today (and the Tier 3 plan)

A GitHub App can only post *as itself* by proving it holds the App's private key. With
no Egret server, that proof has to happen inside your workflow - so the branded
`egret-security-app[bot]` identity is, today, **owner-only**: it needs the key as a
per-org/per-repo secret. True *install-and-forget* branded use (install the public App,
get branded checks, no key to manage) requires a small **self-hosted backend to hold
the key and mint tokens** - planned as part of **Egret Nest** (Tier 3). Until then:
`GITHUB_TOKEN` for everyone; the App key for the owner only.

---

## 1. Create the App

`Settings → Developer settings → GitHub Apps → New GitHub App`. Fill it in as:

| Field | Value |
|---|---|
| **GitHub App name** | `Egret` (globally unique; else `Egret Security`). Becomes `egret[bot]`. |
| **Homepage URL** | `https://github.com/NX1X/Egret` |
| **Callback URL, Expire user tokens, Request user OAuth, Device Flow** | Leave blank / disabled - these are for user login flows Egret doesn't use. |
| **Setup URL, Redirect on update** | Leave blank. |
| **Webhook → Active** | **Uncheck.** Leave Webhook URL + Secret blank. |
| **Subscribe to events** | None (no webhook). |
| **Where can this be installed** | **Only on this account** for now. |

### Permissions

Minimum (Repository permissions):

| Permission | Level | For |
|---|---|---|
| Metadata | Read | required by GitHub |
| Contents | Read | read `policy.yaml` / central org policy |
| Pull requests | Read & write | auto-PR allowlist, PR comments |
| Issues | Read & write | the Egret dashboard issue |
| Checks | Read & write | pass/fail check runs |

Add per feature:

| Permission | Level | For |
|---|---|---|
| Contents | Read & **write** | auto-commit an allowlist |
| Security events | Read & write | SARIF → Code Scanning |
| Actions | Read | read workflow run artifacts |

Keep permissions minimal - this is a security tool; least privilege is the point.

---

## 2. Get credentials

After creating the App:

1. Note the **App ID** (shown on the App's settings page).
2. **Generate a private key** → downloads a `.pem` file. Store it safely; GitHub
   keeps only the public half.
3. Add secrets to the repo (or org, for reuse):
   - `EGRET_APP_ID` - the numeric App ID (can be a variable instead of a secret).
   - `EGRET_APP_PRIVATE_KEY` - the full contents of the `.pem`.
4. **Install** the App on your account/repos: the App's page → *Install App*.

---

## 3. Use the token in a workflow (no server)

```yaml
permissions:
  contents: read
  pull-requests: write
  issues: write
  checks: write

jobs:
  hardened-build:
    runs-on: ubuntu-latest
    steps:
      # Mint a short-lived installation token from the App's key.
      - uses: actions/create-github-app-token@v3   # pin to a full SHA in real workflows
        id: egret-token
        with:
          app-id: ${{ secrets.EGRET_APP_ID }}
          private-key: ${{ secrets.EGRET_APP_PRIVATE_KEY }}
          # Optional: read a central org policy repo too.
          # owner: ${{ github.repository_owner }}
          # repositories: ${{ github.event.repository.name }},.egret-policy

      - uses: actions/checkout@v4

      - uses: NX1X/Egret@v0
        with:
          policy: .github/egret-policy.yaml
          mode: block
          # Egret uses this token (falls back to GITHUB_TOKEN when unset).
          github-token: ${{ steps.egret-token.outputs.token }}
```

When `github-token` is not provided, Egret falls back to the default
`GITHUB_TOKEN` and simply skips the App-only features (org policy, CI-triggering
PRs, branded identity). **Nothing about the App is required** - it is pure
enhancement, per the roadmap invariant.

---

## 4. Later: distribution & the server

- To let other orgs use it, switch **Where can this be installed** to *Any
  account*, and add a **GitHub App Manifest** flow so each org one-click-creates
  their own App (keeps distribution server-less; each org holds its own key).
- If/when the optional self-hosted server (Tier 3) exists, the **only** change is
  turning the webhook **on** and pointing it at *that* deployer's server. The
  agent and this guide stay the same.
