# Egret GitHub App (server-less) - setup guide

Egret can run with **no App at all** (Tier 1). Adding a GitHub App unlocks
org-wide policy, CI-triggering auto-PRs, branded checks/comments, and the issue
dashboard - **without any server**, because the workflow mints the App token and
*is* the compute. A webhook (the only part that would need a server) is **not**
used.

See [ROADMAP.md](ROADMAP.md) Tier 2 for where this fits.

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
      - uses: actions/create-github-app-token@v1
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
