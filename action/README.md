# Egret GitHub Action

Run your build under [Egret](https://github.com/NX1X/Egret) - eBPF egress /
process / file monitoring - and upload the findings to **GitHub Code Scanning**
as SARIF.

## Usage

```yaml
name: build
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:                # scope to the job, not the whole workflow
      contents: read
      security-events: write    # required to upload SARIF to Code Scanning
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: NX1X/Egret@v0.1.0
        with:
          policy: .github/egret-policy.yaml
          mode: audit                # observe + report (default)
          command: make ci           # your whole build, monitored end-to-end
          fail-on-violations: false  # set true to block the merge on findings
```

Egret writes `report.json` / `report.md` / `report.sarif`, appends a summary to
the **job summary**, and (by default) uploads the SARIF so findings show up under
**Security → Code scanning**.

> ⚠️ **Do not inline secrets in `command`.** The command string is written to the
> report and the (publicly-viewable) job summary, where GitHub's secret masking
> does **not** reliably apply. Never write `command: deploy --token ${{ secrets.X }}`.
> Instead export the secret as an env var on the step and reference the **name**
> inside your script: `env: { TOKEN: ${{ secrets.X }} }` then `command: ./deploy.sh`
> (which reads `$TOKEN`).

> ⚠️ **Egret runs your command as root.** Never use this action in a
> `pull_request_target` job that checks out the PR head - that would run untrusted
> fork code as root with your secrets. The action refuses to run under
> `pull_request_target` unless you set `allow-pull-request-target: true`. Prefer
> GitHub-hosted (ephemeral) runners; on self-hosted runners a root compromise
> persists across jobs.

## How wrapping works

The `command` input is run as `sudo egret run --mode <mode> [--config <policy>]
-- bash -c "<command>"`. Make it your whole build (a script, `make ci`, etc.) to
cover the job. The input is passed to the entrypoint via an environment variable
and handed to `bash -c` as a single argument - it is **never interpolated into a
`run:` script**, so it can't inject steps into the Action itself.

Transparent tracing of *every* step without a wrapper needs a pre-job daemon and
is a self-hosted-runner concern - a planned enhancement. Omit `command` to just
install the binary and call `egret run` yourself.

## Inputs

| Input | Default | Description |
|---|---|---|
| `command` | `""` | Command to run under Egret. Empty = install only. |
| `policy` | `""` | Path to `policy.yaml`. Audit-mode defaults if unset. |
| `mode` | `audit` | `audit` (observe) or `block` (enforce default-deny egress). |
| `version` | `latest` | Egret release tag to install. |
| `sarif` | `true` | Produce a SARIF report from the run. |
| `upload-sarif` | `true` | Upload the SARIF to Code Scanning (needs `security-events: write`). |
| `fail-on-violations` | `false` | Fail the job if Egret records any policy violation. |
| `output-dir` | `$RUNNER_TEMP/egret/report` | Where reports are written. |
| `allow-build-from-source` | `false` | If no **verified** release is available, build from source (unpinned). Off = fail closed. |
| `allow-pull-request-target` | `false` | Permit running under `pull_request_target` (root + secrets - see warning above). |

Installed release binaries are **checksum-verified** against the release's
`SHA256SUMS` before running; if verification isn't possible the action fails
closed (it never runs an unverified binary as root).

## Outputs

| Output | Description |
|---|---|
| `report-dir` | Directory containing `report.json` / `report.md` / `report.sarif`. |
| `sarif-file` | Path to the generated SARIF (empty if disabled / no command). |
| `violations` | Number of policy violations recorded. |

## Permissions

- `security-events: write` - to upload SARIF (only when `upload-sarif: true`).
- `contents: read` - checkout.

The `github/codeql-action/upload-sarif` step is SHA-pinned per the repo's
supply-chain policy (all third-party actions are pinned to a full commit SHA).
