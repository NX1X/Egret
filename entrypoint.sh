#!/usr/bin/env bash
# Egret GitHub Action entrypoint.
#
# Subcommands:
#   install  — download + checksum-verify the egret binary onto the runner.
#   run      — run a user command under `egret run`, emit report + SARIF, set
#              step outputs, and (optionally) fail the job on violations.
#
# Whole-job scope: this wraps the command you pass via the `command` input — make
# that your whole build (a script, or `make ci`) to cover the job. Transparent
# tracing of *every* step without a wrapper needs a pre-job daemon and is a
# self-hosted-runner concern (a planned enhancement); the wrapped-command model works
# on stock GitHub-hosted runners today.
set -euo pipefail

REPO="NX1X/Egret"
INSTALL_DIR="${RUNNER_TEMP:-/tmp}/egret"
BIN="${INSTALL_DIR}/egret"
ASSET="egret_linux_amd64"

# parse_tag_name reads a releases JSON blob on stdin and prints tag_name. Portable
# (sed, not grep -P) so it works regardless of the runner's grep flavour.
parse_tag_name() {
  sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# verify_checksum <tag> — download the release SHA256SUMS and verify BIN against
# it. Fail closed: the binary runs as root, so an unverifiable download must not
# proceed (pinning a version is not enough on its own without hash verification).
verify_checksum() {
  local tag="$1"
  local sums="${INSTALL_DIR}/SHA256SUMS"
  local url="https://github.com/${REPO}/releases/download/${tag}/SHA256SUMS"
  if ! curl -fsSL -o "${sums}" "${url}"; then
    echo "::error::No SHA256SUMS published for ${tag}; refusing to run an unverified binary as root."
    return 1
  fi
  # Hash-compare directly: the asset is saved as ${BIN} (…/egret), not "${ASSET}",
  # so `sha256sum -c` on the SHA256SUMS line (which names the file "${ASSET}") would
  # look for the wrong on-disk name and fail. Compare the digests instead.
  local want got
  want="$(grep -E "  ?${ASSET}\$" "${sums}" | awk '{print $1}')"
  got="$(sha256sum "${BIN}" | awk '{print $1}')"
  if [[ -z "${want}" || "${want}" != "${got}" ]]; then
    echo "::error::Checksum verification failed for ${ASSET} (${tag}): expected '${want:-<not listed>}', got '${got}'."
    return 1
  fi
  echo "Verified ${ASSET} against SHA256SUMS."
}

cmd_install() {
  mkdir -p "${INSTALL_DIR}"
  local version="${EGRET_VERSION:-latest}"
  echo "::group::Install Egret (${version})"

  local tag="${version}"
  if [[ "${version}" == "latest" ]]; then
    tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | parse_tag_name || true)"
  fi

  if [[ -n "${tag}" ]]; then
    local url="https://github.com/${REPO}/releases/download/${tag}/${ASSET}"
    echo "Downloading ${url}"
    if curl -fsSL -o "${BIN}" "${url}"; then
      verify_checksum "${tag}"   # fails closed on mismatch / missing sums
      chmod +x "${BIN}"
      echo "${INSTALL_DIR}" >> "${GITHUB_PATH}"
      echo "::endgroup::"
      return 0
    fi
    echo "Release asset not found for ${tag}."
  fi

  # Building from source is NOT a silent fallback: it substitutes an unversioned
  # binary for a pinned one, so it must be explicitly opted into.
  if [[ "${EGRET_ALLOW_BUILD_FROM_SOURCE:-false}" != "true" ]]; then
    echo "::error::Could not install a verified Egret release for '${version}'. Set the action input allow-build-from-source: true to build from source instead (unpinned)."
    echo "::endgroup::"
    exit 1
  fi
  echo "Building egret from source (allow-build-from-source=true; unverified/unpinned)"
  make -C "${GITHUB_ACTION_PATH}" generate build
  cp "${GITHUB_ACTION_PATH}/bin/egret" "${BIN}"
  echo "${INSTALL_DIR}" >> "${GITHUB_PATH}"
  echo "::endgroup::"
}

# count_violations <report.json> — number of entries in the "violations" array,
# using jq when present, else python3, else a conservative 0.
count_violations() {
  local f="$1"
  [[ -f "${f}" ]] || { echo 0; return; }
  if command -v jq >/dev/null 2>&1; then
    jq '.violations | length' "${f}" 2>/dev/null || echo 0
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; print(len((json.load(open(sys.argv[1])) or {}).get("violations") or []))' "${f}" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

# out <key> <value> — append a step output using the delimiter form, so a value
# containing a newline can't forge additional outputs ($GITHUB_OUTPUT injection).
out() {
  local key="$1" val="$2" delim="ghadelim_$$_${RANDOM}"
  { echo "${key}<<${delim}"; printf '%s\n' "${val}"; echo "${delim}"; } >> "${GITHUB_OUTPUT}"
}

cmd_run() {
  # Root execution + fork PRs: this runs the caller's command as root. Refuse to
  # run under pull_request_target (untrusted head, secrets in scope) unless the
  # workflow explicitly opts in, to avoid handing root to a fork PR.
  if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request_target" && "${EGRET_ALLOW_PULL_REQUEST_TARGET:-false}" != "true" ]]; then
    echo "::error::Egret runs your command as root; refusing to run under pull_request_target (untrusted PR code + secrets). Set allow-pull-request-target: true only if you do NOT check out the PR head."
    exit 1
  fi

  local outdir="${EGRET_OUTPUT_DIR:-${INSTALL_DIR}/report}"
  mkdir -p "${outdir}"

  local args=(run --mode "${EGRET_MODE:-audit}" --output-dir "${outdir}")
  if [[ -n "${EGRET_POLICY:-}" ]]; then
    args+=(--config "${EGRET_POLICY}")
  fi
  if [[ "${EGRET_DISABLE_SUDO:-false}" == "true" ]]; then
    args+=(--disable-sudo)
  fi

  echo "::group::Egret run (${EGRET_MODE:-audit} mode)"
  # Egret needs root/CAP_BPF; GitHub-hosted runners allow passwordless sudo. The
  # user command is passed as a single argument to bash -c — never expanded into
  # this script — so it runs exactly as written with no re-interpretation here.
  #
  # The optional dashboard ingest URL/token reach the binary through the
  # ENVIRONMENT (never argv) so the bearer token is not visible in `ps` or
  # /proc/<pid>/cmdline. --preserve-env names them explicitly (belt) on top of
  # -E (suspenders) so delivery survives a stricter sudoers env_reset policy.
  # Only ask sudo to preserve them when ingest is actually configured — a strict
  # self-hosted sudoers that rejects --preserve-env then can't fail an ordinary
  # (no-ingest) run; it can only affect a run that opted into ingest.
  local sudo_env=()
  if [[ -n "${EGRET_INGEST_URL:-}" ]]; then
    sudo_env=(--preserve-env=EGRET_INGEST_URL,EGRET_INGEST_TOKEN)
  fi
  set +e
  sudo "${sudo_env[@]+"${sudo_env[@]}"}" -E \
    env "PATH=${PATH}" "${BIN}" "${args[@]}" -- bash -euo pipefail -c "${EGRET_COMMAND}"
  local rc=$?
  set -e
  echo "::endgroup::"

  local reportjson="${outdir}/report.json"

  # SARIF for Code Scanning.
  local sarif=""
  if [[ "${EGRET_SARIF:-true}" == "true" && -f "${reportjson}" ]]; then
    sarif="${outdir}/egret.sarif"
    echo "::group::Egret SARIF"
    local rargs=(report --from "${reportjson}" --format sarif --out "${sarif}")
    if [[ -n "${EGRET_POLICY:-}" ]]; then
      rargs+=(--policy-path "${EGRET_POLICY}")
    fi
    "${BIN}" "${rargs[@]}"
    echo "::endgroup::"
  fi

  local violations
  violations="$(count_violations "${reportjson}")"

  out "report-dir" "${outdir}"
  out "sarif-file" "${sarif}"
  out "violations" "${violations}"

  echo "Egret: ${violations} policy violation(s); wrapped command exit=${rc}"

  # App-token publishing: post the report to GitHub via the binary's own
  # `egret github` subcommands, using the caller-supplied token (a GitHub App
  # installation token for org-wide + branded identity, or GITHUB_TOKEN). Each is
  # opt-in and SOFT-fails (a ::warning::, never a job failure) so a missing token
  # permission can't break the caller's build. The token travels as an env var to
  # each subcommand — never on a command line (invisible in ps / cmdline).
  local want_publish="false"
  if [[ "${EGRET_CHECK_RUN:-false}" == "true" || "${EGRET_PR_COMMENT:-false}" == "true" || "${EGRET_DASHBOARD_ISSUE:-false}" == "true" ]]; then
    want_publish="true"
  fi
  if [[ "${want_publish}" == "true" && -f "${reportjson}" ]]; then
    if [[ -z "${EGRET_GITHUB_TOKEN:-}" ]]; then
      echo "::warning::check-run/pr-comment/dashboard-issue enabled but no github-token was provided; skipping GitHub publishing."
    else
      echo "::group::Egret GitHub publish"
      if [[ "${EGRET_CHECK_RUN:-false}" == "true" ]]; then
        GITHUB_TOKEN="${EGRET_GITHUB_TOKEN}" "${BIN}" github check --from "${reportjson}" \
          || echo "::warning::egret github check failed (does the token have checks: write?)"
      fi
      if [[ "${EGRET_PR_COMMENT:-false}" == "true" ]]; then
        if [[ "${GITHUB_REF:-}" == refs/pull/* ]]; then
          GITHUB_TOKEN="${EGRET_GITHUB_TOKEN}" "${BIN}" github comment --from "${reportjson}" \
            || echo "::warning::egret github comment failed (does the token have pull-requests: write?)"
        else
          echo "::notice::pr-comment enabled but this is not a pull_request event; skipping the comment."
        fi
      fi
      if [[ "${EGRET_DASHBOARD_ISSUE:-false}" == "true" ]]; then
        GITHUB_TOKEN="${EGRET_GITHUB_TOKEN}" "${BIN}" github dashboard --from "${reportjson}" \
          || echo "::warning::egret github dashboard failed (does the token have issues: write?)"
      fi
      echo "::endgroup::"
    fi
  fi

  # Fail on violations if requested (even in audit mode); otherwise forward the
  # wrapped command's own exit code so the job reflects the build result.
  if [[ "${EGRET_FAIL_ON_VIOLATIONS:-false}" == "true" && "${violations}" -gt 0 ]]; then
    echo "::error::Egret recorded ${violations} policy violation(s) (fail-on-violations)"
    exit 1
  fi
  exit "${rc}"
}

main() {
  case "${1:-}" in
    install) cmd_install ;;
    run)     cmd_run ;;
    start)   echo "::warning::'start' is deprecated; pass a 'command' input to the Egret action instead." ;;
    *) echo "usage: entrypoint.sh {install|run}" >&2; exit 2 ;;
  esac
}

main "$@"
