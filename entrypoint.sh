#!/usr/bin/env bash
# Egret GitHub Action entrypoint.
#
# Subcommands:
#   install  - download + checksum-verify the egret binary onto the runner.
#   run      - run a user command under `egret run`, emit report + SARIF, set
#              step outputs, and (optionally) fail the job on violations.
#
# Whole-job scope: this wraps the command you pass via the `command` input - make
# that your whole build (a script, or `make ci`) to cover the job. Transparent
# tracing of *every* step without a wrapper needs a pre-job daemon and is a
# self-hosted-runner concern (a planned enhancement); the wrapped-command model works
# on stock GitHub-hosted runners today.
set -euo pipefail

REPO="NX1X/Egret"
INSTALL_DIR="${RUNNER_TEMP:-/tmp}/egret"
BIN="${INSTALL_DIR}/egret"
ASSET="egret_linux_amd64"
# The keyless cosign signing identity for a release (Fulcio cert subject +
# OIDC issuer). Used to verify SHA256SUMS.bundle. Kept in sync with release.yml.
COSIGN_IDENTITY_RE='^https://github.com/NX1X/Egret/\.github/workflows/release\.yml@.*'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

# Network hardening for every release fetch. A bare `curl -fsSL` has no timeout
# and no retry: a blackholed connection or a stalled CDN hangs the CONSUMER's job
# until their job timeout with no diagnostic, and a single transient 5xx fails the
# install outright. Cap the handshake and the total transfer, and ride out
# transient failures.
#
# Deliberately NOT --retry-all-errors: that retries hard client errors too, so a
# 401 (bad token) or a 404 (no asset published for this tag - a path we handle and
# fall through on) would burn four round trips and the retry delays before
# reporting what was already known on the first response. curl's default retry set
# is 408/429/5xx plus connect/transfer timeouts; --retry-connrefused adds the other
# genuinely transient case. Note this set does NOT cover a truncated body
# (CURLE_PARTIAL_FILE, exit 18) - that fails closed on the first attempt, which is
# the behaviour we want for a file we are about to hash.
#
# -q MUST come first: without it curl reads ~/.curlrc before these options, and the
# wrapped build runs as ROOT, so it can write a .curlrc containing `insecure` and
# turn every later Egret fetch into an unverified-TLS download. On an ephemeral
# hosted runner that is bounded, but on a persistent self-hosted runner the poisoned
# file survives into other jobs. --config below ADDS a source; it does not suppress
# the implicit one.
#
# --proto/--proto-redir pin the whole chain to HTTPS. The `latest` tag lookup is the
# one leg covered by neither the checksum nor the signature, so an on-path downgrade
# to http:// could rewrite tag_name to an older, still-validly-signed release
# (rollback to a known-vulnerable version) without tripping any verification.
CURL_BASE=(-q --fail --silent --show-error --location
  --proto '=https' --proto-redir '=https'
  --connect-timeout 10 --retry 3 --retry-delay 2 --retry-connrefused)

# fetch <url> <dest> [max_seconds] - download to a file with the hardened options.
# --max-time bounds EACH attempt, so a connection that opens and then stalls
# mid-body fails fast instead of hanging the job. --retry-max-time stops new
# retries once max_seconds have passed since the first attempt; without it the
# worst case is (1 + --retry) attempts at the full ceiling, about 4x max_seconds.
# With it, the worst case is about 2x max_seconds.
fetch() {
  local url="$1" dest="$2" max="${3:-60}"
  curl "${CURL_BASE[@]}" --max-time "${max}" --retry-max-time "${max}" -o "${dest}" "${url}"
}

# valid_token <value> - true when the value is inside the GitHub token alphabet.
# See fetch_api for why this check is structural, not cosmetic.
valid_token() {
  [[ "$1" =~ ^[A-Za-z0-9_.-]+$ ]]
}

# fetch_api <url> - GET the GitHub API to stdout, authenticated when a token is
# available. The UNAUTHENTICATED API allows 60 requests/hour per source IP, shared
# with every other Actions job on that runner IP, so `version: latest` can be
# rate-limited into a confusing "release asset not found" failure.
#
# The token goes in through curl's stdin config file rather than argv, so it is not
# readable from /proc/<pid>/cmdline by the (root) build we are about to run.
#
# It is VALIDATED first, and that is not paranoia about the value's shape - curl's
# config format is a full option grammar, not a header string. A token containing a
# double quote followed by a newline closes the quoted value and everything after it
# parses as curl DIRECTIVES: `url = ...` redirects the request to an attacker's
# host and sends this Authorization header to it, `output = ...` writes an
# arbitrary local file, `proxy = ...` reroutes the connection. Real GitHub
# credentials are base62 and cannot express that, so the previous version was safe
# by luck of the token alphabet rather than by construction - and `github-token` is
# an untyped free-text input on a published Marketplace action, so a consumer
# templating it from a vault lookup or a concatenated expression was exposed.
# Rejecting anything outside the GitHub token alphabet makes the injection
# structurally impossible instead of merely unlikely.
#
# No ambient ${GITHUB_TOKEN} fallback: this must only ever use a credential the
# caller deliberately handed to the action, which is how the publish path already
# behaves. Silently authenticating with a token the user never passed here would
# make the action's outbound identity depend on unrelated workflow-level env.
#
# --location (not --location-trusted) means curl strips the header if the API ever
# redirects off api.github.com, so the token can't leak to an asset CDN.
fetch_api() {
  local url="$1" token="${EGRET_GITHUB_TOKEN:-}"
  if [[ -n "${token}" ]]; then
    # cmd_install validates first and fails closed with a clear error. This
    # repeat keeps the injection guard local to the one place the token enters
    # a curl config. The message goes to STDERR: callers pipe this function's
    # stdout into parse_tag_name, which would silently swallow a stdout message.
    if ! valid_token "${token}"; then
      echo "::error::github-token contains characters outside the expected token alphabet ([A-Za-z0-9_.-]); refusing to use it." >&2
      return 1
    fi
    printf 'header = "Authorization: Bearer %s"\n' "${token}" \
      | curl "${CURL_BASE[@]}" --max-time 30 --retry-max-time 30 --config - "${url}"
  else
    curl "${CURL_BASE[@]}" --max-time 30 --retry-max-time 30 "${url}"
  fi
}

# parse_tag_name reads a releases JSON blob on stdin and prints tag_name. Portable
# (sed, not grep -P) so it works regardless of the runner's grep flavour.
parse_tag_name() {
  sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# verify_signature <tag> <sums> - verify the release SHA256SUMS against its
# keyless cosign signature (SHA256SUMS.bundle). A checksum served from the same
# origin as the binary only catches corruption, not a compromised release; the
# Sigstore signature is what ties SHA256SUMS to this repo's release workflow
# identity. Behaviour:
#   - cosign present + bundle verifies      -> pass
#   - cosign present + bundle FAILS/absent  -> fail closed (tampering signal)
#   - cosign absent, EGRET_REQUIRE_SIGNATURE=true -> fail closed (strict opt-in)
#   - cosign absent, default                -> warn, fall back to checksum-only
#     (GitHub-hosted runners don't ship cosign; don't break the default install)
verify_signature() {
  local tag="$1" sums="$2"
  local bundle="${INSTALL_DIR}/SHA256SUMS.bundle"
  local url="https://github.com/${REPO}/releases/download/${tag}/SHA256SUMS.bundle"

  if ! command -v cosign >/dev/null 2>&1; then
    if [[ "${EGRET_REQUIRE_SIGNATURE:-false}" == "true" ]]; then
      echo "::error::require-signature is set but cosign is not installed; refusing to run an unverified binary as root. Add a cosign install step (e.g. sigstore/cosign-installer) before this action."
      return 1
    fi
    echo "::warning::cosign not found; falling back to checksum-only verification. Install cosign (or set require-signature) to verify the release signature, which a same-origin checksum can't provide."
    return 0
  fi

  if ! fetch "${url}" "${bundle}" 60; then
    echo "::error::cosign is available but no SHA256SUMS.bundle was published for ${tag}; refusing to run (a signed release is expected)."
    return 1
  fi
  if ! cosign verify-blob \
        --bundle "${bundle}" \
        --certificate-identity-regexp "${COSIGN_IDENTITY_RE}" \
        --certificate-oidc-issuer "${COSIGN_OIDC_ISSUER}" \
        "${sums}" >/dev/null 2>&1; then
    echo "::error::cosign signature verification failed for SHA256SUMS (${tag}); refusing to run a binary whose release signature does not match ${REPO}'s release workflow identity."
    return 1
  fi
  echo "Verified SHA256SUMS signature with cosign (identity ${COSIGN_IDENTITY_RE}, issuer ${COSIGN_OIDC_ISSUER})."
}

# verify_checksum <tag> - download the release SHA256SUMS, verify its cosign
# signature (see verify_signature), then verify BIN against it. Fail closed: the
# binary runs as root, so an unverifiable download must not proceed (pinning a
# version is not enough on its own without hash + signature verification).
verify_checksum() {
  local tag="$1"
  local sums="${INSTALL_DIR}/SHA256SUMS"
  local url="https://github.com/${REPO}/releases/download/${tag}/SHA256SUMS"
  if ! fetch "${url}" "${sums}" 60; then
    echo "::error::No SHA256SUMS published for ${tag}; refusing to run an unverified binary as root."
    return 1
  fi
  # Verify the signature over SHA256SUMS BEFORE trusting any digest it lists.
  verify_signature "${tag}" "${sums}" || return 1
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
    # Validate the token HERE, in the parent shell, before the lookup. Inside the
    # $(fetch_api ... | parse_tag_name) pipeline below, a rejected token only
    # produces an empty tag, which then surfaces as a misleading "rate limit"
    # hint. A malformed token is a caller configuration error: fail closed and
    # name it.
    if [[ -n "${EGRET_GITHUB_TOKEN:-}" ]] && ! valid_token "${EGRET_GITHUB_TOKEN}"; then
      echo "::error::github-token contains characters outside the expected token alphabet ([A-Za-z0-9_.-]); refusing to use it. Pass a GitHub App installation token or GITHUB_TOKEN, or pin an explicit version: to skip the release lookup."
      echo "::endgroup::"
      exit 1
    fi
    tag="$(fetch_api "https://api.github.com/repos/${REPO}/releases/latest" | parse_tag_name || true)"
    # Don't let a failed lookup fall through as a bare "asset not found": name the
    # likely cause so the fix (pass github-token, or pin `version:`) is obvious.
    if [[ -z "${tag}" ]]; then
      echo "::warning::Could not resolve the latest Egret release tag from the GitHub API. If this is a rate limit (60 requests/hour per runner IP when unauthenticated), pass the \`github-token\` input or pin an explicit \`version:\`."
    fi
  fi

  if [[ -n "${tag}" ]]; then
    local url="https://github.com/${REPO}/releases/download/${tag}/${ASSET}"
    echo "Downloading ${url}"
    # Larger ceiling than the metadata fetches: this is the multi-MB binary.
    if fetch "${url}" "${BIN}" 300; then
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

# count_violations <report.json> - number of entries in the "violations" array,
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

# out <key> <value> - append a step output using the delimiter form, so a value
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

  # Everything the post-run steps TRUST lives in a fresh directory owned by root:
  # the binary that later runs with your GitHub token, and the report that sets
  # the violation count. In block mode the build runs as THIS user, which owns
  # ${INSTALL_DIR} and ${outdir}, so it could otherwise swap the binary or plant
  # a report there. It cannot write into a root-owned 0755 directory, and /var/tmp
  # is sticky, so it cannot rename or delete one either. The report is copied to
  # ${outdir} afterwards, so the report-dir output is unchanged. (In audit mode the
  # build runs as root, and audit mode is not a security boundary.)
  local tmpbase=/var/tmp
  [[ -d "${tmpbase}" ]] || tmpbase=/tmp
  local safe_dir
  safe_dir="$(sudo mktemp -d "${tmpbase}/egret.XXXXXXXXXX")"
  # shellcheck disable=SC2064  # expand safe_dir now; it is local to this function
  trap "sudo rm -rf -- '${safe_dir}'" EXIT
  sudo chmod 0755 "${safe_dir}"
  sudo install -o root -g root -m 0755 "${BIN}" "${safe_dir}/egret"
  local safe_bin="${safe_dir}/egret"
  local safe_out="${safe_dir}/report"

  local args=(run --mode "${EGRET_MODE:-audit}" --output-dir "${safe_out}")
  if [[ -n "${EGRET_POLICY:-}" ]]; then
    args+=(--config "${EGRET_POLICY}")
  fi
  if [[ "${EGRET_DISABLE_SUDO:-false}" == "true" ]]; then
    args+=(--disable-sudo)
  fi

  echo "::group::Egret run (${EGRET_MODE:-audit} mode)"
  # Egret needs root/CAP_BPF; GitHub-hosted runners allow passwordless sudo. The
  # user command is passed as a single argument to bash -c - never expanded into
  # this script - so it runs exactly as written with no re-interpretation here.
  #
  # The optional dashboard ingest URL/token reach the binary through the
  # ENVIRONMENT (never argv) so the bearer token is not visible in `ps` or
  # /proc/<pid>/cmdline. --preserve-env names them explicitly (belt) on top of
  # -E (suspenders) so delivery survives a stricter sudoers env_reset policy.
  # Only ask sudo to preserve them when ingest is actually configured - a strict
  # self-hosted sudoers that rejects --preserve-env then can't fail an ordinary
  # (no-ingest) run; it can only affect a run that opted into ingest.
  local sudo_env=()
  if [[ -n "${EGRET_INGEST_URL:-}" ]]; then
    # shellcheck disable=SC2054  # not a list of array elements: sudo's
    # --preserve-env takes ONE comma-separated variable list as a single argument.
    sudo_env=(--preserve-env=EGRET_INGEST_URL,EGRET_INGEST_TOKEN)
  fi
  # `sudo -E` preserves the whole environment, so anything set on this step is
  # visible to the wrapped build - which is exactly the third-party toolchain and
  # dependency code Egret exists to watch. EGRET_GITHUB_TOKEN is needed by the
  # INSTALL step (release lookup) and by the `egret github` publish calls below,
  # which set GITHUB_TOKEN explicitly per invocation; the wrapped command never
  # needs it, so drop it from the child.
  #
  # This is DEFENCE IN DEPTH, NOT A BOUNDARY. It removes the token from the child's
  # own environment, which stops the overwhelmingly common case - dependency code
  # enumerating its environment. It does NOT hide the token from a build that goes
  # looking: the build runs as root, this script is still alive holding the value,
  # and root can read /proc/<pid>/environ regardless of ptrace_scope. Treat any
  # token passed to this action as reachable by the code it runs, and pass the
  # least-privileged one that works.
  #
  # NOT scrubbed: a caller-exported GITHUB_TOKEN. That is the user's own job-level
  # variable, commonly set so `gh` works inside the wrapped build; removing it would
  # break those builds. Egret no longer reads it either (see fetch_api), so the only
  # credential Egret itself introduces is the one dropped here.
  set +e
  sudo "${sudo_env[@]+"${sudo_env[@]}"}" -E \
    env -u EGRET_GITHUB_TOKEN "PATH=${PATH}" "${safe_bin}" "${args[@]}" -- bash -euo pipefail -c "${EGRET_COMMAND}"
  local rc=$?
  set -e
  echo "::endgroup::"

  local reportjson="${safe_out}/report.json"

  # A command ran, so a report must exist. Without one, the count below would
  # read 0 violations and skip SARIF, publishing and fail-on-violations - the
  # outcome a hostile build wants. Fail closed instead.
  if [[ ! -f "${reportjson}" ]]; then
    echo "::error::Egret wrote no report, so this run's result cannot be trusted. Failing closed (a missing report must not read as zero violations). See the egret output above."
    exit 1
  fi

  # Copy the reports to the caller-visible directory (the report-dir output).
  # Remove whatever is at each name first, so a link or directory the build left
  # there is replaced, never written through.
  local f
  for f in report.json report.md report.sarif; do
    if [[ -f "${safe_out}/${f}" ]]; then
      rm -rf -- "${outdir:?}/${f}"
      cp -- "${safe_out}/${f}" "${outdir}/${f}"
    fi
  done

  # SARIF for Code Scanning, generated from the TRUSTED report by the TRUSTED binary.
  local sarif=""
  if [[ "${EGRET_SARIF:-true}" == "true" ]]; then
    sarif="${outdir}/egret.sarif"
    rm -rf -- "${sarif}"
    echo "::group::Egret SARIF"
    local rargs=(report --from "${reportjson}" --format sarif --out "${sarif}")
    if [[ -n "${EGRET_POLICY:-}" ]]; then
      rargs+=(--policy-path "${EGRET_POLICY}")
    fi
    "${safe_bin}" "${rargs[@]}"
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
  # each subcommand - never on a command line (invisible in ps / cmdline).
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
        GITHUB_TOKEN="${EGRET_GITHUB_TOKEN}" "${safe_bin}" github check --from "${reportjson}" \
          || echo "::warning::egret github check failed (does the token have checks: write?)"
      fi
      if [[ "${EGRET_PR_COMMENT:-false}" == "true" ]]; then
        if [[ "${GITHUB_REF:-}" == refs/pull/* ]]; then
          GITHUB_TOKEN="${EGRET_GITHUB_TOKEN}" "${safe_bin}" github comment --from "${reportjson}" \
            || echo "::warning::egret github comment failed (does the token have pull-requests: write?)"
        else
          echo "::notice::pr-comment enabled but this is not a pull_request event; skipping the comment."
        fi
      fi
      if [[ "${EGRET_DASHBOARD_ISSUE:-false}" == "true" ]]; then
        GITHUB_TOKEN="${EGRET_GITHUB_TOKEN}" "${safe_bin}" github dashboard --from "${reportjson}" \
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
