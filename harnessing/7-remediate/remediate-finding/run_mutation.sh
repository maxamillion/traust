#!/usr/bin/env bash
# Mutation-test the package a patch touched and emit ONE evidence item
# matching remediation.schema.json#/$defs/patch_evidence (kind: mutation).
#
# Why this exists: a regression test that passes proves the test RUNS, not
# that it would FAIL if the fix were reverted. A mutant that survives on the
# patched line is direct evidence the added test asserts nothing.
#
# Containment (S10). mewt runs the target's own test suite once per mutant,
# so it is hostile-input execution and inherits run_checks.sh's boundary
# exactly: rootless, cap-dropped, no-new-privileges, credential-free,
# --network=none, digest-pinned image, and a disposable copy rather than the
# caller's worktree (so no .git of the real checkout is reachable at all).
# There is deliberately NO UNATTESTED fallback: either podman provides the
# boundary, or the orchestrator declares the surrounding job already is one
# (TRAUST_SANDBOXED_RUNNER, see resolve_boundary). With neither, the script
# emits `not_attempted: <reason>` and exits 0 — an honest evidence item rather
# than a silent decision to run target code in the open. run_checks.sh already
# records that PATH shims are "not a boundary", and a mutation campaign
# executes target code N times instead of once.
#
# Scope: Go only. mewt supports C++, DAML, Go, JS/TS, Rust, Solidity and Move
# but NOT Python, so mutation evidence is never portfolio-wide assurance.
# Widening means granting that toolchain in the safe-exec profile first.
#
# NEVER RUNS ON THE REMEDIATION WORKTREE. mewt rewrites target files in place
# and stores state in a `mewt.sqlite` in its working directory; upstream's own
# docs advise running "against a clean git repo so that you can use
# `git reset --hard HEAD` to restore any mutations that escape the cleanup
# phase" (docs/how-it-works.md). The remediation worktree is exactly where the
# patch diff comes from, so a leaked mutation or a stray database would
# corrupt the artifact under review. This script therefore copies the
# worktree, mutates the copy, and deletes it.
#
# Cost: a campaign is targets x mutants x test-suite-duration and can run for
# HOURS. Point it at the package the patch touched, never a repository root,
# and note the hard timeout below.
#
# Usage:
#   run_mutation.sh <worktree> <target-path> [<out-dir>] [<timeout-seconds>]
#
# Output (stdout): one JSON object (a patch_evidence item).

set -uo pipefail

WORK="${1:?usage: run_mutation.sh <worktree> <target-path> [<out-dir>] [<timeout-s>]}"
TARGET="${2:?usage: run_mutation.sh <worktree> <target-path> [<out-dir>] [<timeout-s>]}"
OUT="${3:-$WORK/.remediation-checks}"
TIMEOUT_S="${4:-${REMEDIATION_MUTATION_TIMEOUT:-3600}}"
mkdir -p "$OUT"
LOG="$OUT/mutation.log"

IMG_GO="${REMEDIATION_IMG_GO:-docker.io/library/golang@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac}"

emit_not_attempted() {
  python3 - "$1" <<'PY'
import json, sys
print(json.dumps({
    "kind": "mutation",
    "outcome": f"not_attempted: {sys.argv[1]}",
    "tool": "mewt",
    "deterministic_steps": f"skipped: {sys.argv[1]}",
}))
PY
  exit 0
}

# --- execution boundary ------------------------------------------------------
# This runs the target's own test suite, so it must execute inside SOME
# boundary. Two are acceptable:
#
#   podman   — nested container, the workstation case. Strongest, and default
#              whenever podman is present.
#   attested — the process is ALREADY inside a credential-free, network-
#              restricted sandbox supplied by the platform (a CI/Konflux job
#              pod whose image carries the scanner binaries, per
#              docs/continuous-operations.md). Declared by the orchestrator
#              setting TRAUST_SANDBOXED_RUNNER to a short label naming it.
#
# TRAUST_SANDBOXED_RUNNER is a DECLARATION OF DEPLOYMENT FACT, not a security
# control: anything that can set an env var can set it, and it buys nothing
# against an attacker already executing here. Its only job is to stop the
# ABSENCE of podman from being read as permission to run target code in the
# open. With neither boundary there is no evidence — `not_attempted`, never a
# silent downgrade.
#
# The resolved boundary is recorded in the emitted evidence so a reader can
# always tell which one produced a verdict.
resolve_boundary() {
  # `command -v podman` is the WRONG probe: it finds the client binary, which
  # is present on a Mac whose VM is stopped and in images that ship the CLI
  # with no working runtime. Every run then fails with exit 125 — the exact
  # failure this resolver exists to avoid. `podman info` round-trips to the
  # runtime, so it answers "can I actually run a container", and it is cheap
  # (no image pull).
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    printf 'podman'
  elif [[ -n "${TRAUST_SANDBOXED_RUNNER:-}" ]]; then
    printf 'attested:%s' "$TRAUST_SANDBOXED_RUNNER"
  else
    printf ''
  fi
}

mewt_in_boundary() {
  # mewt_in_boundary <cmd...> — run under the resolved boundary, always
  # against the disposable copy, never the caller's worktree.
  if [[ "$BOUNDARY" == podman ]]; then
    podman run --rm --network=none \
      --security-opt=no-new-privileges --cap-drop=ALL \
      --user "$(id -u):$(id -g)" --userns=keep-id \
      --tmpfs /home/runner:rw,mode=700 -e HOME=/home/runner \
      -e GOFLAGS -e GOMEMLIMIT -e GOMAXPROCS -e GOPROXY=off \
      -v "$SANDBOX":/work:Z \
      -v "$MEWT":/usr/local/bin/mewt:ro,Z \
      -w /work "$IMG_GO" "$@"
  else
    # The surrounding job IS the boundary. Still scrub the environment and
    # deny module egress, so the attested path is not merely "run it raw".
    ( cd "$SANDBOX" && env -i PATH="$PATH" HOME="${HOME:-/tmp}" \
        GOFLAGS="${GOFLAGS:-}" GOPROXY=off "$@" )
  fi
}

MEWT="$(command -v mewt 2>/dev/null)"
[[ -z "$MEWT" ]] && emit_not_attempted "mewt is not installed on this host"
BOUNDARY="$(resolve_boundary)"
[[ -z "$BOUNDARY" ]] && emit_not_attempted "no execution boundary: podman is unavailable and TRAUST_SANDBOXED_RUNNER is unset, so the campaign would run target code unsandboxed"
[[ -f "$WORK/go.mod" ]] || emit_not_attempted "not a Go module; mewt has no Python support and other languages are out of scope here"

MEWT_VERSION="$("$MEWT" --version 2>/dev/null | head -1)"

# Disposable copy: mewt mutates in place and its cleanup is documented as
# best-effort, so the worktree that produces the patch is never the one it
# touches. Copied with cp -a rather than a fresh checkout so uncommitted
# state is included exactly as the checks saw it.
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/mewt-sandbox-XXXXXX")"
cleanup() { chmod -R u+w "$SANDBOX" 2>/dev/null; rm -rf "$SANDBOX"; }
trap cleanup EXIT INT TERM
cp -a "$WORK/." "$SANDBOX/" 2>/dev/null || emit_not_attempted "could not copy the worktree to a disposable sandbox"

# Go test command for the campaign; mewt auto-detects the language from the
# target's extension and has NO --language flag on `run` (verified against
# src/core/cli.rs RunArgs, mewt 4.x).
mewt_in_boundary timeout --signal=TERM --kill-after=30 "$TIMEOUT_S" \
  mewt run --test.cmd "go test ./..." "$TARGET" >"$LOG" 2>&1
RC=$?

# Read the verdict from `mewt status --format json`, a declared interface with
# per-target rows — NOT from the campaign banner. The banner's vocabulary is
# "Caught/Uncaught/Skipped", and an earlier version of this script guessed
# "killed/survived" and would have returned no verdict on every real run.
STATUS_JSON="$OUT/mutation-status.json"
mewt_in_boundary mewt status --format json >"$STATUS_JSON" 2>/dev/null || true

python3 "$(dirname "$0")/scripts/mutation_evidence.py" \
  --log "$LOG" --rc "$RC" --target "$TARGET" \
  --tool-version "$MEWT_VERSION" --status-json "$STATUS_JSON" \
  --boundary "$BOUNDARY"
