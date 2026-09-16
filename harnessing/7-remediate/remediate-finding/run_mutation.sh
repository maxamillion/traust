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
# --network=none, .git read-only inside the mount, digest-pinned image.
# There is deliberately NO native fallback: run_checks.sh already records
# that PATH shims are "not a boundary", and running a mutation campaign —
# which executes target code N times instead of once — outside the boundary
# would be a posture regression. No podman, no mutation evidence: the script
# emits `not_attempted: <reason>` and exits 0, which is a valid, honest
# evidence item rather than a silent skip.
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

MEWT="$(command -v mewt 2>/dev/null)"
[[ -z "$MEWT" ]] && emit_not_attempted "mewt is not installed on this host"
command -v podman >/dev/null 2>&1 || emit_not_attempted "podman unavailable; a mutation campaign is not run outside the container boundary"
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
podman run --rm --network=none \
  --security-opt=no-new-privileges --cap-drop=ALL \
  --user "$(id -u):$(id -g)" --userns=keep-id \
  --tmpfs /home/runner:rw,mode=700 -e HOME=/home/runner \
  -e GOFLAGS -e GOMEMLIMIT -e GOMAXPROCS -e GOPROXY=off \
  -v "$SANDBOX":/work:Z \
  -v "$MEWT":/usr/local/bin/mewt:ro,Z \
  -w /work "$IMG_GO" \
  timeout --signal=TERM --kill-after=30 "$TIMEOUT_S" \
  mewt run --test.cmd "go test ./..." "$TARGET" >"$LOG" 2>&1
RC=$?

python3 - "$LOG" "$RC" "$TARGET" "$MEWT_VERSION" <<'PY'
import json, pathlib, re, sys

log_path, rc, target, version = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
log = pathlib.Path(log_path).read_text(errors="replace")

# mewt's own output is the source of truth for counts; keep the parse narrow
# and fall back to "unparseable" rather than inventing a verdict.
survived = killed = None
for pat, name in ((r"(\d+)\s+survived", "s"), (r"(\d+)\s+killed", "k")):
    m = re.search(pat, log, re.I)
    if m:
        if name == "s":
            survived = int(m.group(1))
        else:
            killed = int(m.group(1))

# `mewt --version` already prints "mewt <semver>"; don't double the name.
tool = version if version.lower().startswith("mewt") else f"mewt {version}".strip()
item = {"kind": "mutation", "tool": tool or "mewt",
        "command": f'mewt run --test.cmd "go test ./..." {target}',
        "log_path": log_path, "deterministic_steps": "ran"}

if rc == 124 and survived is None:
    item["outcome"] = "not_attempted: campaign exceeded its timeout"
    item["deterministic_steps"] = "skipped: timeout"
elif rc != 0 and survived is None:
    item["outcome"] = f"not_attempted: mewt exited {rc} without a parseable result"
    item["deterministic_steps"] = f"skipped: mewt exited {rc}"
elif survived is None:
    item["outcome"] = "not_attempted: mewt output carried no mutant counts"
    item["deterministic_steps"] = "skipped: no parseable mutant counts"
else:
    total = (killed or 0) + survived
    item["base_observation"] = (
        f"{total} mutant(s) generated in {target}; the suite as patched is the baseline "
        "for whether each is detected"
    )
    item["patched_observation"] = f"{killed if killed is not None else 'unknown'} killed, {survived} survived"
    # A surviving mutant means the tests do not detect that change: the
    # regression test asserts nothing about it. That FAILS to prove the fix
    # is guarded, which is not the same as proving it is broken.
    item["outcome"] = "proves" if survived == 0 else "fails_to_prove"

print(json.dumps(item))
PY
