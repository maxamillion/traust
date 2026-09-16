#!/usr/bin/env python3
"""Turn a mewt campaign's result into one `patch_evidence` item.

Reads `mewt status --format json` rather than the campaign banner. The banner
is prose: mewt 4.0.0 prints "Caught / Uncaught / Skipped", and an earlier
version of this tool guessed "killed / survived" and would have produced no
verdict on every real run. `status --format json` is a declared interface with
per-target rows, so the verdict is derived from data rather than scraped.

Emits to stdout a single object matching
remediation.schema.json#/$defs/patch_evidence (kind: mutation). The schema, not
this script, is the authority on shape — it refuses a claim of proof that does
not carry both observations.

Verdict rules, and why they are strict:

- any uncaught or timed-out mutant  -> fails_to_prove
- every generated mutant exercised and caught -> proves
- nothing escaped but some mutants were never exercised -> fails_to_prove

That last rule matters. mewt deliberately skips less severe mutants on a line
whose more severe mutant went uncaught, so a campaign can finish with zero
uncaught mutants while leaving many untested. Reporting that as proof would
overclaim the very thing this evidence kind exists to establish.

Mutants generated inside `_test.go` files are excluded from the claim: a
surviving mutant in a test file says the test's own assertions are dead, which
is interesting but a different question from whether the suite detects changes
to the patched code. Their count is reported alongside instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KIND = "mutation"
TEST_SUFFIX = "_test.go"


def _tool_label(version: str) -> str:
    """`mewt --version` already prints "mewt <semver>"; don't double the name."""
    v = (version or "").strip()
    if not v:
        return "mewt"
    return v if v.lower().startswith("mewt") else f"mewt {v}"


def _not_attempted(item: dict, reason: str, step: str | None = None) -> dict:
    item["outcome"] = f"not_attempted: {reason}"
    item["deterministic_steps"] = f"skipped: {step or reason}"
    return item


def _total(rows: list[dict], key: str) -> int:
    return sum(int(r.get(key) or 0) for r in rows)


def build_item(
    *,
    target: str,
    rc: int,
    tool_version: str,
    log_path: str,
    status_text: str | None,
    boundary: str = "",
) -> dict:
    # The boundary belongs in the artifact: a verdict produced under nested
    # podman and one produced under a platform-attested sandbox are not
    # equally strong, and a reader cannot otherwise tell them apart.
    cmd = f'mewt run --test.cmd "go test ./..." {target}'
    if boundary:
        cmd += f"  [boundary: {boundary}]"
    item = {
        "kind": KIND,
        "tool": _tool_label(tool_version),
        "command": cmd,
        "log_path": log_path,
        "deterministic_steps": "ran",
    }

    # `timeout` exits 124 when it had to kill the campaign.
    if rc == 124:
        return _not_attempted(item, "campaign exceeded its timeout", "timeout")

    if not status_text:
        reason = (
            f"mewt exited {rc} and produced no readable status json"
            if rc
            else "mewt produced no readable status json"
        )
        return _not_attempted(item, reason)
    try:
        status = json.loads(status_text)
    except json.JSONDecodeError:
        return _not_attempted(item, "mewt status json was unparseable")

    rows = status.get("targets") or []
    src = [r for r in rows if not str(r.get("path", "")).endswith(TEST_SUFFIX)]
    tests = [r for r in rows if str(r.get("path", "")).endswith(TEST_SUFFIX)]
    if not src:
        return _not_attempted(item, f"mewt generated no mutants for {target}")

    generated = _total(src, "total_mutants")
    if generated == 0:
        return _not_attempted(item, f"mewt generated no mutants for {target}")

    tested = _total(src, "tested")
    caught = _total(src, "caught")
    uncaught = _total(src, "uncaught")
    skipped = _total(src, "skipped")
    untested = _total(src, "untested")
    timed_out = _total(src, "timeout")
    unexercised = skipped + untested

    item["base_observation"] = (
        f"{generated} mutant(s) generated across {len(src)} non-test file(s) in "
        f"{target}; {tested} exercised against the suite as patched"
        + (f"; {len(tests)} test-file target(s) excluded from the claim" if tests else "")
    )
    item["patched_observation"] = (
        f"{caught} caught, {uncaught} uncaught, {timed_out} timed out, "
        f"{unexercised} never exercised (skipped {skipped}, untested {untested})"
    )

    if uncaught or timed_out:
        item["outcome"] = "fails_to_prove"
    elif unexercised:
        item["outcome"] = "fails_to_prove"
        item["patched_observation"] += " — nothing escaped, but not every mutant was run"
    elif tested and caught == generated:
        item["outcome"] = "proves"
    else:
        return _not_attempted(item, "mewt status did not account for every generated mutant")
    return item


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log", required=True, help="campaign log path (recorded, not parsed)")
    ap.add_argument("--rc", type=int, required=True, help="exit code of the campaign")
    ap.add_argument("--target", required=True)
    ap.add_argument("--tool-version", default="")
    ap.add_argument("--status-json", required=True, help="output of `mewt status --format json`")
    ap.add_argument(
        "--boundary",
        default="",
        help="execution boundary the campaign ran under (podman | attested:<label>), "
        "recorded in the evidence so a reader can weigh it",
    )
    args = ap.parse_args(argv)

    try:
        status_text = Path(args.status_json).read_text(encoding="utf-8")
    except OSError:
        status_text = None

    item = build_item(
        target=args.target,
        rc=args.rc,
        tool_version=args.tool_version,
        log_path=args.log,
        status_text=status_text,
        boundary=args.boundary,
    )
    print(json.dumps(item))
    return 0


if __name__ == "__main__":
    sys.exit(main())
