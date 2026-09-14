#!/usr/bin/env python3
# Migration utility written 2026-09-11; widened 2026-09-14
"""Re-baseline claim hashes invalidated by sanctioned corpus-wide passes.

Two migrations rewrote CLAIM_FIELDS without re-pinning
`metadata.claim_hashes`, so the findings they touched read as tampered to
`baseline_claims.py verify`:

- **item-4b re-path.** `repath_repo_root_findings.py` rewrote placeholder
  `locations` (`path: "."` or `"/"`) to concrete files. It has no claim-hash
  handling at all — that is the gap.
- **Marker-documented triage repairs, 2026-07-21.** Two passes corrected
  `severity` and appended a self-documenting marker to `description` rather
  than editing silently: CVSS RECONCILIATION (score corrected to match the
  finding's own vector) and DATA REPAIR (severity mis-emitted as
  'informational' despite a high CVSS, a legacy-report emission bug).

`baseline_claims.py record --rebaseline` deliberately refuses anything not
marked `validation_status: corrected`, and neither class was — their claims
are unchanged in substance. Marking them `corrected` to pass that gate would
put a false statement in the report, so the re-baseline lives here behind
predicates narrow enough to be audited.

**Finding the baseline.** A hash is only trustworthy if it reproduces against
the report revision it was taken from, and that revision differs per report:
the corpus was baselined across many passes (orphan-backfill batches, re-audit
batches, identity re-stamps), not one. So this walks each report's own git
history until the recorded hash reproduces, rather than assuming a single
global revision. A hash that reproduces nowhere in history is left flagged —
that is the shape of a claim edited outside any sanctioned pass.

**A hash is re-pinned only when all of these hold**, checked per finding:

1. The recorded hash reproduces exactly at some revision of that report.
2. The finding still exists under the same id.
3. The drift from that revision matches exactly one sanctioned predicate:
   - `locations` is the only claim field that moved, every changed entry moved
     off a repo-root placeholder, and nothing but `path` changed within it; or
   - `description` gained only a sanctioned triage marker as a suffix, and
     `severity` is the only other field that moved.

Anything else is counted and reported, never written. A finding whose `title`,
`cwes` or `remediation` moved, or whose `description` changed in any other
way, is exactly what tamper-evidence exists to catch.

`claim_hashes` is covered by the signature payload (format 2+) but not by the
Merkle root, which hashes events only. So a re-pinned layer needs re-signing
and no root moves. A layer that arrives signed must leave signed: without a
usable signing identity it is restored and reported, never written unsigned.

    python3 -m traust.migrations.rebaseline_claim_hashes <results-root> \\
        [--apply] [--pubkey PATH] [--limit N] [--max-revs N]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from traust_engine.ledger import LedgerError, verify_merkle_signature
from traust_ledger._internal.events._core import CLAIM_FIELDS, compute_claim_hash

from traust.context import add_config_home_arg, analysis_results_dir, load_engine

LAYER_SUFFIX = "-findings-layer.json"
REPORT_SUFFIX = "-security-audit.json"
STATE_DIRS = {".triage-state", ".threat-model-state", ".claude", ".tmp"}
PROGRESS_EVERY = 100

# The re-path's "before" shape. A location on one of these is a placeholder
# standing in for "somewhere in this repo", not a real claim about a file.
# '/' is in the set for the same reason as '.': the pre-re-path corpus used
# both spellings for repo-root.
PLACEHOLDER_PATHS = {".", "", "./", "/"}

# The 2026-07-21 triage passes each appended a self-documenting marker rather
# than editing silently. Two wordings, one shape: a bracketed suffix naming the
# pass and its date.
#
#   [CVSS RECONCILIATION 2026-07-21: score corrected from 3.1 to 4.5 …]
#   [DATA REPAIR 2026-07-21: severity field was mis-emitted as 'informational'
#    despite CVSS 8.3 (legacy-report emission bug); corrected to 'high' …]
#
# Matched by locating the marker's opening rather than with a regex over its
# body: the body contains brackets and quotes, and a permissive pattern would
# let an unrelated edit ride along inside it.
#   [SEVERITY CORRECTION 2026-07-21: 'informational' -> 'medium' — …]
#
# An explicit allowlist rather than a pattern like r"\[[A-Z ]+ \d{4}-…": the
# point of the control is that a human sanctioned each named pass, and any
# appended bracket would satisfy a generic shape.
MARKER_PREFIXES = (
    "[CVSS RECONCILIATION ",
    "[DATA REPAIR ",
    "[SEVERITY CORRECTION ",
)
MARKER_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _split_marker(text: str) -> tuple[str, str] | None:
    """Split `text` into (body, marker) if it ends with a sanctioned marker."""
    cut = max((text.rfind(p), p) for p in MARKER_PREFIXES)
    index, prefix = cut
    if index < 0:
        return None
    marker = text[index:]
    if not marker.rstrip().endswith("]"):
        return None
    if not MARKER_DATE.match(marker[len(prefix) :]):
        return None
    return text[:index].rstrip(), marker

# How far back to walk a single report's history before giving up. Generous:
# the deepest report in the corpus has well under this many revisions.
DEFAULT_MAX_REVS = 40


class WriteRefused(Exception):
    """The layer was restored rather than written. Carries (reason, detail)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def _locations_only_repath(old: dict, new: dict) -> tuple[bool, str]:
    """True when `locations` is the sole claim difference and it is a re-path."""
    moved = [k for k in CLAIM_FIELDS if old.get(k) != new.get(k)]
    if moved != ["locations"]:
        return False, ""

    old_locs = old.get("locations") or []
    new_locs = new.get("locations") or []
    if not isinstance(old_locs, list) or not isinstance(new_locs, list):
        return False, "locations is not a list"
    if len(old_locs) != len(new_locs):
        return False, f"locations count changed {len(old_locs)} -> {len(new_locs)}"

    for before, after in zip(old_locs, new_locs):
        if not isinstance(before, dict) or not isinstance(after, dict):
            return False, "locations entry is not an object"
        if before == after:
            continue
        if str(before.get("path", "")).strip() not in PLACEHOLDER_PATHS:
            return False, f"path {before.get('path')!r} was not a placeholder"
        if {k: v for k, v in before.items() if k != "path"} != {
            k: v for k, v in after.items() if k != "path"
        }:
            return False, "a locations field other than `path` changed"
    return True, ""


def _marked_triage_repair(old: dict, new: dict) -> tuple[bool, str]:
    """True when the only drift is a marker-documented 2026-07-21 triage pass.

    `description` must be the old text plus the marker as a suffix — nothing
    else may differ inside it — and `severity` is the only other field allowed
    to move, because correcting it is what those passes existed to do. The
    marker states the old and new values, so the change carries its own
    justification in the report.
    """
    moved = {k for k in CLAIM_FIELDS if old.get(k) != new.get(k)}
    if not moved or not moved <= {"description", "severity"}:
        return False, ""
    if "description" not in moved:
        # severity alone carries no evidence of why it moved.
        return False, "severity changed with no explanatory marker"

    before, after = old.get("description"), new.get("description")
    if not isinstance(before, str) or not isinstance(after, str):
        return False, "description is not a string"
    split = _split_marker(after)
    if split is None:
        return False, "description changed without an explanatory marker"
    body, _marker = split
    if body != (before or "").rstrip():
        return False, "description changed beyond appending the marker"
    return True, ""


PREDICATES = (
    ("locations re-path", _locations_only_repath),
    ("marked triage repair", _marked_triage_repair),
)


class ClaimRebaseline:
    def __init__(
        self,
        engine,
        results_root: Path,
        *,
        apply: bool = False,
        limit: int | None = None,
        max_revs: int = DEFAULT_MAX_REVS,
        pubkey: Path | None = None,
    ) -> None:
        self.engine = engine
        self.results_root = results_root
        self.apply = apply
        self.limit = limit
        self.max_revs = max_revs
        self.pubkey = pubkey
        self.tally: Counter[str] = Counter()
        self.problems: list[str] = []
        self._started = 0.0

    # -- git ---------------------------------------------------------------

    def _revisions(self, rel: str) -> list[str]:
        proc = subprocess.run(
            ["git", "-C", str(self.results_root), "log", "--format=%H", "--", rel],
            capture_output=True,
            text=True,
        )
        return proc.stdout.split()[: self.max_revs]

    def _findings_at(self, rel: str, rev: str) -> dict | None:
        proc = subprocess.run(
            ["git", "-C", str(self.results_root), "show", f"{rev}:{rel}"],
            capture_output=True,
        )
        if proc.returncode != 0:
            return None
        try:
            doc = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None
        return {f.get("id"): f for f in doc.get("findings", []) if isinstance(f, dict)}

    def _baseline_for(
        self, rel: str, revs: list[str], cache: dict[str, dict | None], fid: str, recorded: str
    ) -> dict | None:
        """The finding as of the revision whose hash matches `recorded`."""
        for rev in revs:
            if rev not in cache:
                cache[rev] = self._findings_at(rel, rev)
            at = cache[rev]
            if not at:
                continue
            old = at.get(fid)
            if old is not None and compute_claim_hash(old) == recorded:
                return old
        return None

    # -- walk --------------------------------------------------------------

    def run(self) -> int:
        self._started = time.monotonic()
        layers = sorted(self.results_root.rglob(f"*{LAYER_SUFFIX}"))
        for path in layers:
            if self.limit and self.tally["layers re-baselined"] >= self.limit:
                break
            self._process(path)
        self._report(len(layers))
        return 1 if self.problems else 0

    def _process(self, path: Path) -> None:
        if STATE_DIRS.intersection(path.relative_to(self.results_root).parts):
            return
        report = path.with_name(path.name[: -len(LAYER_SUFFIX)] + REPORT_SUFFIX)
        if not report.exists():
            return
        try:
            layer = json.loads(path.read_text(encoding="utf-8"))
            audit = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.tally["unreadable"] += 1
            return

        hashes = (layer.get("metadata") or {}).get("claim_hashes") or {}
        if not hashes:
            return
        findings = {f.get("id"): f for f in audit.get("findings", []) if isinstance(f, dict)}

        drifted = {
            fid: rec
            for fid, rec in hashes.items()
            if fid in findings and compute_claim_hash(findings[fid]) != rec
        }
        if not drifted:
            return
        self.tally["layers with drift"] += 1

        rel = str(report.relative_to(self.results_root))
        revs = self._revisions(rel)
        cache: dict[str, dict | None] = {}

        eligible: dict[str, str] = {}
        for fid, recorded in sorted(drifted.items()):
            old = self._baseline_for(rel, revs, cache, fid, recorded)
            if old is None:
                self.tally["baseline reproduces at NO revision — LEFT FLAGGED"] += 1
                self.problems.append(f"{path.name}:{fid}: no revision reproduces the hash")
                continue

            matched, why = None, ""
            for name, predicate in PREDICATES:
                ok, reason = predicate(old, findings[fid])
                if ok:
                    matched = name
                    break
                why = why or reason
            if matched is None:
                moved = [k for k in CLAIM_FIELDS if old.get(k) != findings[fid].get(k)]
                self.tally["no sanctioned predicate — LEFT FLAGGED"] += 1
                self.problems.append(
                    f"{path.name}:{fid}: {why or 'changed: ' + ', '.join(moved)}"
                )
                continue

            self.tally[f"matched: {matched}"] += 1
            eligible[fid] = compute_claim_hash(findings[fid])

        if not eligible:
            return
        self.tally["claims re-baselined"] += len(eligible)
        self.tally["layers re-baselined"] += 1
        if not self.apply:
            return

        try:
            self._persist(path, layer, eligible)
        except WriteRefused as refused:
            self.tally[refused.reason] += 1
            self.problems.append(f"{path.name}: {refused.detail}")
            return
        self.tally["layers written"] += 1
        self._progress()

    # -- write -------------------------------------------------------------

    def _persist(self, path: Path, layer: dict, eligible: dict[str, str]) -> None:
        """Re-pin the eligible hashes, re-sign — or restore and raise."""
        original = path.read_bytes()
        was_signed = bool((layer.get("metadata") or {}).get("merkle_root_signature"))

        layer.setdefault("metadata", {}).setdefault("claim_hashes", {}).update(eligible)

        service = self.engine.ledger.service(data_dir=path.parent)
        service.store_layer(path, layer)
        try:
            service.sign(path)
        except LedgerError as exc:
            path.write_bytes(original)
            raise WriteRefused("sign failed — NOT written", str(exc)) from None

        fresh = service.read_layer_file(path)
        if was_signed and not (fresh.get("metadata") or {}).get("merkle_root_signature"):
            path.write_bytes(original)
            raise WriteRefused(
                "signature LOST during re-sign — NOT written",
                "signed on entry, unsigned after sign(); is LAAS_SIGNING_KEY_PATH "
                "readable and COSIGN_PASSWORD set?",
            )
        if self.pubkey:
            errors = [
                f
                for f in verify_merkle_signature(fresh, str(self.pubkey))
                if f.severity.name == "ERROR"
            ]
            if errors:
                path.write_bytes(original)
                raise WriteRefused(
                    "fresh signature failed to verify — NOT written", errors[0].message[:90]
                )

    def _progress(self) -> None:
        written = self.tally["layers written"]
        if written % PROGRESS_EVERY:
            return
        rate = written / max(time.monotonic() - self._started, 1e-9)
        print(f"  … {written} written ({rate:.1f}/s)", flush=True)

    def _report(self, scanned: int) -> None:
        mode = "APPLY" if self.apply else "DRY RUN"
        elapsed = time.monotonic() - self._started
        print(f"{mode} · {scanned:,} layer files · {elapsed:.0f}s")
        for name, count in self.tally.most_common():
            print(f"  {name:52} {count:,}")
        for problem in self.problems[:20]:
            print(f"    ! {problem}")
        if len(self.problems) > 20:
            print(f"    … {len(self.problems) - 20} more")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    add_config_home_arg(parser)
    parser.add_argument("results_root", type=Path, nargs="?", default=None)
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    parser.add_argument("--limit", type=int, default=None, help="stop after N layers")
    parser.add_argument(
        "--max-revs",
        type=int,
        default=DEFAULT_MAX_REVS,
        help=f"revisions of a report to search for its baseline (default: {DEFAULT_MAX_REVS})",
    )
    parser.add_argument(
        "--pubkey", type=Path, default=None, help="verify each fresh signature before writing"
    )
    args = parser.parse_args(argv)

    engine = load_engine(args.config_home)
    return ClaimRebaseline(
        engine,
        (args.results_root or analysis_results_dir(engine)).resolve(),
        apply=args.apply,
        limit=args.limit,
        max_revs=args.max_revs,
        pubkey=args.pubkey,
    ).run()


if __name__ == "__main__":
    sys.exit(main())
