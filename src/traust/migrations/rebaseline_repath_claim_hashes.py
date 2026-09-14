#!/usr/bin/env python3
# Migration utility written 2026-09-11
"""Re-baseline claim hashes invalidated by the item-4b `locations` re-path.

`repath_repo_root_findings.py` rewrote placeholder `locations` entries
(`path: "."`) to concrete files. `locations` is one of the seven CLAIM_FIELDS,
so every finding it touched has a `metadata.claim_hashes` entry that no longer
matches its report — indistinguishable, to `baseline_claims.py verify`, from a
finding edited behind the ledger's back. That migration had no claim-hash
handling, so the baselines were never re-pinned. This does it.

`baseline_claims.py record --rebaseline` deliberately refuses anything not
marked `validation_status: corrected`, and these findings were not corrected —
their claims are unchanged in substance, only re-pathed. Marking them
`corrected` to satisfy that gate would put a false statement in the report, so
the re-baseline happens here, behind a predicate narrow enough to be audited.

**A hash is re-pinned only when all four hold**, checked per finding:

1. The recorded hash reproduces exactly at `--pinned-rev` (default
   b705703dd1, where the baselines were taken). This proves the baseline was
   sound and that we are reading the right historical claim.
2. `locations` is the ONLY CLAIM_FIELD that differs between that revision and
   the report now.
3. Every `locations` entry that changed moved *away from* a placeholder path
   (`.` or empty) — the re-path's shape. A concrete path changing to another
   concrete path is not this migration's business.
4. The finding still exists in the report under the same id.

Anything failing a check is counted and reported, never written. A finding
whose `title`, `severity`, `cwes`, `description` or `remediation` moved is
exactly the case tamper-evidence exists to catch, and it is left flagged.

`claim_hashes` is covered by the signature payload (format 2+) but not by the
Merkle root, which hashes events only. So a re-pinned layer needs re-signing
and no root moves. A layer that arrives signed must leave signed: without a
usable signing identity it is restored and reported, never written unsigned.

    python3 -m traust.migrations.rebaseline_repath_claim_hashes <results-root> \\
        [--apply] [--pinned-rev SHA] [--pubkey PATH] [--limit N]
"""

from __future__ import annotations

import argparse
import json
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

# Where the claim hashes were pinned. Overridable, because a later corpus may
# have been baselined elsewhere and this must never be guessed silently.
DEFAULT_PINNED_REV = "b705703dd1"

# The re-path's "before" shape. A location on one of these is a placeholder
# standing in for "somewhere in this repo", not a real claim about a file.
# '/' is in the set for the same reason as '.': the pre-re-path corpus used
# both spellings for repo-root, and 328 of the affected claims use '/'.
PLACEHOLDER_PATHS = {".", "", "./", "/"}


class WriteRefused(Exception):
    """The layer was restored rather than written. Carries (reason, detail)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def _locations_only_repath(old: dict, new: dict) -> tuple[bool, str]:
    """True when `locations` is the sole claim difference and it is a re-path.

    Returns (ok, why_not) so the caller can report the precise reason.
    """
    moved = [k for k in CLAIM_FIELDS if old.get(k) != new.get(k)]
    if moved != ["locations"]:
        other = [k for k in moved if k != "locations"]
        return False, f"non-locations claim field(s) changed: {', '.join(other) or 'none'}"

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
        # Everything other than the path must be untouched.
        rest_before = {k: v for k, v in before.items() if k != "path"}
        rest_after = {k: v for k, v in after.items() if k != "path"}
        if rest_before != rest_after:
            return False, "a locations field other than `path` changed"
    return True, ""


class ClaimRebaseline:
    def __init__(
        self,
        engine,
        results_root: Path,
        *,
        apply: bool = False,
        limit: int | None = None,
        pinned_rev: str = DEFAULT_PINNED_REV,
        pubkey: Path | None = None,
    ) -> None:
        self.engine = engine
        self.results_root = results_root
        self.apply = apply
        self.limit = limit
        self.pinned_rev = pinned_rev
        self.pubkey = pubkey
        self.tally: Counter[str] = Counter()
        self.problems: list[str] = []
        self._started = 0.0
        self._pinned_cache: dict[str, dict | None] = {}

    # -- git ---------------------------------------------------------------

    def _pinned_findings(self, report: Path) -> dict | None:
        """The report's findings at --pinned-rev, keyed by id (None if absent)."""
        rel = str(report.relative_to(self.results_root))
        if rel in self._pinned_cache:
            return self._pinned_cache[rel]
        proc = subprocess.run(
            ["git", "-C", str(self.results_root), "show", f"{self.pinned_rev}:{rel}"],
            capture_output=True,
        )
        result: dict | None = None
        if proc.returncode == 0:
            try:
                doc = json.loads(proc.stdout)
                result = {f.get("id"): f for f in doc.get("findings", []) if isinstance(f, dict)}
            except (json.JSONDecodeError, AttributeError):
                result = None
        self._pinned_cache[rel] = result
        return result

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

        pinned = self._pinned_findings(report)
        if pinned is None:
            self.tally["report absent at pinned rev — skipped"] += len(drifted)
            self.problems.append(f"{path.name}: not present at {self.pinned_rev}")
            return

        eligible: dict[str, str] = {}
        for fid, recorded in sorted(drifted.items()):
            old = pinned.get(fid)
            if old is None:
                self.tally["finding absent at pinned rev — skipped"] += 1
                continue
            if compute_claim_hash(old) != recorded:
                self.tally["hash does not reproduce at pinned rev — skipped"] += 1
                self.problems.append(f"{path.name}:{fid}: baseline not reproducible")
                continue
            ok, why = _locations_only_repath(old, findings[fid])
            if not ok:
                self.tally["not a locations re-path — LEFT FLAGGED"] += 1
                self.problems.append(f"{path.name}:{fid}: {why}")
                continue
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
        print(f"{mode} · {scanned:,} layer files · pinned at {self.pinned_rev} · {elapsed:.0f}s")
        for name, count in self.tally.most_common():
            print(f"  {name:48} {count:,}")
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
        "--pinned-rev",
        default=DEFAULT_PINNED_REV,
        help=f"revision the claim hashes were pinned at (default: {DEFAULT_PINNED_REV})",
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
        pinned_rev=args.pinned_rev,
        pubkey=args.pubkey,
    ).run()


if __name__ == "__main__":
    sys.exit(main())
