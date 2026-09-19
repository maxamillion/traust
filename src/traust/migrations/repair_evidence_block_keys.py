#!/usr/bin/env python3
"""Repair evidence blocks that use undeclared keys (2026-09-18).

`report.schema.json` `$defs/evidence_block` allows exactly `caption`, `code`
and `language`, with `additionalProperties: false`. 22 blocks across 21
reports carry `lang` and `type` instead, so those reports cannot be ingested
into storage/v1 at all — they fail validation outright.

Measured 2026-09-18 across `analysis-results/findings`:

    22 blocks, all with the identical key set ('code', 'lang', 'type')
    lang  = 'shell' (17) | 'yaml' (5)   -- and `language` is ALWAYS absent
    type  = 'poc'   (22/22)
    caption                              -- ALWAYS absent

So `lang` is a misspelling of `language`, not a duplicate: nothing is
overwritten by the rename. `type: poc` is real information with no declared
home, and `caption` is free on every one of these blocks, so it lands there
rather than being dropped.

**Historical, not a live producer bug.** Affected reports date 2026-07-15 to
2026-08-12 on harness 0.1.0-* and 0.4.2-*; the newest report in the corpus is
2026-08-17 and nothing has emitted these keys since 08-12. The blocks are
model-authored evidence from older audits. No skill emits them today, which
is why this is a one-shot repair and not a producer change.

Dry run by default. Writes only the evidence block; no finding identity,
fingerprint or disposition is touched.

    python3 -m traust.migrations.repair_evidence_block_keys <root>
    python3 -m traust.migrations.repair_evidence_block_keys <root> --write
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DECLARED = {"caption", "code", "language"}
#: `type` is not dropped -- it is folded into the caption, which is free on
#: every affected block. Keep this mapping explicit: a silent drop of
#: evidence semantics is exactly the kind of change nobody reviews.
TYPE_CAPTIONS = {"poc": "Proof of concept"}

REPORT_GLOBS = ("*-security-audit.json", "*-findings-current.json")


def repair_block(block: dict) -> list[str]:
    """Repair one evidence block in place. Returns what changed."""
    changes: list[str] = []
    if "lang" in block:
        value = block.pop("lang")
        if "language" in block:
            # Never seen in the corpus, but a rename that silently discards a
            # real value is not a repair. Leave it and report it.
            block["lang"] = value
            changes.append("lang-and-language-both-present")
        else:
            block["language"] = value
            changes.append("lang->language")
    if "type" in block:
        value = block.pop("type")
        caption = TYPE_CAPTIONS.get(value)
        if caption is None:
            block["type"] = value
            changes.append(f"unmapped-type:{value}")
        elif block.get("caption"):
            block["type"] = value
            changes.append("caption-already-set")
        else:
            block["caption"] = caption
            changes.append(f"type:{value}->caption")
    return changes


def repair_report(document: dict) -> tuple[int, list[str], set[str]]:
    """Returns (blocks repaired, change labels, keys still undeclared)."""
    repaired = 0
    labels: list[str] = []
    residue: set[str] = set()
    for finding in document.get("findings") or []:
        for block in finding.get("evidence") or []:
            if not (set(block) - DECLARED):
                continue
            changes = repair_block(block)
            if changes:
                repaired += 1
                labels.extend(changes)
            residue |= set(block) - DECLARED
    return repaired, labels, residue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write", action="store_true", help="persist the repairs")
    args = parser.parse_args(argv)

    from collections import Counter

    tally: Counter[str] = Counter()
    residue: Counter[str] = Counter()
    touched: list[tuple[Path, dict, int]] = []

    paths = sorted({p for glob in REPORT_GLOBS for p in args.root.rglob(glob)})
    for path in paths:
        if "_manifest" in path.parts:
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"skip {path}: {error}", file=sys.stderr)
            continue
        repaired, labels, left = repair_report(document)
        if not repaired:
            continue
        tally.update(labels)
        residue.update(left)
        touched.append((path, document, repaired))

    blocks = sum(n for _, _, n in touched)
    print(f"evidence repair: {blocks} block(s) in {len(touched)} report(s)")
    for label, count in tally.most_common():
        print(f"  {count:5}  {label}")
    if residue:
        print(
            f"\nstill undeclared after repair: {dict(residue)} -- these need a "
            "decision, not a rename",
            file=sys.stderr,
        )

    if not args.write:
        print("\ndry run: nothing written. Re-run with --write.")
        return 0
    for path, document, _ in touched:
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {len(touched)} report(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
