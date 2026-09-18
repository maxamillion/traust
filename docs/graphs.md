# The two portfolio graphs — what each holds, and who reads them

**As of 2026-09-18.** Node kinds, layers, outputs and the consumer lists below
were read from the skills and from the code that opens each graph, not
recalled. Every consumer named here was found by searching for the artifact
filename, and a docs-gate check keeps that list honest.

There are two graphs. They answer different questions, and the most common
mistake is reaching for the wrong one:

| | [`/repo-graph`](../harnessing/repo-graph/SKILL.md) | [`/portfolio-graph`](../harnessing/portfolio-graph/SKILL.md) |
|---|---|---|
| **Question it answers** | *which repos exist, who owns them, what has been audited* | *what the code depends on, and what a change reaches* |
| **Kind** | organizational coverage graph | code-level graph |
| **Artifact** | `analysis-results/graph/repo-graph.{json,dot,gexf,html}` + `repo-graph-stats.md` | `analysis-results/graph/portfolio-graph.db` (SQLite: `nodes`, `edges`) |
| **Built from** | the inputs inventory (segment CSVs + `owners.csv`) cross-referenced against `analysis-results/findings/` | the repo-graph spine, then the repos' own manifests and source |
| **Built by** | `harnessing/repo-graph/scripts/build_repo_graph.py` | `python3 -m traust.cli portfolio` |
| **Scale, last build** | ~10k nodes | 3.1 GB; 2.5M symbols, 84k source-packages, 23k packages, 4.9k modules, 3.5k repos |

The spine is shared: **`repo-graph.json` is the L0 layer `/portfolio-graph`
builds on.** So repo-graph is a prerequisite, not an alternative — a stale
repo-graph gives you a portfolio-graph with the wrong repo set.

## /repo-graph — coverage and ownership

Hierarchy: `segment` → `release`/`product` → `product-version` → `category` →
`repo` → `findings`, plus `owner-team` → `repo` and `repo` → `repo-ref` for
the branch-awareness layer.

Edge relations: `contains` (hierarchy), `ships` (an inventory row ships this
repo), `owned-by` (from `owners.csv`), `has-findings` (a findings directory
exists), and `has_ref` / `ships_ref` for the ref layer.

Repo nodes are coloured by max triaged severity across linked findings
directories and carry `attrs.tp_total`, `attrs.findings_dirs` and
`attrs.findings`. That is what makes it the coverage answer: *which repos have
no audit at all* is a query over these nodes.

## /portfolio-graph — the code-level layers

| Layer | Holds |
|---|---|
| **L0** | the repo-graph spine |
| **L1** | module dependencies — Go (`go.mod`) plus npm, PyPI, Maven, Cargo, RubyGems, NuGet |
| **L2** | Kubernetes interfaces (CRDs, API groups) |
| **L3** | artifacts / SBOM, built during a shallow clone→extract→delete sweep and cached per repo |
| **L4** | symbols, via tree-sitter extraction |

All four are implemented. L1's non-Go half (`deps-multi`) is tree-driven and
resumable from a disk cache, which matters because a full rebuild is not cheap.

This is the graph behind blast-radius questions: *which products depend on
module X*, *what does this CVE reach*, *top shared libraries*, *internal
library coupling*.

## Who reads them

Both lists come from searching for the artifact filename across the tree. A
skill or script appears here because it opens the graph, not because it
mentions it.

### `portfolio-graph.db`

| Consumer | Uses it for |
|---|---|
| `/impact-analysis` | blast radius for an advisory, before per-language reachability |
| `/pqc-readiness` | product rollups, vendor tracker, crypto-dependency scans (5 scripts) |
| `/isolation-review` | resolving a service's repo set |
| `/fleet-fix` | selecting every repo affected by one systemic pattern |
| `/dependency-watch` | `fleet_sweep.py`, matching new advisories against the fleet |
| `/drift-watch` | staleness: graph built before the inventory HEAD moved |
| `/refresh-dashboards` | `build_dependency_exposure.py` |
| `cli/build_rescan_worklist.py` | rescan routing |
| `ops/build_crown_jewel_tiers.py` | tiering |

### `repo-graph.json`

| Consumer | Uses it for |
|---|---|
| `/census` | the report population, and `check_repo_liveness.py` |
| `/portfolio-graph` | its L0 spine |
| `/secure-code-audit` | `enrich_findings_cves.py` |
| `/fleet-fix` | `fleet_targets.py` (reads both graphs) |
| `/drift-watch` | staleness vs the inputs inventory |
| `ops/build_crown_jewel_tiers.py`, `migrations/resolve_docs_version_refs.py` | tiering, doc-version resolution |

## Freshness, and what goes wrong when they are stale

`/drift-watch` watches both: it reports `stale` when a graph was built before
the inputs inventory's HEAD moved, because inventory or ownership may have
changed underneath it. Neither graph is rebuilt automatically — drift routes
attention, and a human decides.

Staleness is not cosmetic, and the failure mode differs by graph:

- **A stale repo-graph** misstates coverage and ownership. Findings routed
  from it go to the wrong team, and "repos with no audit" omits repos added
  since the build.
- **A stale portfolio-graph** understates blast radius. An advisory sweep
  against an old dependency layer reports fewer affected repos than exist,
  which reads as good news.

Both are derived artifacts and both are rebuildable; neither is a system of
record. When a number from a graph disagrees with a number from `/census`,
the census is the denominator authority
([census SKILL](../harnessing/census/SKILL.md)).
