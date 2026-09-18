# Graphs — every graph the harness builds or reads

Six graph-shaped artifacts, built by different skills for different questions.
Reaching for the wrong one is the usual mistake, so each entry below states the
question it answers and who consumes it.

Sizes and node counts depend entirely on your inventory. `repo-graph-stats.md`
and `portfolio-graph-summary.json` report yours after a build.

| Graph | Artifact | Question it answers | Built by |
|---|---|---|---|
| **repo-graph** | `repo-graph.{json,dot,gexf,html}` + `repo-graph-stats.md` | which repos exist, who owns them, what has been audited | [`/repo-graph`](../harnessing/repo-graph/SKILL.md) |
| **portfolio-graph** | `portfolio-graph.db` (SQLite) + `portfolio-graph-summary.json` | what the code depends on, and what a change reaches | [`/portfolio-graph`](../harnessing/portfolio-graph/SKILL.md) |
| **findings projection** | `findings.db` (SQLite) | ad-hoc queries over the findings corpus | [`/findings-db`](../harnessing/findings-db/SKILL.md) |
| **ATT&CK coverage layer** | `attack-navigator-layer.json` (Navigator format 4.5) | which adversary techniques the portfolio's findings and validated chains cover | [`/attack-coverage`](../harnessing/attack-coverage/SKILL.md) |
| **attack chains** | `attack_chains[]` inside validation reports | how a confirmed finding chains from entry point to terminal asset | [`/validate-findings`](../harnessing/5-validate/validate-findings/SKILL.md) |
| **reachability call graphs** | transient, per-run adapter output | is the vulnerable symbol actually reachable in this module | `adapters govulncheck` / `adapters joern` |

Graph artifacts land in `analysis-results/graph/` under the configured
`analysis-results` root — except the call graphs, which are per-run and never
persisted, and attack chains, which live inside the validation reports that
produce them.

Every one is a **derived artifact**, not a system of record. All are
rebuildable, and when a number from a graph disagrees with `/census`, the
census is the denominator authority
([census SKILL](../harnessing/census/SKILL.md)).

---

## repo-graph — coverage and ownership

Built from the inputs inventory (segment CSVs + `owners.csv`) cross-referenced
against the findings tree.

Hierarchy: `segment` → `release`/`product` → `product-version` → `category` →
`repo` → `findings`, plus `owner-team` → `repo` and `repo` → `repo-ref` for
the branch-awareness layer.

Edges: `contains` (hierarchy), `ships` (an inventory row ships this repo),
`owned-by` (from `owners.csv`), `has-findings` (a findings directory exists),
and `has_ref` / `ships_ref` for the ref layer.

Repo nodes are coloured by max triaged severity across linked findings
directories and carry `attrs.tp_total`, `attrs.findings_dirs` and
`attrs.findings`. That is what makes it the coverage answer: *which repos have
no audit at all* is a query over these nodes.

Four outputs for four audiences: `.json` is canonical and machine-readable,
`.dot` for GraphViz, `.gexf` for Gephi, `.html` a self-contained pan/zoom page.

**Read by:** `/census` (report population, and repo liveness),
`/portfolio-graph` (as its L0 spine), `/secure-code-audit` (CVE enrichment),
`/fleet-fix` (target selection), `/drift-watch` (staleness), plus
`ops/build_crown_jewel_tiers` (tiering) and
`migrations/resolve_docs_version_refs` (doc-version resolution).

## portfolio-graph — the code-level layers

| Layer | Holds |
|---|---|
| **L0** | the repo-graph spine |
| **L1** | module dependencies — Go (`go.mod`) plus npm, PyPI, Maven, Cargo, RubyGems, NuGet |
| **L2** | Kubernetes interfaces (CRDs, API groups) |
| **L3** | artifacts / SBOM, built during a shallow clone→extract→delete sweep, cached per repo |
| **L4** | symbols, via tree-sitter extraction |

All four are implemented. L1's non-Go half (`deps-multi`) is tree-driven and
resumable from a disk cache, which matters because a full rebuild is not cheap.

**`repo-graph.json` is the L0 layer this builds on**, so repo-graph is a
prerequisite rather than an alternative — a stale spine yields a
portfolio-graph over the wrong repo set.

This is the graph behind blast-radius questions: *which products depend on
module X*, *what does this CVE reach*, *top shared libraries*, *internal
library coupling*.

**Read by:** `/impact-analysis` (advisory blast radius, before per-language
reachability), `/pqc-readiness` (product rollups, vendor tracker,
crypto-dependency scans), `/isolation-review` (resolving a service's repo
set), `/fleet-fix` (every repo affected by one systemic pattern),
`/dependency-watch` (fleet advisory sweep), `/refresh-dashboards` (dependency
exposure), `/drift-watch` (staleness), plus `cli/build_rescan_worklist`
(rescan routing) and `ops/build_crown_jewel_tiers` (tiering).

## findings.db — the findings projection

A SQLite projection of the findings corpus, so a leadership question becomes a
query rather than a walk over thousands of JSON files. Not a graph in the
node/edge sense, but it sits beside the others in `analysis-results/graph/`
and is what to reach for when the question is about findings rather than about
repos or code.

A projection, never an authority: the disposition ledgers remain the source of
truth.

## attack-navigator-layer.json — ATT&CK coverage

Joins three sources into one Navigator layer, scored by evidence strength:
**observed** (3) from confirmed `attack_chains[].mitre_attack_refs` in
validation reports, **modeled** (2) from threat-model `attack_refs`, and
**derived** (1) from finding categories.

The scoring is the point: a technique covered only by category inference is
not the same claim as one demonstrated against a live target.

## attack_chains[] — per-finding attack paths

Not a standalone file. Each validation report carries `attack_chains[]` with
`chain_id`, `name`, `entry_point`, `terminal_asset`, `mitre_attack_refs[]`,
`steps[]` and a `verdict`. This is the graph that says *how* an attacker gets
from an entry point to an asset, and it is the input the ATT&CK layer scores
as "observed".

## Reachability call graphs — transient

`adapters govulncheck` (Go) and `adapters joern` (Java/C) build call graphs to
decide whether a vulnerable symbol is reachable, then emit candidates rather
than the graph. Nothing is persisted: the graph exists for the run, and what
survives is a reachability classification on each candidate.

These are analysis steps, not artifacts — there is nothing to refresh or query
later.

---

## Freshness

`/drift-watch` watches repo-graph and portfolio-graph, reporting `stale` when
a graph predates the inputs inventory's HEAD, because inventory or ownership
may have changed underneath it. Neither is rebuilt automatically — drift
routes attention and a human decides.

Staleness costs differ by graph, and one of them is dangerous:

- **A stale repo-graph** misstates coverage and ownership. Findings route to
  the wrong team, and "repos with no audit" omits repos added since the build.
- **A stale portfolio-graph** *understates* blast radius. An advisory sweep
  against an old dependency layer reports fewer affected repos than exist,
  which reads as good news.
