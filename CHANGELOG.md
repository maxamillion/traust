# Changelog

All notable changes to Traust are documented here.

## [0.2.4]

- **The execution boundary is a config setting, not an invented env var.**
  0.2.3 added `TRAUST_SANDBOXED_RUNNER`, a variable nothing on the platform
  exports — a convention only this repo knew about, so the path it guarded
  would never have fired. Replaced by `sandbox:` in
  `$TRAUST_CONFIG_HOME/execution-boundaries.yaml`, with a template in
  `config/` seeded by `install_traust`.

  `sandbox: none` is the default: direct execution with a scrubbed
  environment, on a disposable copy rather than the worktree the diff comes
  from. `sandbox: podman` opts into a nested rootless container and is never
  silently downgraded — with no working runtime the lane reports
  `not_attempted`. Detection stays `podman info` rather than
  `command -v podman`.

  Verified on both lanes in both modes: default runs and returns `proves`
  (mutation 19/19; property failed-then-passed), a configured `podman` with no
  runtime refuses with that reason, and an invalid value falls back to the
  documented default. Documented in setup.md, config/README.md,
  external-dependencies.md and the orchestrator prerequisites.

## [0.2.3]

- **The evidence lanes no longer hard-require podman.** `run_mutation.sh` and
  `run_property.sh` accept either nested podman or a platform-attested
  sandbox, declared by the orchestrator as
  `TRAUST_SANDBOXED_RUNNER=<runner-label>`. On a central runner whose image
  carries the toolchain but cannot nest containers, both lanes would otherwise
  have returned `not_attempted` on every run, permanently.

  Still no *unattested* fallback: with neither boundary the lanes emit
  `not_attempted` rather than running target code in the open. The env var is
  a declaration of deployment fact, not a security control — its only job is
  to stop podman's absence from being read as permission.

- **Boundary detection uses `podman info`, not `command -v podman`.** The
  client binary is present on a host whose VM is stopped and in images that
  ship the CLI with no runtime; choosing podman there failed every run with
  exit 125 — the exact failure the change was meant to prevent. Caught by
  running it with the VM deliberately stopped.

- The resolved boundary is recorded in each evidence item's `command`, since a
  verdict from nested podman and one from an attested sandbox are not equally
  strong. `docs/external-dependencies.md` gains the boundary contract and
  names the new podman consumers; `docs/continuous-operations.md` gains the
  orchestrator prerequisite row.

## [0.2.2]

- Pin traust-contracts v0.4.0 / traust-engine v0.2.3 / traust-ledger v0.2.2,
  so a *verification* report can carry the typed patch-evidence block.
- **`/verify-remediation` gains its one executed claim** (ToB plan item 5b).
  Step 4-pre already re-ran the scanner on the patched checkout and compared
  against facts recorded in the original report — which is why it warned that
  a vanished fact can be rule evolution rather than a code change. New step
  4-pre.5 scans BOTH revisions and emits a typed `scanner_differential`
  evidence item, making the rule-evolution case an explicit
  `not_attempted` instead of a silent mis-read.

  §8a's stage-8 ceiling is lifted for that differential only: `proves` means
  the pattern the finding rested on is gone — pattern-level, since a diff can
  silence a scanner by moving the sink. Findings with no scanner backing stay
  analysis-only, and step 4a's root-cause check remains mandatory.

## [0.2.1]

- Pin traust-contracts v0.3.0, traust-engine v0.2.2 and traust-ledger v0.2.1 —
  the final hop of the train for the remediation `evidence[]` block. Until
  this pin, `reporting/validate.py` rejected any report carrying it, because
  the remediation schema is `additionalProperties: false`.

  Smoke-tested rather than assumed: the same evidence-carrying report
  validates with 0 errors against the newly pinned schema and is rejected
  against v0.1.1 with *"Additional properties are not allowed ('evidence' was
  unexpected)"*, and all eight enforcement cases behave — a `proves` claim
  missing either observation is refused, `not_attempted` without a reason is
  refused, and invented kinds/outcomes are refused.

## [0.1.1]

## Changes

- Event `occurred_at` is built through contracts' `to_rfc3339` via
  `traust.lib.event_time.report_occurred_at`, replacing the same f-string in
  four emitters. A report stating an unusable date now raises instead of
  getting a silent substitute; an absent one falls back to `recorded_at`.
  A triage report carrying `"triage_completed": true` previously emitted the
  literal `'TrueT00:00:00+00:00'`.

- `--recorded-at` is validated at the CLI boundary in all six producers. It
  fed `recorded_at` unchecked, whose `[:10]` prefix reaches interactive
  `source.ref` and therefore `event_id`.

- New migration `traust.migrations.fix_event_timestamps`: converts bare dates
  to midnight UTC (preserving the `[:10]` prefix, so `event_id` does not
  move), drops an unrepairable `occurred_at`, and reports a non-conforming
  `recorded_at` rather than rewriting a required field. Dry-run by default,
  idempotent, and a layer that arrives signed must leave signed.

- Read sites prefer a *parseable* timestamp over a merely present one.
  `build_trends.py` bucketed via `date.fromisoformat(value[:10])` and crashed
  on `'TrueT00:00'`.

- Unrelated fix, bundled: `check_reference_integrity` allowlisted only
  `<skill_dir>/scripts/` while the docs use `<skill-base>`, so it flagged a
  valid reference as stale and failed on a clean tree. It also missed a
  genuinely stale path in the same file. Both corrected.

### Upgrading

Pins move to contracts / engine / ledger 0.1.1, which enforce RFC 3339 on
`LayerEvent.recorded_at` and `.occurred_at` on read as well as write. Run the
migration against any existing corpus first:

```bash
python3 -m traust.migrations.fix_event_timestamps <results-root>          # dry run
python3 -m traust.migrations.fix_event_timestamps <results-root> --apply  # write
```

`--apply` re-roots each repaired layer, so it needs a signing identity
(`LAAS_SIGNING_KEY_PATH` + `COSIGN_PASSWORD`) for layers that are currently
signed. Unsigned layers only need re-stamping.

## [0.1.0]

Workflow engine for automated, multi-framework security assessment of
software portfolios — source repositories, container images, RPM packages,
Kubernetes operators, and infrastructure-as-code. Provides the skills, slash
commands, schemas, and prompt engineering that let an AI coding agent run
consistent, repeatable audits, then triage and validate findings, recording
every disposition in a signed ledger.
