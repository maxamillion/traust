# Changelog

All notable changes to Traust are documented here.

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
