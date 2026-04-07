# Generated Validation Corpus

This directory documents staged generated validation tiers used by the benchmark harness.

The staged validation tests generate deterministic, inert fixtures at runtime for:

- `stage_100`
- `stage_500`
- `stage_1000`
- `stage_realworld`
- `ember_pe`
- `external_formats`

Generated fixtures are preferred here over committing hundreds of near-duplicate files. They are:

- safe and inert
- deterministic
- derived from benign and suspicious-safe seed content
- suitable only for passive validation

Reports for staged runs are written under `quarantine/validation_reports/`.
