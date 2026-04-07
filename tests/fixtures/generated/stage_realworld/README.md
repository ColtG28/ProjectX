`stage_realworld` targets approximately:

- 2000 benign real-world-style fixtures
- 600 suspicious-safe real-world-style fixtures

The staged validation harness materializes these fixtures at runtime from safe stored seeds plus deterministic real-world-style context markers. The generated corpus is intended to mimic package, framework, archive, office, admin, and inert loader-chain structure without adding real malware, executable payloads, or unsafe samples.

Reports are written under `quarantine/validation_reports/` when the ignored `stage_realworld` tests are run.

Current measured `stage_realworld` combined snapshot:

- benign clean rate: `2000/2000`
- false positives: `0/2000`
- suspicious-safe escalation: `600/600`
- trust hits: `1485`
- vendor/ecosystem trust hits: `1285`
- simulated signer-style metadata hits: `200`
- provenance-supported benign clean cases: `1200`
- suspicious-safe cases with provenance-like context that still escalated: `85`
- gate: `PASS`

Measured diversity fields include category variance, entropy diversity, structure diversity, real-world variance, category coverage, and confidence-band stability.

The signer-style metadata cases are simulated passive validation metadata, not cryptographic signature verification. They exist to exercise provenance reporting and trust dampening constraints without adding unsafe samples or platform-specific execution.
