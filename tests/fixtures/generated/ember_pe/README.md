`ember_pe_benchmark` is a PE-focused evaluation adapter.

It writes `quarantine/validation_reports/ember_pe_benchmark.json`.

Current measured local baseline:

- external EMBER/raw-PE manifest: not run because `PROJECTX_EMBER_PE_MANIFEST` was not set
- controlled PE benign clean rate: `2/2`
- controlled PE suspicious-safe escalation: `2/2`
- controlled PE false positives: `0/2`

Important scope notes:

- Standard EMBER feature releases are not raw PE files, so they are not directly scannable by this passive file scanner.
- To run an external PE-file evaluation, set `PROJECTX_EMBER_PE_MANIFEST` to a JSONL file where each line contains at least `path` and `label`.
- Accepted labels include `benign`, `clean`, `0`, `suspicious`, `malicious`, `suspicious_safe`, and `1`.
- The adapter is PE-focused and does not validate ELF, Mach-O, GUI workflow, or real-time protection by itself.
