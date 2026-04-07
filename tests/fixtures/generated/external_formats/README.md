`external_format_benchmark` is a manifest-driven validation harness for PE, ELF, and Mach-O.

It writes `quarantine/validation_reports/external_format_benchmark_summary.json`.

Current measured local result:

- external PE samples acquired/tested: `0/0`
- external ELF samples acquired/tested: `0/0`
- external Mach-O samples acquired/tested: `0/0`
- controlled PE baseline: `1/1` benign clean, `1/1` suspicious-safe escalated, `0/1` false positives
- controlled ELF baseline: `1/1` benign clean, `1/1` suspicious-safe escalated, `0/1` false positives
- controlled Mach-O baseline: `1/1` benign clean, `2/2` suspicious-safe escalated, `0/1` false positives

The harness does not download live malware or opaque corpora. To run an external safe corpus, provide JSONL manifests with one object per line:

```json
{"path":"/absolute/path/to/sample.exe","label":"benign","source":"local_safe_corpus","category":"installer"}
```

Supported environment variables:

- `PROJECTX_PE_BENCHMARK_MANIFEST` or `PROJECTX_EMBER_PE_MANIFEST`
- `PROJECTX_ELF_BENCHMARK_MANIFEST`
- `PROJECTX_MACHO_BENCHMARK_MANIFEST`
- `PROJECTX_EXTERNAL_BENCHMARK_CAP`, default `1000000` per format

Accepted labels:

- benign labels: `benign`, `clean`, `0`
- suspicious-safe labels: `suspicious`, `malicious`, `suspicious_safe`, `1`

Scope notes:

- PE external evaluation is manifest-driven and separate from the controlled PE smoke baseline.
- ELF external evaluation is manifest-driven; no canonical EMBER-equivalent ELF benchmark is assumed.
- Mach-O validation is manifest-driven; no standard EMBER-equivalent Mach-O benchmark is assumed.
- Counts are reported exactly. If no manifest is provided, external acquired/tested counts remain zero by design.
