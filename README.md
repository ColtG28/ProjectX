# ProjectX

ProjectX is a GUI-first defensive file scanner built in Rust with `egui`/`eframe`.

## Scope

- Desktop GUI is the primary and only product interface.
- ProjectX is intended for passive, defensive file analysis.
- The scanner focuses on local-first inspection, triage visibility, quarantine handling, and report history.
- Sandbox execution, detonation, and runtime environment modification are not part of the desktop product.
- External and network-based enrichment should remain opt-in and privacy-conscious.

## What It Does

- Scans files and folders from the desktop GUI
- Extracts passive signals from file metadata, strings, normalized text, decoded content, scripts, archives, and known formats
- Produces structured reports and scan history
- Retains suspicious files in quarantine and restores clean files when appropriate
- Surfaces detection reasons, rule hits, and ML/heuristic context in the GUI
- Provides aligned Results and History workspaces for dense triage, operational review, and quarantine tracking
- Presents local timestamps, passive-signal badges, and clearer reason text to support day-to-day review
- Explains findings in operator-friendly language so each signal can stand on its own without raw internal codes
- Calibrates verdicts to reduce avoidable false positives from benign admin scripts, dense archives, installer/updater files, and routine document automation unless stronger corroborating evidence is present
- Strengthens binary-side confidence with explainable PE/ELF structure cues such as import relationships, packed-section markers, resource staging, and loader-chain combinations

## What It Does Not Do

- No offensive behavior
- No payload execution as part of the GUI workflow
- No live malware handling requirement for development tests
- No CLI entry path

## Running The App

```bash
cargo run --release
```

## Running Tests

```bash
cargo test
```

## Test Data Guidance

Use only inert and defensive fixtures:

- benign files
- synthetic suspicious text fixtures
- malformed but harmless archive or parser fixtures
- mock report payloads
- metadata-only test cases
- categorized benign regression fixtures under `tests/fixtures/benign/`
- suspicious-safe regression fixtures under `tests/fixtures/suspicious_safe/`

Avoid real malware samples.

## Calibration Maintenance

- Benign regression fixtures are organized by category under `tests/fixtures/benign/`
- Suspicious-safe regression fixtures are organized by category under `tests/fixtures/suspicious_safe/`
- Calibration tests verify that common false-positive cases stay clean or below the suspicious threshold
- Correlated passive signals still need to escalate out of clean, so tests cover both benign-heavy and suspicious-corroborated cases
- Stronger passive detections rely on explainable combinations such as script + decoded content + local rule, risky macro automation + corroborating strings, or PE/ELF symbol combinations
- Binary-side suspicious-safe fixtures exercise PE/ELF structure-plus-content cases without requiring executable or unsafe samples
- Conservative parser-depth checks now read lightweight PE section headers and ELF section tables so suspicious binary verdicts can lean on real structure, not just marker strings
- Conservative PE import-directory parsing now reads real import relationships for higher-confidence loader and injection chains when parsing succeeds safely
- Conservative ELF symbol-table parsing now reads real dynamic-symbol relationships for higher-confidence loader, network, and relaunch chains when parsing succeeds safely
- `.symtab/.strtab` parsing is intentionally not enabled in the current desktop product; the ELF parser stays focused on dynamic symbols and low-risk relationships to preserve robustness and explainability
- PE and ELF parser regressions now include near-threshold binary cases so structure-only or weakly corroborated parser cues stay predictable across both formats
- Benign parser guardrails verify that normal PE/ELF layouts stay clean unless stronger corroborating signals are present
- Malformed parser regressions verify that truncated or inconsistent PE/ELF headers fail safely without emitting misleading structural findings
- Threshold-edge parser tests verify that borderline parsed structure stays below suspicious until corroborating content, rule, or decode signals are present
- Shared deterministic parser test helpers under `tests/support/parser_fixtures.rs` keep PE/ELF byte fixtures small, readable, and consistent across unit and regression coverage
- When changing weights, dampening rules, or local rules, update or extend the fixture-driven regression tests first

## Severity Guidance

- `Clean` means no strong malicious indicators were identified during passive analysis.
- `Suspicious` means the scanner found patterns that warrant review, but the evidence is not yet strong enough for a high-confidence malicious verdict.
- `Malicious` means multiple high-confidence passive indicators align and the file should be treated as unsafe.
- Recent calibration changes make `Suspicious` a more trustworthy triage label by favoring corroborated signals across different sources over a simple count of weak findings.
- Structural binary findings become more important when section/resource/layout evidence agrees with content, local-rule, or decode signals instead of acting as standalone noise.

## Notes

- Quarantine data and GUI history are stored under `quarantine/`.
- The app now launches directly into the GUI from `src/main.rs`.
- Older CLI and sandbox-execution-oriented product paths have been removed from the desktop app.
- Quarantine restore and delete actions require confirmation from the GUI before modifying local files.
