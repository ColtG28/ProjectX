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
- Strengthens binary-side confidence with explainable PE/ELF/Mach-O structure cues such as import relationships, packed-section markers, resource staging, loader-chain combinations, and linked-library relationships
- Adds a local intelligence layer for reputation, trust-aware dampening, and richer local rule context without changing the passive-only product scope
- Adds a user-space real-time protection mode that watches selected paths with OS file events when available, falls back to grouped polling when needed, queues passive scans for meaningful updates, and feeds results into the same quarantine and report workflow

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
- Local intelligence metadata lives under `src/static/intelligence/data/`, with a structured JSON store and optional analyst override lists under `quarantine/intelligence/`
- GUI protection settings live under `quarantine/gui_settings.json`, recent protection events are stored under `quarantine/gui_protection_events.json`, and deferred protection backlog state is persisted under `quarantine/gui_protection_backlog.json`
- Calibration tests verify that common false-positive cases stay clean or below the suspicious threshold
- Correlated passive signals still need to escalate out of clean, so tests cover both benign-heavy and suspicious-corroborated cases
- Stronger passive detections rely on explainable combinations such as script + decoded content + local rule, risky macro automation + corroborating strings, or PE/ELF/Mach-O binary relationships
- Binary-side suspicious-safe fixtures exercise PE/ELF/Mach-O structure-plus-content cases without requiring executable or unsafe samples
- Local rule matches now carry lightweight confidence metadata so high-confidence passive rule hits are visible in reports and can support clearer confidence separation
- The structured intelligence store supports known-bad hashes, known-good hashes, framework fingerprints, vendor/package trust hints, and trusted tooling/package context entries with source, category, confidence, trust level, vendor, ecosystem, version, expiry, and allowed-dampening metadata
- Trust and provenance entries are platform-aware for PE, ELF, and Mach-O so Windows, Unix/Linux, and macOS trust hints do not bleed loosely across ecosystems
- Trust-aware dampening now uses local allowlist hashes, framework fingerprints, trusted vendor/package context, and known admin or package-manager context to keep weak standalone signals from escalating too easily while leaving stronger corroborated evidence visible
- Static scoring now adds extra dampening for common framework-bundle and package-workflow contexts so weak script or loader noise is less likely to cross into review without corroboration
- Static scoring now also dampens weak unsupported noise in CI/workflow automation paths and benign encoded-config/template contexts so long-tail build and asset cases stay cleaner near threshold
- Provenance records now carry vendor/ecosystem rationale, optional version-range or expiry metadata, matched markers, and allowed dampening scope so trust decisions stay auditable in JSON output and detail views
- Local known-bad hash matches now act as explicit intelligence evidence rather than hidden overrides, and optional external intelligence remains off by default
- Rule-family coverage now extends across PowerShell, JavaScript, Office, encoded stager/config, PE/ELF/Mach-O loader families, and related structure-plus-content corroboration cases with family/confidence metadata carried into reports
- New conservative rule families now also cover archive-download-launch and fetch/decode/blob chains when multiple corroborating literals align
- High-signal rule refinements now add conservative archive-extract-and-run and PE injection-plus-network families without inflating shallow rule count
- Verdict bands now favor corroborated evidence quality over raw score alone, so a single strong parser cue is more likely to stay in review while multi-source structure + content/rule/decode cases escalate more clearly
- Conservative parser-depth checks now read lightweight PE section headers, ELF section tables, and Mach-O load commands so suspicious binary verdicts can lean on real structure, not just marker strings
- Conservative PE import-directory parsing now reads real import relationships for higher-confidence loader and injection chains when parsing succeeds safely
- Conservative PE entrypoint-to-section checks now add confidence when the parsed entrypoint lands inside packed-looking or writable-and-executable sections
- Conservative ELF symbol-table parsing now reads real dynamic-symbol relationships for higher-confidence loader, network, and relaunch chains when parsing succeeds safely
- Conservative ELF static symbol-table support now adds a small amount of parsed loader and exec-network evidence when `.symtab/.strtab` relationships are present and well-formed
- Initial Mach-O parsing now reads magic/header cues, fat-binary wrappers, segment and section names, segment protections, and linked-library load commands when parsing succeeds safely
- Conservative Mach-O dylib interpretation now distinguishes normal vs weak/reexport-style load commands and can surface relative loader-path chains when they are meaningfully corroborated
- `.symtab/.strtab` parsing is intentionally not enabled in the current desktop product; the ELF parser stays focused on dynamic symbols and low-risk relationships to preserve robustness and explainability
- PE, ELF, and Mach-O parser regressions now include near-threshold binary cases so structure-only or weakly corroborated parser cues stay predictable across formats
- Benign parser guardrails verify that normal PE/ELF/Mach-O layouts stay clean unless stronger corroborating signals are present
- Malformed parser regressions verify that truncated or inconsistent PE/ELF/Mach-O headers fail safely without emitting misleading structural findings
- Threshold-edge parser tests verify that borderline parsed structure stays below suspicious until corroborating content, rule, or decode signals are present
- Shared deterministic parser test helpers under `tests/support/parser_fixtures.rs` keep PE/ELF/Mach-O byte fixtures small, readable, and consistent across unit and regression coverage
- `tests/intelligence_benchmark.rs` now emits a lightweight regression report for benign clean-rate, false-positive-rate snapshots, suspicious-safe escalation-rate, per-format baseline behavior, rule-family hit quality, trust-hit influence, known-bad influence, and intelligence status notes
- The validation harness now reports broader category-by-category benign and suspicious-safe results so false-positive and escalation behavior can be compared across admin, developer, installer, archive, encoded, office, script, and binary fixture slices
- Staged validation now supports `stage_100`, `stage_500`, `stage_1000`, and `stage_realworld` benchmark tiers through deterministic generated corpus expansion, with machine-readable reports written under `quarantine/validation_reports/`
- Stage progression is gated explicitly: Stage 1 must keep false positives below 5% and suspicious-safe escalation above 90% before Stage 2; Stage 2 must keep false positives below 3% and suspicious-safe escalation above 92% with stable category behavior before Stage 3; Stage 3 uses the stricter largest-tier gate of false positives below 2%, suspicious-safe escalation above 95%, stable category behavior, and clean protection regressions; `stage_realworld` requires false positives at or below 3%, suspicious-safe escalation above 92%, material provenance/trust representation, stable categories, and clean protection regressions
- The staged harness supports benign-only, suspicious-safe-only, and combined runs so false-positive behavior and escalation behavior can be measured separately before relying on a combined gate decision
- Stage 2 has now been measured at `500 benign + 250 suspicious-safe` with machine-readable support-view reports for `benign_only`, `suspicious_only`, and `combined`
- The current Stage 2 combined snapshot passed cleanly at `500/500` benign clean, `0/500` false positives, and `250/250` suspicious-safe escalation, so the harness currently qualifies to proceed toward Stage 3 under its measured scope
- Stage 3 has now been measured at `1000 benign + 500 suspicious-safe` with machine-readable support-view reports for `benign_only`, `suspicious_only`, and `combined`
- The current Stage 3 combined snapshot passed cleanly at `1000/1000` benign clean, `0/1000` false positives, and `500/500` suspicious-safe escalation under the controlled generated fixture scope
- `stage_realworld` has been added as a larger real-world-style generated tier at `2000 benign + 600 suspicious-safe`, covering npm-style bundles, package/update workflows, admin scripts, archives, configs/templates, office notes, binary-adjacent fixtures, and inert cross-platform loader/script chains
- The current `stage_realworld` combined snapshot passed at `2000/2000` benign clean, `0/2000` false positives, and `600/600` suspicious-safe escalation, with additional diversity metrics for category variance, entropy diversity, structure diversity, category coverage, and confidence-band stability
- The current `stage_realworld` provenance snapshot records `1485` trust hits, `1285` vendor/ecosystem hits, `200` simulated signer-style metadata hits, `1200` provenance-supported benign clean cases, and `85` suspicious-safe cases that still escalated despite provenance-like context
- A PE-focused `ember_pe_benchmark` adapter now writes `quarantine/validation_reports/ember_pe_benchmark.json`; when `PROJECTX_EMBER_PE_MANIFEST` is not set, it reports that no external EMBER/raw-PE manifest was evaluated and runs a controlled PE smoke baseline instead
- The current local PE benchmark baseline passed at `2/2` controlled benign PE fixtures clean, `0/2` controlled PE false positives, and `2/2` controlled suspicious-safe PE fixtures escalated; this is not an external EMBER score
- `external_format_benchmark` now provides a manifest-driven PE/ELF/Mach-O validation harness with per-format acquisition caps up to `1,000,000` samples, deduplication, exact acquired/prepared/tested counts, rule-family hit summaries, and provenance counters when external manifests are supplied
- The current cross-format external benchmark run did not acquire external PE/ELF/Mach-O samples because no manifests were configured; controlled safe baselines passed at PE `1/1` benign clean + `1/1` suspicious-safe escalated, ELF `1/1` benign clean + `1/1` suspicious-safe escalated, and Mach-O `1/1` benign clean + `2/2` suspicious-safe escalated
- `final_validation_report` now prepares a workspace-local corpus by copying safe local benign system binaries into `quarantine/final_validation/corpus/real_benign/` before scanning, then combines those with deterministic inert generated PE/ELF/Mach-O/script/archive/config/office fixtures and writes reusable manifests plus `quarantine/validation_reports/final_validation_report.json`
- The current final local validation snapshot tested `430` files: `150` copied local benign Mach-O system binaries, `140` generated benign fixtures, and `140` generated suspicious-safe fixtures; results were `287/290` benign clean, `3/290` false positives, and `140/140` suspicious-safe escalated
- The three observed final-validation false positives were copied local macOS system binaries (`actool`, `afscexpand`, and `cpuctl`), so the most honest remaining local weak spot is Mach-O benign system-binary precision rather than PE/ELF generated-fixture behavior
- The final-validation manifests can be reused by the cross-format harness; the current manifest-backed run measured PE `20/20` benign clean + `20/20` suspicious-safe escalated, ELF `20/20` benign clean + `20/20` suspicious-safe escalated, and Mach-O `167/170` benign clean + `20/20` suspicious-safe escalated
- GUI regression coverage now includes real-time watched-path queueing, grouped burst handling, deferred backlog recovery, per-path throttling, protection-history filtering, and temp/cache rate limiting so automatic scans stay predictable and auditable
- Real-time validation now also covers event-driven replace bursts, duplicate active-scan suppression for already-pending files, larger event-burst grouping, busy-queue dedupe, larger backlog-fairness checks, and watcher-init fallback into grouped polling so protection behavior is measured under more realistic event conditions
- Protection summaries now surface event drop rate, dedupe efficiency, and backlog recovery rate so real-time reliability can be reviewed without changing the passive scan workflow
- Protection review in Operations now supports filtering by event type, file class, priority, origin, result, and follow-up action so grouped bursts, deferred retries, and completed automatic scans are easier to audit
- When changing weights, dampening rules, or local rules, update or extend the fixture-driven regression tests first

## Severity Guidance

- `Clean` means no strong malicious indicators were identified during passive analysis.
- `Suspicious` means the scanner found patterns that warrant review, but the evidence is not yet strong enough for a high-confidence malicious verdict.
- `Malicious` means multiple high-confidence passive indicators align and the file should be treated as unsafe.
- Recent calibration changes make `Suspicious` a more trustworthy triage label by favoring corroborated signals across different sources over a simple count of weak findings.
- Structural binary findings become more important when section/resource/layout evidence agrees with content, local-rule, or decode signals instead of acting as standalone noise.
- Cross-format verdict logic now applies the same basic decision quality expectations to PE, ELF, and Mach-O: structure alone stays modest, while corroborated multi-source evidence moves more confidently into review or likely-malicious territory.
- Local intelligence contributes as an explainable confidence input: known-bad reputation raises confidence, while trust/allowlist context dampens weak unsupported noise instead of silently suppressing findings.
- Trust is ecosystem-aware: PE, ELF, and Mach-O only receive platform-relevant trust dampening, and trust entries specify which weak signal classes they are allowed to soften.
- Provenance records now support signer hints, package source, distribution channel, confidence weight, trust scope, confidence score, source quality, last-verified date, and decay factor so stale or weaker trust/intelligence can remain auditable and lower impact.
- Real-time protection uses the same passive scoring, verdicting, quarantine, and reporting workflow as manual scans, so automatic scans remain explainable and reviewable.
- Protection activity records now capture event class, grouped change counts, burst windows, file-class hints, and workflow origin so operators can tell why a single grouped scan was queued instead of seeing a flood of duplicate events.
- Deferred, throttled, skipped, and scanned protection outcomes remain visible after restart, and the Operations workspace is the review surface for filtering protection history by event type, file class, priority, and origin.
- Event-driven monitoring now surfaces whether protection is using Windows, macOS, or Linux file events, or whether it has fallen back to grouped polling because a watcher could not be initialized cleanly.
- Queue health now reflects live queue pressure, deferred backlog, and recent throttling/deferral behavior so "Healthy", "Busy", and "Backed up" mean something operational instead of just reflecting one raw count.
- Validation numbers should be read as measured fixture-scope outcomes, not global AV-quality claims; expand the benign and suspicious-safe corpora further before making stronger accuracy claims.
- The current staged scope should be read honestly: Stage 1, Stage 2, Stage 3, and `stage_realworld` have measured cleanly in controlled validation, but those outcomes are fixture-scope results rather than global AV-quality claims.
- EMBER reporting is PE-focused and separate from staged validation: standard EMBER feature releases do not provide raw PE files for direct passive scanning, so external EMBER-style evaluation requires a local JSONL manifest of raw PE paths and labels via `PROJECTX_EMBER_PE_MANIFEST`.
- Cross-format external validation is manifest-driven: set `PROJECTX_PE_BENCHMARK_MANIFEST` or `PROJECTX_EMBER_PE_MANIFEST`, `PROJECTX_ELF_BENCHMARK_MANIFEST`, and `PROJECTX_MACHO_BENCHMARK_MANIFEST` to evaluate safe local corpora; absent manifests are reported as zero external samples rather than treated as benchmark success.
- The final local validation report is the most realistic in-workspace measurement currently available because it includes copied local benign system binaries, but it is still not a malware benchmark and should not be read as global AV-quality evidence.
- Protection queueing now avoids duplicate active scans for the same file by grouping additional bursts into one deferred follow-up snapshot, and backlog draining skips already-pending paths so retries stay fairer under load.

## Platform Coverage

- `PE`: Windows executable and library analysis
- `ELF`: Linux and Unix executable and library analysis
- `Mach-O`: macOS executable, library, and universal binary analysis

## Notes

- Quarantine data and GUI history are stored under `quarantine/`.
- Real-time protection is user-space and passive-first: it watches selected files or folders, classifies create/modify/replace-style changes, groups rapid repeats into one logical event when practical, and never executes the watched content.
- Windows, macOS, and Linux all use the same event-driven protection workflow when watcher initialization succeeds; polling remains the explicit fallback path instead of a hidden backup behavior.
- Protection workflow is intentionally split by task rather than by subsystem: Settings configures watched paths, Scan shows live protection state and recent activity, and Operations is the durable review timeline for protection-driven events.
- The app now launches directly into the GUI from `src/main.rs`.
- Older CLI and sandbox-execution-oriented product paths have been removed from the desktop app.
- Quarantine restore and delete actions require confirmation from the GUI before modifying local files.
