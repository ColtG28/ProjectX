# ProjectX

ProjectX is a GUI-first defensive file scanner built in Rust with `egui`/`eframe`.

## Downloads

- [Downloads](./DOWNLOADS.md)
- [GitHub releases](https://github.com/ColtG-28/ProjectX/releases)

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

## Shipping Releases

Tag a release like `v1.0.0` and push the tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions will build optimized release archives for Linux, Windows, and macOS and publish them to GitHub Releases automatically. The repository-local [Downloads](./DOWNLOADS.md) page always points at the latest release assets, so you do not need to make the project public or enable GitHub Pages.

## Update Checks

The desktop app checks GitHub Releases through the official GitHub Releases REST API. It compares the installed app version with the latest stable release tag, ignores drafts by default, and ignores prereleases unless explicitly enabled.

Supported environment variables:

- `PROJECTX_GITHUB_OWNER`
- `PROJECTX_GITHUB_REPO`
- `PROJECTX_GITHUB_TOKEN`
- `PROJECTX_INCLUDE_PRERELEASES`

Behavior notes:

- Public repositories do not require a token.
- Private repositories can be checked if `PROJECTX_GITHUB_TOKEN` is provided.
- Draft releases are ignored.
- Prereleases are ignored unless `PROJECTX_INCLUDE_PRERELEASES=true`.
- Release selection is explicit rather than trusting raw API order: ProjectX filters releases, parses version tags, prefers the newest appropriate version, and uses publish time only as a fallback.
- Asset matching is scored by OS, architecture hints, package type, and naming clues instead of relying on one filename substring.
- If multiple assets match equally well, the updater reports the ambiguity instead of guessing.
- If GitHub is offline, rate-limited, or misconfigured, the app reports that state explicitly instead of pretending it is up to date.
- The app stores updater cache metadata in local app config, including the last attempted lookup, the last successful lookup, the last error state, the selected release metadata, and a short recent-attempt history.
- When a matching `.sha256` release asset exists, the updater records the expected SHA-256 and can verify a user-selected downloaded file without auto-running it.
- The updater remains manual and safe: it can open a release page, open a download, and verify a downloaded artifact, but it does not auto-install updates.

macOS note:
- The macOS release contains a real `ProjectX.app` bundle inside a DMG.
- The bundle is ad-hoc signed for local usability, but it is still not notarized.
- After dragging `ProjectX.app` into `Applications`, open it with right-click -> `Open` the first time, or allow it from `System Settings` -> `Privacy & Security` if macOS blocks launch.
- For locally built or manually distributed copies, you can also remove the quarantine attribute with `bash scripts/remove_macos_quarantine.sh /path/to/ProjectX.app`.

## Release Packaging

Local packaging commands:

```bash
cargo build --release --locked
bash scripts/package_macos_app.sh
bash scripts/package_linux_release.sh
pwsh -File scripts/package_windows_release.ps1
```

Output locations:

- macOS: `release-artifacts/macos/ProjectX.app` and `release-artifacts/macos/ProjectX-macos.dmg`
- Windows: `release-artifacts/windows/ProjectX-windows.zip`
- Linux: `release-artifacts/linux/ProjectX-linux.tar.gz`

Platform packaging notes:

- macOS ships as a Finder-launchable `.app` bundle inside a DMG and uses ad-hoc signing only.
- Windows ships as a clean portable `ProjectX.exe` layout inside a zip, not an installer.
- Linux currently ships as a portable bundle with a `.desktop` file, icon, and install helper; AppImage is not part of this branch.

## Runtime Data Paths

ProjectX now stores writable runtime data in per-user application directories instead of assuming the repo root is the working directory.

- macOS: `~/Library/Application Support/ProjectX` and cache under `~/Library/Caches/ProjectX`
- Windows: `%LOCALAPPDATA%\\ProjectX` for runtime data and `%APPDATA%\\ProjectX` for config
- Linux: XDG app-data/config/cache directories under `ProjectX`

This covers settings, scan history, reports, quarantine, protection backlog, telemetry, ML feedback, and cache data. You can override the defaults with `PROJECTX_DATA_DIR`, `PROJECTX_CONFIG_DIR`, and `PROJECTX_CACHE_DIR` when needed for local testing.

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

Avoid real malware samples.

## Calibration Maintenance

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
