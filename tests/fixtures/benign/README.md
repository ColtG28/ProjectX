# Benign Fixture Corpus

These fixtures exist to harden calibration against false positives.

Each file is harmless and intentionally shaped to resemble patterns that can look suspicious in passive scanners:

- `admin/`: deployment, maintenance, backup, and cleanup workflows
- `developer/`: minified or bundled scripts, build outputs, and eval-style configuration loaders
- `installers/`: update checks, download logic, and archive unpacking flows
- `office/`: harmless macro-like automation markers and document workflows
- `encoded/`: base64 or encoded configuration/data blobs
- `archives/`: source content used to build valid nested or dense archives during tests

The fixtures are small, readable where practical, and must remain free of:

- real malware
- exploit payloads
- credential theft
- persistence logic
- execution or detonation behavior

Tests may combine these fixture files into temporary archive or Office-like containers, but the source content itself stays inert and local.
Benign parser guardrails may also use deterministic PE/ELF byte builders from `tests/support/parser_fixtures.rs` to exercise parsed section, import, interpreter, or ELF symbol layouts without storing executable samples.
Some parser guardrails intentionally mix weak parsed binary cues with harmless text so threshold-edge behavior stays stable as PE and ELF support evolve.

## Fixture Notes

- `admin/deployment_helper.ps1`
  Simulates a deployment helper that downloads a manifest and runs local admin checks.
  Triggers: possible PowerShell automation markers.
  Should remain clean because the workflow is routine admin automation without stronger corroboration.

- `admin/backup_cleanup.ps1`
  Simulates scheduled cleanup and archive maintenance.
  Triggers: file and archive workflow terms.
  Should remain clean because it lacks obfuscation, hidden content recovery, or corroborating rule hits.

- `developer/minified_bundle.js`
  Simulates a production frontend bundle.
  Triggers: minified structure and compact JavaScript formatting.
  Should remain clean because it has no risky automation or downloader correlation.

- `developer/eval_config_loader.js`
  Simulates a legacy configuration loader using `eval`.
  Triggers: JavaScript eval-style patterns.
  Should remain clean because it uses benign config text rather than script launch or download markers.

- `developer/framework_chunk.js`
  Simulates a framework bundle that decodes benign strings at runtime.
  Triggers: encoded string handling in legitimate code.
  Should remain clean because the decoded data is configuration, not hidden active content.

- `developer/obfuscated_feature_flags.js`
  Simulates feature-flag loading with base64 and eval-like reconstruction.
  Triggers: encoded strings and JavaScript reconstruction.
  Should remain clean because it is a benign configuration pattern.

- `installers/update_checker.ps1`
  Simulates an update checker with download-style text.
  Triggers: PowerShell web request markers.
  Should remain clean because it reflects a normal update workflow without stronger corroboration.

- `installers/silent_upgrade.cmd`
  Simulates a quiet installer script with version and archive checks.
  Triggers: download-like text and command chaining.
  Should remain clean because it is a straightforward installer wrapper.

- `installers/environment_probe.ps1`
  Simulates environment probing before install compatibility checks.
  Triggers: web request and system inspection markers.
  Should remain clean because it is normal environment validation.

- `office/macro_notes.txt`
  Simulates macro container storage and auto-run labels.
  Triggers: macro storage markers.
  Should remain clean because it lacks downloader or high-risk automation markers.

- `office/formatting_macro_notes.txt`
  Simulates formatting-heavy workbook automation.
  Triggers: macro and auto-run labels.
  Should remain clean because the described behavior is document formatting only.

- `office/data_transform_macro.txt`
  Simulates document data transformation and workbook automation.
  Triggers: macro storage plus light automation wording.
  Should remain clean because it describes harmless spreadsheet processing.

- `encoded/config_blob.txt`
  Simulates an encoded configuration blob.
  Triggers: base64 decoding paths.
  Should remain clean because the decoded data is plain configuration.

- `encoded/embedded_template.txt`
  Simulates a packaged encoded template block.
  Triggers: base64 decoding paths.
  Should remain clean because it decodes to inert template data.

- `archives/readme.txt`, `archives/update_manifest.txt`, `archives/script_notes.txt`
  Simulate harmless archive contents used to build nested or dense archives in tests.
  Triggers: archive complexity only when combined in generated containers.
  Should remain clean because the contents are documentation and manifests, not payloads.
