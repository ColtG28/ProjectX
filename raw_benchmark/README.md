# Raw ProjectX Benchmark

## Safety First

This workflow is for **guest-only** malware benchmarking.

- Never scan malware on the host.
- Never open malware with host desktop tools.
- Never use shared folders for malware storage.
- Never mount host directories read-write inside the guest for sample handling.
- Export only sanitized reports and logs, never raw samples.
- Take a guest snapshot before importing malware and revert it after the run.

The scripts in this directory assume malware and benchmark storage live only under approved guest paths such as `/opt/projectx_benchmark/` or `/var/lib/projectx_benchmark/`. They intentionally reject likely host-mounted paths like `/mnt`, `/media`, `/Volumes`, `/run/desktop`, `/run/host`, `/host_mnt`, and `/Users`.

Clean corpus source paths are allowed from guest-local read-only locations such as `/bin`, `/usr`, and `/etc`, but copied benchmark samples still end up under the guest-only benchmark workspace before scanning.

## What This Validates

This is the primary raw-file validation path for ProjectX runtime scanning.

- ProjectX scans real raw files with its actual runtime pipeline.
- Samples are never executed on the host.
- Results are exported as JSON, CSV, Markdown, and optionally HTML-safe text artifacts only.

## Layout

- `raw_benchmark/benchmark_config.json`
- `raw_benchmark/setup_guest_env.sh`
- `raw_benchmark/download_malicious_corpus.py`
- `raw_benchmark/build_clean_corpus.py`
- `raw_benchmark/run_projectx_benchmark.sh`
- `raw_benchmark/run_quick_test.sh`
- `raw_benchmark/run_scans.py`
- `raw_benchmark/evaluate_results.py`
- `raw_benchmark/next_steps.py`
- `raw_benchmark/export_reports.py`
- `scripts/bootstrap_vm.sh`
- `scripts/view_results.py`

## Guest Responsibilities

1. Prepare the guest benchmark environment:

```bash
bash raw_benchmark/setup_guest_env.sh
```

2. Stage malicious samples inside the guest only.

Recommended default:
- place them under `/opt/projectx_benchmark/incoming_malicious/`

3. Build the malicious manifest:

```bash
python3 raw_benchmark/download_malicious_corpus.py
```

Optional network retrieval is supported only inside the guest:

```bash
python3 raw_benchmark/download_malicious_corpus.py --allow-network
```

4. Build the clean manifest:

```bash
python3 raw_benchmark/build_clean_corpus.py
```

5. Run the benchmark:

```bash
bash raw_benchmark/run_projectx_benchmark.sh
```

6. For a fast pipeline sanity check without real malware, run:

```bash
bash raw_benchmark/run_quick_test.sh
```

## Host Responsibilities

- Maintain the VM or isolated guest environment.
- Snapshot before importing malware.
- Revert or destroy the guest after scanning.
- Export only reports:

```bash
python3 raw_benchmark/export_reports.py --destination /safe/report/export/path
```

## Outputs

The one-command run writes results under:

- `/opt/projectx_benchmark/results/latest/`
- `raw_benchmark/artifacts/latest/`

Key files:

- `scan_results.jsonl`
- `scan_results.csv`
- `metrics.json`
- `report.md`
- `summary.json`
- `report.html`
- `failure_analysis.json`
- `failure_analysis.md`
- `next_steps.json`
- `next_steps.md`
- `publish_manifest.json`

History is appended to:

- `raw_benchmark/artifacts/history/runs.jsonl`

## Report Semantics

- `metrics.json` contains TP, FP, TN, FN, accuracy, precision, recall, F1, specificity, FPR, FNR, ROC-AUC, PR-AUC, confusion matrix, per-type breakdown, and runtime summary.
- `failure_analysis.json` focuses on false-positive and false-negative clusters plus concrete scanner weaknesses.
- `next_steps.json` gives ranked scanner improvement recommendations.

## Guardrails

- Malware and clean corpora must live under approved guest-only prefixes from the config.
- Export refuses non-textual artifacts.
- The benchmark runner refuses to proceed if manifests are missing or paths look like shared/host mounts.

## Cleanup / Reset

- Revert the guest snapshot after each malware run.
- If you cannot revert, remove `/opt/projectx_benchmark/malicious/`, `/opt/projectx_benchmark/clean/`, `/opt/projectx_benchmark/manifests/`, and `/opt/projectx_benchmark/results/` inside the guest and rebuild them.
- Do not copy the malware corpus back to the host as part of cleanup.
