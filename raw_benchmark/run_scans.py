#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import (
    SafetyError,
    ensure_directory,
    ensure_guest_only_path,
    load_config,
    load_manifest,
    recommended_batch_size,
    recommended_concurrency,
    write_csv,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ProjectX over guest-only raw-file corpora.")
    parser.add_argument("--config", default="raw_benchmark/benchmark_config.json")
    return parser.parse_args()


def scan_one(binary: Path, flags: list[str], sample: dict, timeout_seconds: int) -> dict:
    started = time.perf_counter()
    sample_path = Path(sample["stored_path"])
    command = [str(binary), *flags, str(sample_path)]
    try:
        if not sample_path.exists():
            raise FileNotFoundError(sample_path)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        elapsed = time.perf_counter() - started
        stdout = result.stdout.strip()
        payload = json.loads(stdout) if stdout else {}
        verdict = payload.get("verdict", {})
        threat = payload.get("threat_severity") or {}
        findings = payload.get("findings", []) or []
        telemetry = payload.get("telemetry", []) or []
        ml = payload.get("ml") or {}
        return {
            "sample_id": sample["sample_id"],
            "sha256": sample["sha256"],
            "label": sample["label"],
            "file_type": sample.get("file_type"),
            "path": sample["stored_path"],
            "predicted_label": str(verdict.get("severity", "error")).lower(),
            "score": float(verdict.get("risk", 0.0) or 0.0),
            "confidence": float(threat.get("severity_score", 0.0) or 0.0),
            "elapsed_seconds": elapsed,
            "warning_count": len(telemetry),
            "finding_count": len(findings),
            "finding_codes": [item.get("code", "unknown") for item in findings[:20]],
            "ml_label": ml.get("label"),
            "ml_score": float(ml.get("blended_score", 0.0) or 0.0),
            "heuristic_reasons": list(ml.get("reasons", [])[:20]),
            "telemetry_preview": [item.get("message", "") for item in telemetry[:10]],
            "return_code": result.returncode,
            "error": None if result.returncode == 0 else f"exit_status_{result.returncode}",
        }
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - started
        return {
            "sample_id": sample["sample_id"],
            "sha256": sample["sha256"],
            "label": sample["label"],
            "file_type": sample.get("file_type"),
            "path": sample["stored_path"],
            "predicted_label": "error",
            "score": 0.0,
            "confidence": 0.0,
            "elapsed_seconds": elapsed,
            "warning_count": 0,
            "finding_count": 0,
            "finding_codes": [],
            "ml_label": None,
            "ml_score": 0.0,
            "heuristic_reasons": [],
            "telemetry_preview": [],
            "return_code": None,
            "error": "timeout",
        }
    except json.JSONDecodeError as error:
        elapsed = time.perf_counter() - started
        return {
            "sample_id": sample["sample_id"],
            "sha256": sample["sha256"],
            "label": sample["label"],
            "file_type": sample.get("file_type"),
            "path": sample["stored_path"],
            "predicted_label": "error",
            "score": 0.0,
            "confidence": 0.0,
            "elapsed_seconds": elapsed,
            "warning_count": 0,
            "finding_count": 0,
            "finding_codes": [],
            "ml_label": None,
            "ml_score": 0.0,
            "heuristic_reasons": [],
            "telemetry_preview": [],
            "return_code": None,
            "error": f"invalid_json:{error}",
        }
    except FileNotFoundError as error:
        elapsed = time.perf_counter() - started
        return {
            "sample_id": sample["sample_id"],
            "sha256": sample["sha256"],
            "label": sample["label"],
            "file_type": sample.get("file_type"),
            "path": sample["stored_path"],
            "predicted_label": "error",
            "score": 0.0,
            "confidence": 0.0,
            "elapsed_seconds": elapsed,
            "warning_count": 0,
            "finding_count": 0,
            "finding_codes": [],
            "ml_label": None,
            "ml_score": 0.0,
            "heuristic_reasons": [],
            "telemetry_preview": [],
            "return_code": None,
            "error": f"missing_sample:{error}",
        }


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    binary = ensure_guest_only_path(Path(config["projectx_binary"]), config, "ProjectX binary")
    manifests_dir = ensure_directory(Path(config["manifests_dir"]), config, "manifest directory")
    results_dir = ensure_directory(Path(config["results_dir"]), config, "results directory")
    artifacts_dir = ensure_directory(results_dir / "latest", config, "latest results directory")
    timeout_seconds = int(config["scan_timeout_seconds"])
    concurrency = recommended_concurrency(config)
    batch_size = recommended_batch_size(config)
    flags = list(config.get("scan_flags", []))

    malicious = load_manifest(manifests_dir / "malicious_manifest.json")
    clean = load_manifest(manifests_dir / "clean_manifest.json")
    if not malicious and not clean:
        raise SafetyError("No corpus manifests found. Build the malicious and clean corpora inside the guest first.")

    rows = malicious + clean
    for sample in rows:
        ensure_guest_only_path(Path(sample["stored_path"]), config, f"{sample['label']} sample")
    output = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            futures = [pool.submit(scan_one, binary, flags, sample, timeout_seconds) for sample in batch]
            for future in as_completed(futures):
                output.append(future.result())

    output.sort(key=lambda row: row["sample_id"])
    jsonl_path = artifacts_dir / "scan_results.jsonl"
    with jsonl_path.open("w") as handle:
        for row in output:
            handle.write(json.dumps(row) + "\n")
    write_csv(artifacts_dir / "scan_results.csv", output)
    run_config = {
        "concurrency": concurrency,
        "batch_size": batch_size,
        "timeout_seconds": timeout_seconds,
        "scan_flags": flags,
        "total_samples": len(rows),
    }
    (artifacts_dir / "run_config.json").write_text(json.dumps(run_config, indent=2) + "\n")
    print(jsonl_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
