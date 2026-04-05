#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import (
    ensure_directory,
    load_config,
    predicted_label_to_binary,
    write_json,
    write_markdown,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build failure analysis and next steps for the raw benchmark.")
    parser.add_argument("--config", default="raw_benchmark/benchmark_config.json")
    return parser.parse_args()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def load_jsonl(path: Path) -> list[dict]:
    with path.open() as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    artifacts = ensure_directory(Path(config["results_dir"]) / "latest", config, "latest results directory")
    metrics = load_json(artifacts / "metrics.json")
    rows = load_jsonl(artifacts / "scan_results.jsonl")
    fp = [row for row in rows if row["label"] == "clean" and row["predicted_label"] in {"suspicious", "malicious"}]
    fn = [row for row in rows if row["label"] == "malicious" and row["predicted_label"] == "clean"]
    suspicious_overprediction = sum(1 for row in rows if row.get("predicted_label") == "suspicious")
    malicious_overprediction = sum(1 for row in rows if row.get("predicted_label") == "malicious")
    heuristic_pressure = heuristic_pressure_summary(rows)
    threshold_message = threshold_recommendation(metrics, suspicious_overprediction, malicious_overprediction)

    failure_payload = {
        "false_positive_clusters": cluster(fp),
        "false_negative_clusters": cluster(fn),
        "file_type_specific_weaknesses": metrics["per_type_breakdown"],
        "suspicious_overprediction_patterns": [
            threshold_message
            if fp or suspicious_overprediction or malicious_overprediction
            else "none_detected"
        ],
        "likely_missing_feature_families": [
            "stricter benign installer / updater suppressors",
            "clean script allow-listing signals",
            "better calibration between heuristic and ML risk contributions",
        ],
        "likely_weak_heuristic_thresholds": [
            threshold_message
        ],
        "likely_weak_ml_calibration": [
            "portable/native score may need recalibration against a real clean corpus"
        ],
        "heuristics_vs_ml": heuristic_pressure,
        "recommended_next_scanner_improvements": [
            {
                "rank": 1,
                "step": "Investigate false positives in benign PE files with elevated section entropy or installer-like layout",
                "why": "False-positive clusters by file type and finding codes point to PE-heavy clean misses.",
            },
            {
                "rank": 2,
                "step": "Tune suspicious/malicious thresholds using raw benchmark score distributions",
                "why": threshold_message,
            },
            {
                "rank": 3,
                "step": "Improve file-type-specific suppressors for clean script and archive-heavy benign content",
                "why": "Per-type clusters are the fastest path to recovering precision without weakening malware recall globally.",
            },
            {
                "rank": 4,
                "step": "Review heuristic weights versus ML blended score on misclassified files",
                "why": heuristic_pressure["summary"],
            },
            {
                "rank": 5,
                "step": "Add category-specific calibration using clean and malicious score distributions from this raw benchmark",
                "why": "This benchmark now captures actual runtime feature behavior, so it is the right place to tune score cutoffs.",
            },
        ],
    }
    next_steps_payload = {
        "run_recommendation": "Use this raw benchmark as the primary validation path for ProjectX runtime scanning.",
        "ranked_actions": failure_payload["recommended_next_scanner_improvements"],
        "safety_follow_ups": [
            "Revert the guest snapshot after each malicious benchmark run.",
            "Export only report artifacts with export_reports.py.",
            "Do not move raw samples back to the host.",
        ],
    }
    write_json(artifacts / "failure_analysis.json", failure_payload)
    write_json(artifacts / "next_steps.json", next_steps_payload)
    write_markdown(
        artifacts / "failure_analysis.md",
        "\n".join(
            ["# Failure Analysis", ""]
            + [f"- False positive cluster: {item}" for item in failure_payload["false_positive_clusters"]]
            + [f"- False negative cluster: {item}" for item in failure_payload["false_negative_clusters"]]
            + [f"- Heuristics vs ML: {failure_payload['heuristics_vs_ml']['summary']}"]
            + ["", "## Recommended Next Scanner Improvements", ""]
            + [f"- {item['rank']}. {item['step']} ({item['why']})" for item in failure_payload["recommended_next_scanner_improvements"]]
        ),
    )
    write_markdown(
        artifacts / "next_steps.md",
        "\n".join(
            [
                "# Next Steps",
                "",
                f"- Run recommendation: {next_steps_payload['run_recommendation']}",
                "",
                "## Safety Follow-Ups",
                "",
                *[f"- {item}" for item in next_steps_payload["safety_follow_ups"]],
                "",
                "## Ranked Actions",
                "",
                *[f"- {item['rank']}. {item['step']} ({item['why']})" for item in next_steps_payload["ranked_actions"]],
            ]
        ),
    )
    print(artifacts / "failure_analysis.json")
    return 0


def cluster(rows: list[dict]) -> list[str]:
    counts: dict[str, int] = {}
    for row in rows:
        key = row.get("file_type") or "unknown"
        if row.get("finding_codes"):
            key = f"{key} | findings={','.join(row['finding_codes'][:3])}"
        counts[key] = counts.get(key, 0) + 1
    return [f"{key} ({value})" for key, value in sorted(counts.items(), key=lambda item: item[1], reverse=True)[:10]]


def heuristic_pressure_summary(rows: list[dict]) -> dict:
    mismatches = [row for row in rows if predicted_label_to_binary(row.get("predicted_label", "")) != (1 if row["label"] == "malicious" else 0)]
    if not mismatches:
        return {"summary": "No heuristic-vs-ML mismatch pressure detected in the current run."}
    heuristic_only = sum(1 for row in mismatches if row.get("heuristic_reasons") and float(row.get("ml_score", 0.0) or 0.0) < float(row.get("score", 0.0) or 0.0))
    return {
        "summary": f"{heuristic_only} of {len(mismatches)} misclassified files show stronger final risk than ML blended score, suggesting heuristics may be overpowering ML on edge cases."
    }


def threshold_recommendation(metrics: dict, suspicious_count: int, malicious_count: int) -> str:
    fp = int(metrics.get("fp", 0))
    clean = int(metrics.get("total_clean_samples", 0))
    if clean and fp / clean > 0.10:
        return "Suspicious and malicious thresholds are likely too aggressive for part of the clean corpus and should be recalibrated with raw benchmark score distributions."
    if suspicious_count > malicious_count:
        return "The scanner leans suspicious more often than malicious, which is safer operationally but still suggests threshold tuning may recover precision."
    return "Thresholds should be reviewed against raw benchmark score distributions before the next large-scale run."


if __name__ == "__main__":
    raise SystemExit(main())
