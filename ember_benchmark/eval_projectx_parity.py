#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import numpy as np
from sklearn import metrics

from projectx_ember_schema import ARTIFACTS_DIR


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a scaled adapted ProjectX benchmark only when parity is acceptable.")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--sample-size", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--projectx-bin", default=str(Path("target/debug/ProjectX")))
    return parser.parse_args()


def main() -> int:
    parity_path = ARTIFACTS_DIR / "parity_test.json"
    if not parity_path.exists():
        print("Scaled parity evaluation blocked: parity_test.json does not exist yet.")
        return 2
    parity = json.loads(parity_path.read_text())
    if parity["recommendation"] != "parity acceptable":
        print(
            "Scaled parity evaluation blocked: parity is not acceptable. "
            "Reports must remain NOT Rust-parity until the feature-gap risk is reduced."
        )
        return 3

    subprocess.run(
        [
            "python3",
            str(Path(__file__).resolve().parent / "projectx_ember_adapter.py"),
            "--dataset-dir",
            args.dataset_dir,
            "--sample-size",
            str(args.sample_size),
            "--seed",
            str(args.seed),
        ],
        check=True,
    )
    input_jsonl = ARTIFACTS_DIR / "adapter_output.jsonl"
    rust_scores = subprocess.run(
        [args.projectx_bin, "--score-features-jsonl", str(input_jsonl)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    score_path = ARTIFACTS_DIR / "scaled_rust_scores.jsonl"
    score_path.write_text(rust_scores)

    labels = []
    scores = []
    for line in input_jsonl.read_text().splitlines():
        row = json.loads(line)
        labels.append(int(row["source_label"]))
    for line in rust_scores.splitlines():
        row = json.loads(line)
        scores.append(float(row["score"]))
    y_true = np.asarray(labels, dtype=np.int32)
    y_score = np.asarray(scores, dtype=np.float64)
    y_pred = (y_score >= 0.5).astype(int)

    payload = {
        "benchmark_label": "ProjectX-adapted parity benchmark",
        "benchmark_validity": "valid parity benchmark",
        "parity_confidence": parity["parity_confidence"],
        "missing_feature_risk": parity["missing_feature_risk"],
        "sample_count": int(len(y_true)),
        "accuracy": float(metrics.accuracy_score(y_true, y_pred)),
        "precision": float(metrics.precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(metrics.recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(metrics.f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(metrics.roc_auc_score(y_true, y_score)),
        "pr_auc": float(metrics.average_precision_score(y_true, y_score)),
        "confusion_matrix": metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "schema_coverage_notes": "See adapter_summary.json and schema_mapping.json for explicit mapped, approximate, and missing fields.",
    }
    out_json = ARTIFACTS_DIR / "scaled_benchmark.json"
    out_md = ARTIFACTS_DIR / "scaled_benchmark.md"
    out_json.write_text(json.dumps(payload, indent=2) + "\n")
    out_md.write_text(
        "\n".join(
            [
                "# Scaled Parity Benchmark",
                "",
                f"- Benchmark label: {payload['benchmark_label']}",
                f"- Benchmark validity: {payload['benchmark_validity']}",
                f"- Parity confidence: {payload['parity_confidence']}",
                f"- Missing feature risk: {payload['missing_feature_risk']}",
                f"- Sample count: {payload['sample_count']}",
                f"- Accuracy: {payload['accuracy']:.6f}",
                f"- Precision: {payload['precision']:.6f}",
                f"- Recall: {payload['recall']:.6f}",
                f"- F1: {payload['f1_score']:.6f}",
                f"- ROC-AUC: {payload['roc_auc']:.6f}",
                f"- PR-AUC: {payload['pr_auc']:.6f}",
                "",
            ]
        )
    )
    print(out_json)
    return 0


if __name__ == "__main__":
    args = parse_args()
    raise SystemExit(main())
