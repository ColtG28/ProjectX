#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn import metrics

from common import (
    append_run_history,
    ensure_directory,
    iso_timestamp,
    load_config,
    publish_safe_artifacts,
    predicted_label_to_binary,
    recommended_batch_size,
    recommended_concurrency,
    truth_label_to_binary,
    write_json,
    write_markdown,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate guest-only raw benchmark scan results.")
    parser.add_argument("--config", default="raw_benchmark/benchmark_config.json")
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict]:
    with path.open() as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    artifacts_dir = ensure_directory(Path(config["results_dir"]) / "latest", config, "latest results directory")
    rows = load_jsonl(artifacts_dir / "scan_results.jsonl")
    run_config_path = artifacts_dir / "run_config.json"
    run_config = json.loads(run_config_path.read_text()) if run_config_path.exists() else {}
    if not rows:
        raise SystemExit("No scan results found. Run raw_benchmark/run_scans.py first.")

    y_true = np.asarray([truth_label_to_binary(row["label"]) for row in rows], dtype=np.int32)
    y_score = np.asarray([float(row.get("score", 0.0) or 0.0) for row in rows], dtype=np.float64)
    y_pred = np.asarray([predicted_label_to_binary(row.get("predicted_label", "")) for row in rows], dtype=np.int32)

    tn, fp, fn, tp = metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = metrics.precision_score(y_true, y_pred, zero_division=0)
    recall = metrics.recall_score(y_true, y_pred, zero_division=0)
    specificity = tn / max(tn + fp, 1)
    total_elapsed = float(sum(row["elapsed_seconds"] for row in rows))
    total_malicious = int(sum(1 for row in rows if row["label"] == "malicious"))
    total_clean = int(sum(1 for row in rows if row["label"] == "clean"))
    score_labels = label_breakdown(rows, "predicted_label")
    error_count = int(sum(1 for row in rows if row.get("error")))
    warning_count = int(sum(int(row.get("warning_count", 0) or 0) for row in rows))
    payload = {
        "benchmark_type": "PROJECTX_NATIVE_RAW_BENCHMARK",
        "total_samples": len(rows),
        "total_malicious_samples": total_malicious,
        "total_clean_samples": total_clean,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "accuracy": float(metrics.accuracy_score(y_true, y_pred)),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(metrics.f1_score(y_true, y_pred, zero_division=0)),
        "specificity": float(specificity),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
        "roc_auc": float(metrics.roc_auc_score(y_true, y_score)) if len(set(y_true)) > 1 else None,
        "pr_auc": float(metrics.average_precision_score(y_true, y_score)) if len(set(y_true)) > 1 else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "per_type_breakdown": breakdown_by(rows, "file_type"),
        "predicted_label_breakdown": score_labels,
        "scan_error_count": error_count,
        "warning_count": warning_count,
        "runtime_summary": {
            "total_elapsed_seconds": total_elapsed,
            "throughput_files_per_second": float(len(rows) / max(total_elapsed, 1e-9)),
        },
        "resource_profile": {
            "concurrency": int(run_config.get("concurrency", recommended_concurrency(config))),
            "batch_size": int(run_config.get("batch_size", recommended_batch_size(config))),
        },
    }
    write_json(artifacts_dir / "metrics.json", payload)
    write_markdown(
        artifacts_dir / "report.md",
        "\n".join(
            [
                "# Raw Benchmark Report",
                "",
                f"- Total samples: {payload['total_samples']}",
                f"- Total malicious samples: {payload['total_malicious_samples']}",
                f"- Total clean samples: {payload['total_clean_samples']}",
                f"- Accuracy: {payload['accuracy']:.6f}",
                f"- Precision: {payload['precision']:.6f}",
                f"- Recall: {payload['recall']:.6f}",
                f"- F1-score: {payload['f1_score']:.6f}",
                f"- Specificity: {payload['specificity']:.6f}",
                f"- False positive rate: {payload['false_positive_rate']:.6f}",
                f"- False negative rate: {payload['false_negative_rate']:.6f}",
                f"- ROC-AUC: {payload['roc_auc']}",
                f"- PR-AUC: {payload['pr_auc']}",
                f"- Predicted clean: {payload['predicted_label_breakdown'].get('clean', 0)}",
                f"- Predicted suspicious: {payload['predicted_label_breakdown'].get('suspicious', 0)}",
                f"- Predicted malicious: {payload['predicted_label_breakdown'].get('malicious', 0)}",
                f"- Scan errors: {payload['scan_error_count']}",
                f"- Warning count: {payload['warning_count']}",
                f"- Throughput: {payload['runtime_summary']['throughput_files_per_second']:.6f} files/sec",
            ]
        ),
    )
    (artifacts_dir / "report.html").write_text(
        "\n".join(
            [
                "<!doctype html>",
                "<html><head><meta charset='utf-8'><title>ProjectX Raw Benchmark</title></head><body>",
                "<h1>ProjectX Raw Benchmark</h1>",
                "<ul>",
                f"<li>Total samples: {payload['total_samples']}</li>",
                f"<li>Total malicious samples: {payload['total_malicious_samples']}</li>",
                f"<li>Total clean samples: {payload['total_clean_samples']}</li>",
                f"<li>Accuracy: {payload['accuracy']:.6f}</li>",
                f"<li>Precision: {payload['precision']:.6f}</li>",
                f"<li>Recall: {payload['recall']:.6f}</li>",
                f"<li>F1-score: {payload['f1_score']:.6f}</li>",
                f"<li>Specificity: {payload['specificity']:.6f}</li>",
                f"<li>False positive rate: {payload['false_positive_rate']:.6f}</li>",
                f"<li>False negative rate: {payload['false_negative_rate']:.6f}</li>",
                f"<li>ROC-AUC: {payload['roc_auc']}</li>",
                f"<li>PR-AUC: {payload['pr_auc']}</li>",
                f"<li>Scan errors: {payload['scan_error_count']}</li>",
                f"<li>Warning count: {payload['warning_count']}</li>",
                f"<li>Throughput: {payload['runtime_summary']['throughput_files_per_second']:.6f} files/sec</li>",
                "</ul>",
                "</body></html>",
            ]
        )
        + "\n"
    )
    write_json(
        artifacts_dir / "summary.json",
        {
            "status": "completed",
            "timestamp": iso_timestamp(),
            "results_path": str(artifacts_dir),
            "metrics_file": str(artifacts_dir / "metrics.json"),
            "report_file": str(artifacts_dir / "report.md"),
            "html_report_file": str(artifacts_dir / "report.html"),
        },
    )
    history_entry = {
        "timestamp": iso_timestamp(),
        "dataset_size": len(rows),
        "malicious_samples": total_malicious,
        "clean_samples": total_clean,
        "metrics": {
            "accuracy": payload["accuracy"],
            "precision": payload["precision"],
            "recall": payload["recall"],
            "f1_score": payload["f1_score"],
            "specificity": payload["specificity"],
            "false_positive_rate": payload["false_positive_rate"],
            "false_negative_rate": payload["false_negative_rate"],
        },
    }
    history_path = append_run_history(history_entry)
    publish_safe_artifacts(artifacts_dir, config)
    summary = json.loads((artifacts_dir / "summary.json").read_text())
    summary["history_file"] = str(history_path)
    write_json(artifacts_dir / "summary.json", summary)
    print(artifacts_dir / "metrics.json")
    return 0


def breakdown_by(rows: list[dict], key: str) -> dict:
    breakdown: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = row.get(key) or "unknown"
        state = breakdown.setdefault(bucket, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        truth_positive = row["label"] == "malicious"
        predicted = bool(predicted_label_to_binary(row.get("predicted_label", "")))
        if truth_positive and predicted:
            state["tp"] += 1
        elif truth_positive and not predicted:
            state["fn"] += 1
        elif not truth_positive and predicted:
            state["fp"] += 1
        else:
            state["tn"] += 1
    return breakdown


def label_breakdown(rows: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown").lower()
        counts[value] = counts.get(value, 0) + 1
    return counts


if __name__ == "__main__":
    raise SystemExit(main())
