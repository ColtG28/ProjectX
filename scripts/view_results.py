#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
METRICS_PATH = ROOT / "raw_benchmark" / "artifacts" / "latest" / "metrics.json"


def main() -> int:
    if not METRICS_PATH.exists():
        raise SystemExit(f"Metrics file not found: {METRICS_PATH}")

    metrics = json.loads(METRICS_PATH.read_text())
    print(f"Benchmark type: {metrics.get('benchmark_type', 'unknown')}")
    print(f"Total samples: {metrics.get('total_samples', 0)}")
    print(f"Accuracy: {metrics.get('accuracy', 0.0):.6f}")
    print(f"Precision: {metrics.get('precision', 0.0):.6f}")
    print(f"Recall: {metrics.get('recall', 0.0):.6f}")
    print(f"F1-score: {metrics.get('f1_score', 0.0):.6f}")
    print(f"False positives: {metrics.get('fp', 0)}")
    print(f"False negatives: {metrics.get('fn', 0)}")

    issues = []
    if float(metrics.get("false_positive_rate", 0.0) or 0.0) > 0.10:
        issues.append("High false-positive rate")
    if float(metrics.get("false_negative_rate", 0.0) or 0.0) > 0.10:
        issues.append("High false-negative rate")
    if int(metrics.get("scan_error_count", 0) or 0) > 0:
        issues.append("Scan errors present")

    if issues:
        print("Major issues:")
        for issue in issues:
            print(f"- {issue}")
    else:
        print("Major issues: none detected from the summary thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
