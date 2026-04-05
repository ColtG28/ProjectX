#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize benchmark reports for quick comparison.")
    parser.add_argument("--reports-dir", default=str(Path(__file__).resolve().parent / "reports"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reports_dir = Path(args.reports_dir)
    reports = sorted(reports_dir.glob("*.json"))
    if not reports:
        print("No benchmark reports found.")
        return 0

    for report_path in reports:
        report = json.loads(report_path.read_text())
        metrics = report.get("metrics", {})
        print(
            json.dumps(
                {
                    "report": report_path.name,
                    "model_family": report.get("model_family"),
                    "accuracy": metrics.get("accuracy"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall"),
                    "f1_score": metrics.get("f1_score"),
                    "roc_auc": metrics.get("roc_auc"),
                    "pr_auc": metrics.get("pr_auc"),
                    "rust_portable_compatible": report.get("rust_portable_compatible"),
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
