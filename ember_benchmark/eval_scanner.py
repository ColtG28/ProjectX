#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression

from common import (
    REPORTS_DIR,
    category_breakdown,
    choose_threshold,
    classification_metrics,
    failure_analysis,
    safe_float,
    slugify,
    write_report_triplet,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate a ProjectX benchmark run and generate reports.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--model-family", default="ember_reference_logreg")
    parser.add_argument("--calibration", default="sigmoid", choices=["none", "sigmoid", "isotonic"])
    parser.add_argument("--run-name", default="ember_eval")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_dir)
    dataset = np.load(run_dir / "dataset_bundle.npz")
    feature_names = json.loads((run_dir / "feature_names.json").read_text())
    prep_summary = json.loads((run_dir / "prep_summary.json").read_text())

    x_train = dataset["x_train"]
    y_train = dataset["y_train"]
    x_val = dataset["x_val"]
    y_val = dataset["y_val"]
    x_test = dataset["x_test"]
    y_test = dataset["y_test"]
    test_meta = pd.read_csv(run_dir / "test_metadata.csv")

    started = time.perf_counter()
    base_model = LogisticRegression(max_iter=400, class_weight="balanced", solver="liblinear")
    base_model.fit(x_train, y_train)

    if args.calibration == "none":
        model = base_model
        val_scores = model.predict_proba(x_val)[:, 1]
        calibration_method = None
    else:
        model = CalibratedClassifierCV(base_model, method=args.calibration, cv="prefit")
        model.fit(x_val, y_val)
        val_scores = model.predict_proba(x_val)[:, 1]
        calibration_method = args.calibration

    threshold = choose_threshold(y_val, val_scores)
    scores = model.predict_proba(x_test)[:, 1]
    metrics_payload = classification_metrics(y_test, scores, threshold)
    y_pred = (scores >= threshold).astype(int)
    elapsed = max(time.perf_counter() - started, 1e-9)

    report = {
        "run_name": args.run_name,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model_family": args.model_family,
        "data_source": prep_summary["source"],
        "rust_portable_compatible": False,
        "architectural_status": (
            "Reference EMBER benchmark only. This run does not prove Rust scanner parity because "
            "EMBER vectorized features are not the same schema as ProjectX portable runtime features."
        ),
        "dataset": {
            "train_count": int(len(y_train)),
            "validation_count": int(len(y_val)),
            "test_count": int(len(y_test)),
            "test_malicious_rate": float(np.mean(y_test)),
        },
        "thresholds": {
            "malicious_threshold": float(threshold),
            "suspicious_threshold": float(max(0.0, threshold * 0.8)),
        },
        "metrics": {key: safe_float(value) if isinstance(value, float) else value for key, value in metrics_payload.items()},
        "throughput": {
            "samples_per_second": float(len(y_test) / elapsed),
            "evaluation_seconds": float(elapsed),
        },
        "calibration": {
            "method": calibration_method,
            "validation_threshold_selected_for": "best_f1",
        },
        "per_category_breakdown": category_breakdown(test_meta, y_test, scores, threshold),
        "failure_analysis": failure_analysis(test_meta, x_test, y_test, scores, threshold, feature_names),
        "misclassification_summary": {
            "false_positive_count": int(((y_test == 0) & (y_pred == 1)).sum()),
            "false_negative_count": int(((y_test == 1) & (y_pred == 0)).sum()),
        },
        "limitations": [
            "EMBER does not ship binaries, so this benchmark evaluates feature-space models rather than host-side binary scanning.",
            "ProjectX Rust portable inference currently expects a different feature schema than EMBER vectorized features.",
        ],
    }

    report_base = REPORTS_DIR / slugify(args.run_name)
    write_report_triplet(report_base, report)
    print(report_base.with_suffix(".json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
