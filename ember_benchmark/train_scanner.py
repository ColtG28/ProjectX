#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression

from common import choose_threshold, rust_portable_feature_names


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a ProjectX benchmark model.")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument(
        "--model-family",
        default="ember_reference_logreg",
        choices=["ember_reference_logreg", "portable_logreg"],
    )
    parser.add_argument("--calibration", default="sigmoid", choices=["none", "sigmoid", "isotonic"])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = Path(args.run_dir)
    dataset = np.load(run_dir / "dataset_bundle.npz")
    feature_names = json.loads((run_dir / "feature_names.json").read_text())

    x_train = dataset["x_train"]
    y_train = dataset["y_train"]
    x_val = dataset["x_val"]
    y_val = dataset["y_val"]

    rust_feature_count = len(rust_portable_feature_names())
    rust_compatible = x_train.shape[1] == rust_feature_count and args.model_family == "portable_logreg"

    if args.model_family == "portable_logreg" and not rust_compatible:
        blocker = {
            "status": "blocked",
            "reason": "ProjectX portable model training requires a feature matrix that matches the Rust portable schema exactly.",
            "rust_feature_count": rust_feature_count,
            "training_feature_count": int(x_train.shape[1]),
            "explanation": (
                "Current EMBER vectorized features do not match ProjectX portable features. "
                "Without a schema-aligned extractor or a binary corpus for ProjectX feature extraction, "
                "a Rust-compatible portable model cannot be honestly trained from this dataset."
            ),
        }
        (run_dir / "training_blocker.json").write_text(json.dumps(blocker, indent=2) + "\n")
        print(json.dumps(blocker, indent=2))
        return 2

    started = time.perf_counter()
    base_model = LogisticRegression(max_iter=400, class_weight="balanced", solver="liblinear")
    base_model.fit(x_train, y_train)

    if args.calibration == "none":
        model = base_model
        val_scores = model.predict_proba(x_val)[:, 1]
        calibration = None
    else:
        model = CalibratedClassifierCV(base_model, method=args.calibration, cv="prefit")
        model.fit(x_val, y_val)
        val_scores = model.predict_proba(x_val)[:, 1]
        calibration = args.calibration

    threshold = choose_threshold(y_val, val_scores)
    training_seconds = time.perf_counter() - started

    weights = None
    intercept = None
    if hasattr(base_model, "coef_"):
        weights = base_model.coef_[0].tolist()
        intercept = float(base_model.intercept_[0])

    model_payload = {
        "model_family": args.model_family,
        "calibration": calibration,
        "threshold": threshold,
        "rust_portable_compatible": rust_compatible,
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "training_seconds": training_seconds,
    }
    if weights is not None and intercept is not None:
        model_payload["portable_model_candidate"] = {
            "model_type": "portable-linear-v1",
            "version": f"benchmark-{args.model_family}",
            "feature_names": feature_names,
            "weights": weights,
            "intercept": intercept,
            "malicious_threshold": threshold,
            "suspicious_threshold": max(0.0, threshold * 0.8),
            "max_input_bytes": 33554432,
            "notes": (
                "Rust-compatible only when feature_names and feature count match ProjectX runtime schema exactly."
            ),
            "calibration": None,
        }

    (run_dir / "trained_model.json").write_text(json.dumps(model_payload, indent=2) + "\n")
    print(run_dir / "trained_model.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
