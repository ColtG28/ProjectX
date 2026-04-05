#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from common import RUNS_DIR, load_ember_vectorized, sample_test_subset, slugify


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare a reproducible EMBER subset for ProjectX benchmarking.")
    parser.add_argument("--dataset-dir", required=True, help="Path to extracted EMBER dataset directory.")
    parser.add_argument("--feature-version", type=int, default=2)
    parser.add_argument("--sample-size", type=int, default=100000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--run-name", default="ember_preprocess")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = RUNS_DIR / slugify(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)

    try:
        bundle = load_ember_vectorized(Path(args.dataset_dir), args.feature_version)
    except (FileNotFoundError, ValueError) as error:
        print(f"Preprocess failed: {error}")
        return 2

    x_test, y_test, test_meta = sample_test_subset(bundle, args.sample_size, args.seed)

    np.savez_compressed(
        run_dir / "dataset_bundle.npz",
        x_train=bundle.x_train,
        y_train=bundle.y_train,
        x_val=bundle.x_val,
        y_val=bundle.y_val,
        x_test=x_test,
        y_test=y_test,
    )
    bundle.train_meta.to_csv(run_dir / "train_metadata.csv", index=False)
    bundle.val_meta.to_csv(run_dir / "validation_metadata.csv", index=False)
    test_meta.to_csv(run_dir / "test_metadata.csv", index=False)
    (run_dir / "feature_names.json").write_text(json.dumps(bundle.feature_names, indent=2) + "\n")
    (run_dir / "prep_summary.json").write_text(
        json.dumps(
            {
                "source": bundle.source,
                "dataset_dir": str(Path(args.dataset_dir).resolve()),
                "feature_version": args.feature_version,
                "seed": args.seed,
                "train_count": int(len(bundle.y_train)),
                "validation_count": int(len(bundle.y_val)),
                "test_count": int(len(y_test)),
                "feature_count": int(bundle.x_train.shape[1]),
                "test_malicious_rate": float(np.mean(y_test)),
            },
            indent=2,
        )
        + "\n"
    )
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
