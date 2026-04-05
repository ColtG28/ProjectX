#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create EMBER vectorized files and metadata when raw JSONL features are present.")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--feature-version", type=int, default=2)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dataset_dir = Path(args.dataset_dir)
    required_outputs = [
        dataset_dir / "X_train.dat",
        dataset_dir / "y_train.dat",
        dataset_dir / "X_test.dat",
        dataset_dir / "y_test.dat",
    ]
    if all(path.exists() for path in required_outputs):
        print("Vectorized EMBER files already exist.")
        return 0

    try:
        import sys

        repo_path = Path(__file__).resolve().parent / "ember_repo"
        sys.path.insert(0, str(repo_path))
        import ember  # type: ignore
    except ModuleNotFoundError as error:
        print(
            "Vectorization failed: upstream EMBER import is unavailable. "
            "If the missing module is 'lief', install it in the benchmark environment before retrying. "
            f"Original error: {error}"
        )
        return 2

    try:
        ember.create_vectorized_features(str(dataset_dir), feature_version=args.feature_version)
        ember.create_metadata(str(dataset_dir))
    except Exception as error:  # noqa: BLE001
        print(f"Vectorization failed: {error}")
        return 3

    print("Vectorized EMBER files created successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
