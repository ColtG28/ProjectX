#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    classify_file_type,
    copy_sample,
    ensure_directory,
    ensure_allowed_source_path,
    load_config,
    sha256_file,
    write_csv,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a deduplicated clean corpus inside the guest.")
    parser.add_argument("--config", default="raw_benchmark/benchmark_config.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    clean_dir = ensure_directory(Path(config["clean_dir"]), config, "clean corpus")
    manifests_dir = ensure_directory(Path(config["manifests_dir"]), config, "manifest directory")

    allowed_exts = {item.lower() for item in config.get("allowed_clean_extensions", [])}
    max_files = int(config.get("max_clean_files", 5000))
    samples = []
    seen_hashes: set[str] = set()

    for source in config.get("clean_sources", []):
        for raw_path in source.get("paths", []):
            source_path = ensure_allowed_source_path(Path(raw_path), config, "clean source")
            for candidate in sorted(item for item in source_path.rglob("*") if item.is_file()):
                if len(samples) >= max_files:
                    break
                if allowed_exts and candidate.suffix.lower() not in allowed_exts:
                    continue
                digest = sha256_file(candidate)
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)
                stored = copy_sample(candidate, clean_dir, digest)
                samples.append(
                    {
                        "sample_id": digest,
                        "sha256": digest,
                        "label": "clean",
                        "source_name": source["name"],
                        "source_type": source["type"],
                        "stored_path": str(stored),
                        "original_path": str(candidate),
                        "file_size_bytes": stored.stat().st_size,
                        "file_type": classify_file_type(stored),
                    }
                )
            if len(samples) >= max_files:
                break

    payload = {
        "corpus": "clean",
        "sample_count": len(samples),
        "sample_type_counts": count_by(samples, "file_type"),
        "source_counts": count_by(samples, "source_name"),
        "samples": samples,
    }
    write_json(manifests_dir / "clean_manifest.json", payload)
    write_csv(manifests_dir / "clean_manifest.csv", samples)
    print(manifests_dir / "clean_manifest.json")
    return 0


def count_by(rows: list[dict], key: str) -> dict:
    counts: dict[str, int] = {}
    for row in rows:
        value = row.get(key, "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


if __name__ == "__main__":
    raise SystemExit(main())
