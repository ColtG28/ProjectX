#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

from common import (
    SafetyError,
    classify_file_type,
    copy_sample,
    ensure_directory,
    ensure_guest_only_path,
    load_config,
    sha256_file,
    write_csv,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare a guest-only malicious corpus for ProjectX benchmarking.")
    parser.add_argument("--config", default="raw_benchmark/benchmark_config.json")
    parser.add_argument("--allow-network", action="store_true")
    return parser.parse_args()


def download_url(url: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, destination)
    return destination


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    malicious_dir = ensure_directory(Path(config["malicious_dir"]), config, "malicious corpus")
    manifests_dir = ensure_directory(Path(config["manifests_dir"]), config, "manifest directory")
    incoming_dir = ensure_directory(malicious_dir / "_incoming", config, "malicious staging")

    samples = []
    seen_hashes: set[str] = set()
    max_files = int(config.get("max_malicious_files", 5000))

    for source in config.get("malicious_sources", []):
        source_type = source["type"]
        if source_type == "guest_local":
            src_dir = ensure_guest_only_path(Path(source["path"]), config, "malicious source")
            candidates = sorted(item for item in src_dir.rglob("*") if item.is_file())
        elif source_type == "http":
            if not args.allow_network:
                raise SafetyError(
                    f"Network download for source {source['name']} is disabled. Re-run with --allow-network only inside the guest."
                )
            urls = source.get("urls", [])
            candidates = []
            for url in urls:
                local = incoming_dir / Path(url).name
                candidates.append(download_url(url, local))
        else:
            raise SafetyError(f"Unsupported malicious source type: {source_type}")

        for candidate in candidates:
            if len(samples) >= max_files:
                break
            if config["allowed_malicious_extensions"] and candidate.suffix.lower() not in set(config["allowed_malicious_extensions"]):
                continue
            digest = sha256_file(candidate)
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            stored = copy_sample(candidate, malicious_dir, digest)
            samples.append(
                {
                    "sample_id": digest,
                    "sha256": digest,
                    "label": "malicious",
                    "source_name": source["name"],
                    "source_type": source_type,
                    "stored_path": str(stored),
                    "original_path": str(candidate),
                    "file_size_bytes": stored.stat().st_size,
                    "file_type": classify_file_type(stored),
                }
            )

    payload = {
        "corpus": "malicious",
        "sample_count": len(samples),
        "sample_type_counts": count_by(samples, "file_type"),
        "source_counts": count_by(samples, "source_name"),
        "samples": samples,
    }
    write_json(manifests_dir / "malicious_manifest.json", payload)
    write_csv(manifests_dir / "malicious_manifest.csv", samples)
    write_json(manifests_dir / "malicious_hashes.json", {"sha256": [row["sha256"] for row in samples]})
    print(manifests_dir / "malicious_manifest.json")
    return 0


def count_by(rows: list[dict], key: str) -> dict:
    counts: dict[str, int] = {}
    for row in rows:
        value = row.get(key, "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


if __name__ == "__main__":
    raise SystemExit(main())
