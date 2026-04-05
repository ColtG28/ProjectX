#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
import zipfile
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


def expand_candidates(candidate: Path, extract_root: Path) -> tuple[list[Path], list[dict]]:
    failures: list[dict] = []
    if candidate.suffix.lower() != ".zip":
        return [candidate], failures

    extraction_dir = extract_root / candidate.stem
    extraction_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(candidate) as archive:
            members = [member for member in archive.infolist() if not member.is_dir()]
            extracted: list[Path] = []
            for member in members:
                member_name = Path(member.filename).name
                if not member_name:
                    continue
                target = extraction_dir / member_name
                try:
                    with archive.open(member, pwd=b"infected") as source, target.open("wb") as handle:
                        handle.write(source.read())
                    extracted.append(target)
                except RuntimeError as error:
                    failures.append(
                        {
                            "path": str(candidate),
                            "reason": f"zip_member_failed:{member.filename}:{error}",
                        }
                    )
            if extracted:
                return extracted, failures
            failures.append({"path": str(candidate), "reason": "zip_archive_empty_after_extraction"})
            return [], failures
    except zipfile.BadZipFile as error:
        failures.append({"path": str(candidate), "reason": f"bad_zip:{error}"})
        return [], failures


def candidate_rows(candidates: list[Path], source: dict, config: dict, malicious_dir: Path, seen_hashes: set[str], max_files: int, current_count: int) -> tuple[list[dict], list[dict]]:
    rows: list[dict] = []
    failures: list[dict] = []
    extract_root = malicious_dir / "_extracted" / source["name"]
    extract_root.mkdir(parents=True, exist_ok=True)

    for candidate in candidates:
        if current_count + len(rows) >= max_files:
            break
        expanded, expand_failures = expand_candidates(candidate, extract_root)
        failures.extend(expand_failures)
        for item in expanded:
            if current_count + len(rows) >= max_files:
                break
            if config["allowed_malicious_extensions"] and item.suffix.lower() not in set(config["allowed_malicious_extensions"]):
                continue
            try:
                digest = sha256_file(item)
            except OSError as error:
                failures.append({"path": str(item), "reason": f"sha256_failed:{error}"})
                continue
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            stored = copy_sample(item, malicious_dir, digest)
            rows.append(
                {
                    "sample_id": digest,
                    "sha256": digest,
                    "label": "malicious",
                    "source_name": source["name"],
                    "source_type": source["type"],
                    "stored_path": str(stored),
                    "original_path": str(item),
                    "file_size_bytes": stored.stat().st_size,
                    "file_type": classify_file_type(stored),
                }
            )
    return rows, failures


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    malicious_dir = ensure_directory(Path(config["malicious_dir"]), config, "malicious corpus")
    manifests_dir = ensure_directory(Path(config["manifests_dir"]), config, "manifest directory")
    incoming_dir = ensure_directory(malicious_dir / "_incoming", config, "malicious staging")

    samples = []
    seen_hashes: set[str] = set()
    max_files = int(config.get("max_malicious_files", 5000))
    download_failures: list[dict] = []
    processed_files: list[str] = []

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
                local = incoming_dir / Path(url.split("?")[0]).name
                try:
                    candidates.append(download_url(url, local))
                    processed_files.append(str(local))
                except (urllib.error.URLError, OSError) as error:
                    download_failures.append({"path": url, "reason": f"download_failed:{error}"})
        else:
            raise SafetyError(f"Unsupported malicious source type: {source_type}")

        new_rows, source_failures = candidate_rows(
            candidates=candidates,
            source=source,
            config=config,
            malicious_dir=malicious_dir,
            seen_hashes=seen_hashes,
            max_files=max_files,
            current_count=len(samples),
        )
        samples.extend(new_rows)
        download_failures.extend(source_failures)

    payload = {
        "corpus": "malicious",
        "sample_count": len(samples),
        "sample_type_counts": count_by(samples, "file_type"),
        "source_counts": count_by(samples, "source_name"),
        "processed_files": processed_files,
        "failures": download_failures,
        "samples": samples,
    }
    write_json(manifests_dir / "malicious_manifest.json", payload)
    write_csv(manifests_dir / "malicious_manifest.csv", samples)
    write_json(manifests_dir / "malicious_hashes.json", {"sha256": [row["sha256"] for row in samples]})
    write_json(
        manifests_dir / "malicious_download_summary.json",
        {
            "sample_count": len(samples),
            "processed_count": len(processed_files),
            "failure_count": len(download_failures),
            "failures": download_failures,
        },
    )
    if len(samples) == 0:
        print("WARNING: malicious manifest contains zero samples.")
    print(f"Malicious samples prepared: {len(samples)}")
    if download_failures:
        print(f"Download/extraction issues: {len(download_failures)}")
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
