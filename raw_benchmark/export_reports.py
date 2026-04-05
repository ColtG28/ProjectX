#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from common import ensure_directory, load_config, safe_report_file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export sanitized raw-benchmark reports only.")
    parser.add_argument("--config", default="raw_benchmark/benchmark_config.json")
    parser.add_argument("--destination", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(Path(args.config))
    source_dir = ensure_directory(Path(config["results_dir"]) / "latest", config, "results directory")
    destination = Path(args.destination).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)

    copied = 0
    exported_files: list[dict[str, str]] = []
    for path in source_dir.rglob("*"):
        if not path.is_file():
            continue
        if not safe_report_file(path, config):
            raise RuntimeError(
                f"Refusing to export {path.name}. Only sanitized textual reports may leave the guest."
            )
        target = destination / path.name
        shutil.copy2(path, target)
        exported_files.append({"source": str(path), "destination": str(target)})
        copied += 1
    (destination / "export_manifest.json").write_text(json.dumps({"exported_files": exported_files}, indent=2) + "\n")
    print(f"Exported {copied} safe report file(s) to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
