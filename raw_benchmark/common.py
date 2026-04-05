#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import mimetypes
import os
import platform
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "benchmark_config.json"
ARTIFACTS_ROOT = ROOT / "artifacts"
LATEST_ARTIFACTS_DIR = ARTIFACTS_ROOT / "latest"
HISTORY_DIR = ARTIFACTS_ROOT / "history"


class SafetyError(RuntimeError):
    pass


def require_linux_host() -> None:
    if platform.system().lower() != "linux":
        raise SafetyError(
            "ProjectX raw benchmark scripts are guest-only and must run on Linux inside the isolated VM."
        )


def load_config(path: Path | None = None) -> dict:
    require_linux_host()
    target = path or CONFIG_PATH
    return json.loads(target.read_text())


def resolve_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def approved_guest_prefixes(config: dict) -> list[Path]:
    return [resolve_path(item) for item in config["approved_guest_prefixes"]]


def blocked_prefixes(config: dict) -> list[Path]:
    return [resolve_path(item) for item in config["blocked_path_prefixes"]]


def ensure_guest_only_path(path: Path, config: dict, purpose: str) -> Path:
    target = resolve_path(path)
    blocked = blocked_prefixes(config)
    if any(target == prefix or prefix in target.parents for prefix in blocked):
        raise SafetyError(
            f"{purpose} path {target} is blocked because it looks like a host-mounted or shared location."
        )
    approved = approved_guest_prefixes(config)
    if not any(target == prefix or prefix in target.parents for prefix in approved):
        raise SafetyError(
            f"{purpose} path {target} is outside approved guest-only prefixes: "
            + ", ".join(str(item) for item in approved)
        )
    return target


def ensure_allowed_source_path(path: Path, config: dict, purpose: str) -> Path:
    target = resolve_path(path)
    blocked = blocked_prefixes(config)
    if any(target == prefix or prefix in target.parents for prefix in blocked):
        raise SafetyError(
            f"{purpose} path {target} is blocked because it looks like a host-mounted or shared location."
        )
    allowed = [resolve_path(item) for item in config.get("allowed_readonly_source_prefixes", [])]
    if allowed and not any(target == prefix or prefix in target.parents for prefix in allowed):
        raise SafetyError(
            f"{purpose} path {target} is outside allowed read-only source prefixes: "
            + ", ".join(str(item) for item in allowed)
        )
    return target


def ensure_directory(path: Path, config: dict, purpose: str) -> Path:
    target = ensure_guest_only_path(path, config, purpose)
    target.mkdir(parents=True, exist_ok=True)
    return target


def ensure_local_directory(path: Path) -> Path:
    target = resolve_path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def classify_file_type(path: Path) -> str:
    lower = path.suffix.lower()
    if lower in {".exe", ".dll", ".sys", ".com"}:
        return "pe"
    if lower in {".ps1", ".vbs", ".js", ".bat", ".cmd", ".sh"}:
        return "script"
    if lower in {".zip", ".7z", ".rar", ".tar", ".gz"}:
        return "archive"
    if lower in {".pdf", ".html", ".htm", ".doc", ".docm", ".xls", ".xlsm"}:
        return "document"
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed:
        return guessed.replace("/", "_")
    return "unknown"


def copy_sample(src: Path, dst_dir: Path, sha256: str) -> Path:
    dst_dir.mkdir(parents=True, exist_ok=True)
    extension = src.suffix.lower()
    target = dst_dir / f"{sha256}{extension}"
    if not target.exists():
        shutil.copy2(src, target)
    return target


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def write_markdown(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n")


def write_csv(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    fieldnames = sorted({key for row in rows for key in row.keys()}) if rows else []
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if fieldnames:
            writer.writeheader()
            writer.writerows(rows)


def safe_report_file(path: Path, config: dict) -> bool:
    return path.suffix.lower() in set(config["export_safe_extensions"])


def load_manifest(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data.get("samples", [])


def truth_label_to_binary(label: str) -> int:
    return 1 if label == "malicious" else 0


def predicted_label_to_binary(label: str) -> int:
    return 1 if label in {"suspicious", "malicious"} else 0


def recommended_concurrency(config: dict) -> int:
    configured = int(config.get("concurrency", 0) or 0)
    if configured > 0:
        return max(1, configured)
    cpu_count = os.cpu_count() or 1
    memory_mb = detect_memory_mb()
    if memory_mb is not None and memory_mb <= 4096:
        return max(1, min(2, cpu_count))
    return max(1, min(4, cpu_count))


def recommended_batch_size(config: dict) -> int:
    configured = int(config.get("batch_size", 0) or 0)
    if configured > 0:
        return max(1, configured)
    memory_mb = detect_memory_mb()
    if memory_mb is not None and memory_mb <= 4096:
        return 8
    if memory_mb is not None and memory_mb <= 8192:
        return 16
    return 32


def detect_memory_mb() -> int | None:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return None
    for line in meminfo.read_text().splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) // 1024
    return None


def publish_safe_artifacts(source_dir: Path, config: dict) -> Path:
    latest_dir = ensure_local_directory(LATEST_ARTIFACTS_DIR)
    for path in latest_dir.iterdir():
        if path.is_file():
            path.unlink()
    published_files = []
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        if not safe_report_file(path, config):
            continue
        target = latest_dir / path.name
        shutil.copy2(path, target)
        published_files.append(target.name)
    manifest = {
        "published_at": iso_timestamp(),
        "source_dir": str(source_dir),
        "files": published_files,
    }
    write_json(latest_dir / "publish_manifest.json", manifest)
    return latest_dir


def append_run_history(summary: dict) -> Path:
    history_dir = ensure_local_directory(HISTORY_DIR)
    history_path = history_dir / "runs.jsonl"
    with history_path.open("a") as handle:
        handle.write(json.dumps(summary) + "\n")
    return history_path


def iso_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
