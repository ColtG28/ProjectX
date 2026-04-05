#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import random
import re
from math import gcd
from pathlib import Path

import numpy as np

from common import ROOT, rust_portable_feature_names
from projectx_ember_schema import (
    ARTIFACTS_DIR,
    EMBER_DATA_DIRECTORY_NAMES,
    NETWORK_IMPORT_MODULES,
    PROCESS_IMPORT_MODULES,
    PROJECTX_PATTERN_NAMES,
    SUSPICIOUS_IMPORT_MODULES,
    SUSPICIOUS_SECTION_NAMES,
    projectx_portable_mapping_spec,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Adapt EMBER raw feature rows into ProjectX portable feature vectors.")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--sample-size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--output-jsonl", default=str(ARTIFACTS_DIR / "adapter_output.jsonl"))
    parser.add_argument("--summary-json", default=str(ARTIFACTS_DIR / "adapter_summary.json"))
    parser.add_argument("--summary-md", default=str(ARTIFACTS_DIR / "adapter_summary.md"))
    return parser.parse_args()


def log2ish(value: float) -> float:
    if value <= 0:
        return 0.0
    return float(np.log2(value + 1.0))


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def dataset_paths(dataset_dir: Path) -> list[Path]:
    paths = [dataset_dir / f"train_features_{index}.jsonl" for index in range(6)]
    paths.append(dataset_dir / "test_features.jsonl")
    return [path for path in paths if path.exists()]


def iter_rows_from_path(path: Path):
    subset = "test" if path.name == "test_features.jsonl" else "train"
    with path.open() as handle:
        for line_number, line in enumerate(handle, start=1):
            row = json.loads(line)
            if int(row.get("label", -1)) not in (0, 1):
                continue
            row["_subset"] = subset
            row["_source_file"] = path.name
            row["_line_number"] = line_number
            yield row


def sample_rows(dataset_dir: Path, sample_size: int, seed: int) -> list[dict]:
    paths = dataset_paths(dataset_dir)
    if not paths:
        return []
    rng = random.Random(seed)
    rng.shuffle(paths)
    quota = max(1, math.ceil(sample_size / len(paths)))
    rows: list[dict] = []
    for path in paths:
        taken = 0
        for row in iter_rows_from_path(path):
            rows.append(row)
            taken += 1
            if len(rows) >= sample_size or taken >= quota:
                break
        if len(rows) >= sample_size:
            break
    return rows[:sample_size]


def histogram_stats(row: dict) -> dict:
    counts = np.asarray(row["histogram"], dtype=np.float32)
    total = float(counts.sum()) or 1.0
    probs = counts / total
    nonzero = probs[probs > 0]
    entropy = float(-(nonzero * np.log2(nonzero)).sum()) if len(nonzero) else 0.0
    printable = counts[0x20:0x7F].sum() + counts[0x09]
    ascii_bytes = counts[:128].sum()
    high_bytes = counts[128:].sum()
    return {
        "total": total,
        "entropy": entropy,
        "unique_ratio": float((counts > 0).sum() / 256.0),
        "null_ratio": float(counts[0] / total),
        "printable_ratio": float(printable / total),
        "ascii_ratio": float(ascii_bytes / total),
        "high_ratio": float(high_bytes / total),
        "byte_hist_32": [float(counts[i * 8 : (i + 1) * 8].sum() / total) for i in range(32)],
    }


def normalized_byteentropy(row: dict) -> list[float]:
    values = np.asarray(row["byteentropy"], dtype=np.float32)
    total = float(values.sum()) or 1.0
    return [float(item / total) for item in values]


def section_metrics(row: dict) -> dict:
    sections = row["section"]["sections"]
    entropies = [float(section.get("entropy", 0.0)) for section in sections]
    suspicious_names = sum(
        1
        for section in sections
        if str(section.get("name", "")).strip().lower() in SUSPICIOUS_SECTION_NAMES
    )
    executable = sum(1 for section in sections if "MEM_EXECUTE" in section.get("props", []))
    writable = sum(1 for section in sections if "MEM_WRITE" in section.get("props", []))
    zero_size = sum(1 for section in sections if int(section.get("size", 0)) == 0)
    return {
        "num_sections": len(sections),
        "executable_sections": executable,
        "writable_sections": writable,
        "zero_raw_sections": zero_size,
        "suspicious_section_names": suspicious_names,
        "section_entropy_mean": float(sum(entropies) / len(entropies)) if entropies else 0.0,
        "section_entropy_max": float(max(entropies)) if entropies else 0.0,
        "high_entropy_sections": sum(1 for value in entropies if value > 0.8),
    }


def import_metrics(row: dict) -> dict:
    imports = row["imports"]
    module_names = [str(module).split(".", 1)[0].lower() for module in imports.keys()]
    import_functions = sum(len(functions) for functions in imports.values())
    suspicious = sum(1 for module in module_names if module in SUSPICIOUS_IMPORT_MODULES)
    network = sum(1 for module in module_names if module in NETWORK_IMPORT_MODULES)
    process = sum(1 for module in module_names if module in PROCESS_IMPORT_MODULES)
    return {
        "import_descriptors": len(imports),
        "import_functions": import_functions,
        "suspicious_imports": suspicious,
        "network_import_modules": network,
        "process_import_modules": process,
    }


def data_directory_map(row: dict) -> dict:
    mapping = {name: {"size": 0, "virtual_address": 0} for name in EMBER_DATA_DIRECTORY_NAMES}
    for item in row["datadirectories"]:
        mapping[item["name"]] = {
            "size": int(item.get("size", 0)),
            "virtual_address": int(item.get("virtual_address", 0)),
        }
    return mapping


def approximate_header_anomaly(row: dict, section_count: int) -> float:
    anomaly_points = 0.0
    header = row["header"]
    magic = header["optional"].get("magic", "")
    if section_count == 0 or section_count > 96:
        anomaly_points += 1.0
    if magic not in {"PE32", "PE32_PLUS"}:
        anomaly_points += 1.0
    if not row["datadirectories"] or len(row["datadirectories"]) < 10:
        anomaly_points += 0.5
    entry_name = str(row["section"].get("entry", "")).strip()
    if not entry_name:
        anomaly_points += 0.5
    if row["general"].get("imports", 0) == 0 and row.get("imports"):
        anomaly_points += 0.5
    if header["optional"].get("sizeof_headers", 0) <= 0:
        anomaly_points += 0.5
    return min(1.0, anomaly_points / 4.0)


def normalize_string_value(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\x00", " ").strip().lower()).strip()


def metadata_string_items(row: dict) -> list[str]:
    values: list[str] = []
    section = row.get("section", {})
    entry_name = normalize_string_value(str(section.get("entry", "")))
    if entry_name:
        values.append(entry_name)

    for item in section.get("sections", []):
        name = normalize_string_value(str(item.get("name", "")))
        if len(name) >= STRING_MIN_LEN:
            values.append(name)

    for module_name, functions in row.get("imports", {}).items():
        module_text = normalize_string_value(str(module_name))
        if len(module_text) >= STRING_MIN_LEN:
            values.append(module_text)
        for function_name in functions:
            function_text = normalize_string_value(str(function_name))
            if len(function_text) >= STRING_MIN_LEN:
                values.append(function_text)

    for export_name in row.get("exports", []):
        export_text = normalize_string_value(str(export_name))
        if len(export_text) >= STRING_MIN_LEN:
            values.append(export_text)
    return values


STRING_MIN_LEN = 4

SUSPICIOUS_METADATA_TOKENS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "base64",
    "invoke-",
    "virtualalloc",
    "loadlibrary",
    "iex",
    "downloadstring",
    "webclient",
    "new-object",
]


def approximate_string_patterns(row: dict, strings: dict) -> tuple[list[float], list[str], dict]:
    items = metadata_string_items(row)
    denominator = max(int(strings.get("numstrings", 0)), 1)
    url_ratio = ratio(strings.get("urls", 0), max(strings.get("numstrings", 0), 1))
    path_ratio = ratio(strings.get("paths", 0), max(strings.get("numstrings", 0), 1))
    registry_ratio = ratio(strings.get("registry", 0), max(strings.get("numstrings", 0), 1))
    mz_ratio = ratio(strings.get("MZ", 0), max(strings.get("numstrings", 0), 1))

    values: list[float] = []
    approximated: list[str] = []
    for index, pattern in enumerate(PROJECTX_PATTERN_NAMES):
        metadata_hits = sum(1 for item in items if pattern in item)
        metadata_ratio = metadata_hits / denominator
        value = metadata_ratio
        if pattern == "http":
            value = max(value, url_ratio)
        elif pattern == "https":
            value = max(value, url_ratio * 0.75)
        elif pattern == "url":
            value = max(value, url_ratio)
        elif pattern == "web":
            value = max(value, url_ratio, metadata_ratio)
        elif pattern == "path":
            value = max(value, path_ratio)
        elif pattern == "file":
            value = max(value, path_ratio, metadata_ratio)
        elif pattern in {"cmd", "powershell", "shell", "macro", "vba", "vb", "net", "exe", "dll"}:
            value = max(value, metadata_ratio)
        elif pattern == "address":
            value = max(value, registry_ratio * 0.5, metadata_ratio)
        elif pattern == "run":
            value = max(value, mz_ratio * 0.25, metadata_ratio)
        elif pattern == "open":
            value = max(value, registry_ratio * 0.25, metadata_ratio)
        values.append(float(min(1.0, value)))
        approximated.append(f"string_pattern_{index:02d}")
    known_max_len = max([len(item) for item in items], default=0)
    suspicious_metadata_hits = sum(
        1 for item in items if any(token in item for token in SUSPICIOUS_METADATA_TOKENS)
    )
    return values, approximated, {
        "metadata_string_count": len(items),
        "known_max_string_length": known_max_len,
        "suspicious_metadata_hits": suspicious_metadata_hits,
    }


def infer_alignment(values: list[int], default: int) -> int:
    candidates = [abs(value) for value in values if value and value > 0]
    if not candidates:
        return default
    current = candidates[0]
    for value in candidates[1:]:
        current = gcd(current, value)
    if current <= 0:
        return default
    supported = [256, 512, 1024, 2048, 4096, 8192]
    valid = [item for item in supported if current % item == 0 or item % current == 0]
    return max(valid) if valid else default


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def infer_file_alignment(row: dict) -> int:
    raw_sizes = [int(section.get("size", 0)) for section in row.get("section", {}).get("sections", [])]
    header_size = int(row["header"]["optional"].get("sizeof_headers", 0))
    return infer_alignment(raw_sizes + [header_size], 512)


def infer_section_alignment(row: dict) -> int:
    vsizes = [int(section.get("vsize", 0)) for section in row.get("section", {}).get("sections", [])]
    rvas = [int(item.get("virtual_address", 0)) for item in row.get("datadirectories", [])]
    return max(infer_alignment(vsizes + rvas, 4096), 512)


def estimate_raw_layout(row: dict) -> list[dict]:
    file_alignment = infer_file_alignment(row)
    header_end = align_up(int(row["header"]["optional"].get("sizeof_headers", 0)), file_alignment)
    cursor = max(header_end, file_alignment)
    estimated = []
    for section in row.get("section", {}).get("sections", []):
        raw_size = int(section.get("size", 0))
        start = cursor
        end = start + raw_size
        estimated.append({
            "name": normalize_string_value(str(section.get("name", ""))),
            "raw_start": start,
            "raw_end": end,
        })
        cursor = align_up(end, file_alignment)
    return estimated


def estimate_virtual_layout(row: dict) -> list[dict]:
    section_alignment = infer_section_alignment(row)
    cursor = section_alignment
    estimated = []
    for section in row.get("section", {}).get("sections", []):
        vsize = max(int(section.get("vsize", 0)), int(section.get("size", 0)))
        start = align_up(cursor, section_alignment)
        end = start + vsize
        estimated.append({
            "name": normalize_string_value(str(section.get("name", ""))),
            "virtual_start": start,
            "virtual_end": end,
        })
        cursor = end
    return estimated


def approximate_entrypoint_ratio(row: dict) -> float:
    total_vsize = max(float(row["general"].get("vsize", 0)), 1.0)
    entry_name = normalize_string_value(str(row.get("section", {}).get("entry", "")))
    for section in estimate_virtual_layout(row):
        if section["name"] == entry_name and entry_name:
            midpoint = section["virtual_start"] + ((section["virtual_end"] - section["virtual_start"]) * 0.5)
            return float(min(1.0, max(0.0, midpoint / total_vsize)))
    return 0.0


def approximate_overlay_ratio(row: dict) -> float:
    file_size = float(row["general"].get("size", 0))
    if file_size <= 0:
        return 0.0
    estimated_layout = estimate_raw_layout(row)
    estimated_end = max((item["raw_end"] for item in estimated_layout), default=0)
    if file_size <= estimated_end:
        return 0.0
    return float(min(1.0, max(0.0, (file_size - estimated_end) / file_size)))


def adapt_row(row: dict, mapping_spec_by_name: dict[str, dict]) -> dict:
    names = rust_portable_feature_names()
    vector = [0.0] * len(names)
    approx = []
    missing = []

    hist = histogram_stats(row)
    byteentropy = normalized_byteentropy(row)
    strings = row["strings"]
    general = row["general"]
    header = row["header"]
    sections = section_metrics(row)
    imports = import_metrics(row)
    data_dirs = data_directory_map(row)

    pattern_values, approximated_pattern_features, string_metadata = approximate_string_patterns(row, strings)
    suspicious_string_ratio = ratio(
        strings.get("urls", 0)
        + strings.get("paths", 0)
        + strings.get("registry", 0)
        + strings.get("MZ", 0)
        + string_metadata["suspicious_metadata_hits"],
        max(strings.get("numstrings", 0), 1),
    )
    known_string_max_len = max(
        int(round(float(strings.get("avlength", 0.0)))),
        int(string_metadata["known_max_string_length"]),
    )

    feature_values = {
        "size_log2": log2ish(general["size"]),
        "bytes_examined_log2": log2ish(general["size"]),
        "truncated_input": 0.0,
        "entropy": hist["entropy"],
        "unique_byte_ratio": hist["unique_ratio"],
        "null_byte_ratio": hist["null_ratio"],
        "printable_ratio": hist["printable_ratio"],
        "ascii_ratio": hist["ascii_ratio"],
        "high_byte_ratio": hist["high_ratio"],
        "longest_printable_run_ratio": ratio(known_string_max_len, max(general["size"], 1)),
        "string_count_log2": log2ish(strings["numstrings"]),
        "avg_string_len": float(strings["avlength"]),
        "max_string_len_log2": log2ish(known_string_max_len),
        "url_string_ratio": ratio(strings["urls"], max(strings["numstrings"], 1)),
        "path_string_ratio": ratio(strings["paths"], max(strings["numstrings"], 1)),
        "suspicious_string_ratio": min(1.0, suspicious_string_ratio),
        "mz_header": 1.0,
        "pe_valid": 1.0,
        "pe_is_64": 1.0 if header["optional"].get("magic") == "PE32_PLUS" else 0.0,
        "pe_is_dll": 1.0 if "DLL" in " ".join(header["coff"].get("characteristics", [])) else 0.0,
        "pe_num_sections": float(sections["num_sections"]),
        "pe_executable_sections": float(sections["executable_sections"]),
        "pe_writable_sections": float(sections["writable_sections"]),
        "pe_zero_raw_sections": float(sections["zero_raw_sections"]),
        "pe_suspicious_section_name_hits": float(sections["suspicious_section_names"]),
        "pe_import_descriptor_count": float(imports["import_descriptors"]),
        "pe_import_function_count_log2": log2ish(imports["import_functions"]),
        "pe_suspicious_import_count": float(imports["suspicious_imports"]),
        "pe_network_import_modules": float(imports["network_import_modules"]),
        "pe_process_import_modules": float(imports["process_import_modules"]),
        "pe_has_cert": 1.0 if data_dirs["CERTIFICATE_TABLE"]["size"] > 0 else 0.0,
        "pe_is_probably_packed": 1.0
        if sections["suspicious_section_names"] > 0 and imports["import_descriptors"] < 3
        else 0.0,
        "pe_has_exports": 1.0 if general["exports"] > 0 else 0.0,
        "pe_has_resources": float(general["has_resources"]),
        "pe_has_tls": float(general["has_tls"]),
        "pe_has_debug": float(general["has_debug"]),
        "pe_section_entropy_mean": float(sections["section_entropy_mean"]),
        "pe_section_entropy_max": float(sections["section_entropy_max"]),
        "pe_high_entropy_sections": float(sections["high_entropy_sections"]),
        "pe_entrypoint_ratio": approximate_entrypoint_ratio(row),
        "pe_image_size_log2": log2ish(general["vsize"]),
        "pe_overlay_ratio": approximate_overlay_ratio(row),
        "pe_header_anomaly_score": approximate_header_anomaly(row, sections["num_sections"]),
        "elf_header": 0.0,
        "pdf_header": 0.0,
        "zip_header": 0.0,
        "shebang_header": 0.0,
        "dos_stub_contains_message": 0.0,
    }

    for index in range(32):
        feature_values[f"byte_hist_{index:02d}"] = hist["byte_hist_32"][index]
    for index in range(50):
        feature_values[f"string_pattern_{index:02d}"] = pattern_values[index]
    for index in range(256):
        feature_values[f"byte_entropy_{index:02x}"] = byteentropy[index]

    for index, name in enumerate(names):
        vector[index] = float(feature_values.get(name, 0.0))
        status = mapping_spec_by_name[name]["status"]
        if status == "partial":
            approx.append(name)
        elif status == "missing_in_ember":
            missing.append(name)
    for name in approximated_pattern_features:
        if name not in approx:
            approx.append(name)

    sample_id = f"{row['sha256']}:{row['_source_file']}:{row['_line_number']}"
    return {
        "sample_id": sample_id,
        "sha256": row["sha256"],
        "source_label": int(row["label"]),
        "subset": row["_subset"],
        "feature_values": vector,
        "adapter_metadata": {
            "approximate_features": approx,
            "missing_features": missing,
            "string_fidelity_notes": [
                "string_pattern_* is normalized by EMBER strings.numstrings and limited to metadata strings actually likely to exist in PE bytes.",
                "longest_printable_run_ratio and max_string_len_log2 are lower-bound estimates from EMBER string statistics plus known import/export/section strings.",
            ],
            "pe_structural_fidelity_notes": [
                "pe_entrypoint_ratio uses alignment-aware estimated virtual layout rather than raw AddressOfEntryPoint bytes.",
                "pe_overlay_ratio uses alignment-aware estimated raw layout rather than simple summed section sizes.",
            ],
            "fidelity_counts": {
                "exact": sum(1 for item in mapping_spec_by_name.values() if item["status"] == "exact_match"),
                "high_fidelity_derived": sum(1 for item in mapping_spec_by_name.values() if item["status"] == "transformable_match"),
                "approximate": sum(1 for item in mapping_spec_by_name.values() if item["status"] == "partial"),
                "unrecoverable": sum(1 for item in mapping_spec_by_name.values() if item["status"] in {"missing_in_ember", "incompatible"}),
            },
            "approximate_feature_count": len(approx),
            "missing_feature_count": len(missing),
            "source_file": row["_source_file"],
            "source_line": row["_line_number"],
            "subset": row["_subset"],
            "avclass": row.get("avclass"),
        },
    }


def write_summary(summary_json: Path, summary_md: Path, rows: list[dict], mapping_spec: list[dict]) -> dict:
    counts = {}
    for item in mapping_spec:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    exact = counts.get("exact_match", 0)
    transformable = counts.get("transformable_match", 0)
    approximate = counts.get("partial", 0)
    missing = counts.get("missing_in_ember", 0) + counts.get("incompatible", 0)
    coverage = (exact + transformable + approximate) / len(mapping_spec)
    approximation_ratio = approximate / max(len(mapping_spec), 1)
    recommendation = (
        "safe for parity test"
        if coverage >= 0.95 and missing <= 5 and approximation_ratio <= 0.08
        else "not safe for parity test"
    )
    payload = {
        "total_samples_transformed": len(rows),
        "projectx_feature_count": len(mapping_spec),
        "feature_coverage_percentage": coverage * 100.0,
        "exact_mapped_fields": exact,
        "transformable_fields": transformable,
        "approximate_fields": approximate,
        "approximation_ratio": approximation_ratio,
        "missing_or_unrecoverable_fields": missing,
        "fidelity_counts": {
            "exact": exact,
            "high_fidelity_derived": transformable,
            "approximate": approximate,
            "unrecoverable": missing,
        },
        "recommendation": recommendation,
        "parity_risk_notes": [
            "ProjectX string_pattern_* features now use metadata strings likely present in PE bytes and are normalized by EMBER strings.numstrings, but they still do not preserve the full raw string corpus.",
            "ProjectX pe_entrypoint_ratio and pe_overlay_ratio now use alignment-aware estimated PE layout, but they are still not reconstructed from raw PE offsets.",
            "ProjectX longest_printable_run_ratio and max_string_len_log2 now use lower-bound derivations from EMBER string statistics plus known metadata strings.",
            "ProjectX dos_stub_contains_message remains unrecoverable from EMBER raw rows.",
            "ProjectX pe_header_anomaly_score and some import-descriptor semantics remain approximate on EMBER raw rows.",
        ],
    }
    summary_json.write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Adapter Summary",
        "",
        f"- Total samples transformed: {payload['total_samples_transformed']}",
        f"- Feature coverage percentage: {payload['feature_coverage_percentage']:.2f}",
        f"- Exact-mapped fields: {payload['exact_mapped_fields']}",
        f"- Transformable fields: {payload['transformable_fields']}",
        f"- Approximate fields: {payload['approximate_fields']}",
        f"- Approximation ratio: {payload['approximation_ratio']:.4f}",
        f"- Missing/unrecoverable fields: {payload['missing_or_unrecoverable_fields']}",
        f"- Recommendation: {payload['recommendation']}",
        "",
        "## Parity Risk Notes",
        "",
    ]
    for note in payload["parity_risk_notes"]:
        lines.append(f"- {note}")
    lines.append("")
    summary_md.write_text("\n".join(lines))
    return payload


def main() -> int:
    args = parse_args()
    dataset_dir = Path(args.dataset_dir)
    rows = sample_rows(dataset_dir, args.sample_size, args.seed)
    mapping_spec = projectx_portable_mapping_spec()
    mapping_spec_by_name = {item["projectx_feature"]: item for item in mapping_spec}
    output_jsonl = Path(args.output_jsonl)
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)

    adapted = [adapt_row(row, mapping_spec_by_name) for row in rows]
    with output_jsonl.open("w") as handle:
        for record in adapted:
            handle.write(json.dumps(record) + "\n")

    write_summary(Path(args.summary_json), Path(args.summary_md), adapted, mapping_spec)
    print(output_jsonl)
    print(args.summary_json)
    print(args.summary_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
