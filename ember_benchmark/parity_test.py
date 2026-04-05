#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import subprocess
from pathlib import Path

import numpy as np

from projectx_ember_adapter import main as adapter_main
from projectx_ember_schema import ARTIFACTS_DIR, load_projectx_embedded_model_from_rust_source, projectx_portable_mapping_spec, sigmoid


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a small-scale Python-vs-Rust parity test on adapted EMBER rows.")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--sample-size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--projectx-bin", default=str(Path("target/debug/ProjectX")))
    return parser.parse_args()


def classify(score: float, model: dict) -> str:
    if score >= model["malicious_threshold"]:
        return "malicious"
    if score >= model["suspicious_threshold"]:
        return "suspicious"
    return "clean"


def python_score_rows(records: list[dict], model: dict) -> list[dict]:
    weights = np.asarray(model["weights"], dtype=np.float32)
    outputs = []
    for record in records:
        values = np.asarray(record["feature_values"], dtype=np.float32)
        score = float(sigmoid(float(model["intercept"] + float(np.dot(weights, values)))))
        outputs.append(
            {
                "sample_id": record["sample_id"],
                "score": score,
                "label": classify(score, model),
            }
        )
    return outputs


def run_rust_scoring(projectx_bin: Path, input_jsonl: Path, output_jsonl: Path) -> None:
    command = [str(projectx_bin), "--score-features-jsonl", str(input_jsonl)]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    output_jsonl.write_text(result.stdout)


def load_jsonl(path: Path) -> list[dict]:
    with path.open() as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build_failure_analysis(parity_payload: dict, mapping_spec: list[dict]) -> dict:
    missing = [item["projectx_feature"] for item in mapping_spec if item["status"] == "missing_in_ember"]
    approximate = [item["projectx_feature"] for item in mapping_spec if item["status"] == "partial"]
    payload = {
        "true_100k_rust_parity_possible_now": False,
        "feature_gaps": {
            "missing_in_ember": missing,
            "approximate": approximate,
        },
        "recommended_next_implementation_order": [
            "Replace string-pattern approximations with a raw-string-preserving benchmark source if true ProjectX string semantics are required.",
            "Replace section-order PE approximations with entrypoint and overlay values sourced from raw PE offsets or a richer benchmark corpus.",
            "Decide whether ProjectX wants to adopt EMBER-style hashed PE structure features or keep the current portable schema intentionally narrower.",
            "Only after feature-gap risk is reduced should scaled adapted benchmarks be treated as parity candidates.",
        ],
        "code_locations_to_improve": [
            "src/ml/portable_features.rs",
            "ember_benchmark/projectx_ember_adapter.py",
            "ember_benchmark/ember_repo/ember/features.py",
        ],
        "parity_recommendation": parity_payload["recommendation"],
    }
    return payload


def main() -> int:
    args = parse_args()
    projectx_bin = Path(args.projectx_bin)
    if not projectx_bin.exists():
        subprocess.run(["cargo", "build"], check=True)

    input_jsonl = ARTIFACTS_DIR / "adapter_output.jsonl"
    summary_json = ARTIFACTS_DIR / "adapter_summary.json"
    summary_md = ARTIFACTS_DIR / "adapter_summary.md"
    subprocess.run(
        [
            "python3",
            str(Path(__file__).resolve().parent / "projectx_ember_adapter.py"),
            "--dataset-dir",
            args.dataset_dir,
            "--sample-size",
            str(args.sample_size),
            "--seed",
            str(args.seed),
            "--output-jsonl",
            str(input_jsonl),
            "--summary-json",
            str(summary_json),
            "--summary-md",
            str(summary_md),
        ],
        check=True,
    )

    records = load_jsonl(input_jsonl)
    model = load_projectx_embedded_model_from_rust_source()
    python_scores = python_score_rows(records, model)
    rust_output_jsonl = ARTIFACTS_DIR / "rust_parity_scores.jsonl"
    run_rust_scoring(projectx_bin, input_jsonl, rust_output_jsonl)
    rust_scores = load_jsonl(rust_output_jsonl)

    python_by_id = {item["sample_id"]: item for item in python_scores}
    rust_by_id = {item["sample_id"]: item for item in rust_scores}
    paired = [
        (python_by_id[sample_id], rust_by_id[sample_id], record)
        for sample_id, record in ((record["sample_id"], record) for record in records)
        if sample_id in python_by_id and sample_id in rust_by_id
    ]
    py_values = np.asarray([left["score"] for left, _, _ in paired], dtype=np.float64)
    rust_values = np.asarray([right["score"] for _, right, _ in paired], dtype=np.float64)
    drifts = np.abs(py_values - rust_values)
    correlation = float(np.corrcoef(py_values, rust_values)[0, 1]) if len(py_values) > 1 else 1.0
    label_matches = sum(1 for left, right, _ in paired if left["label"] == right["label"])
    clean_total = sum(1 for left, _, _ in paired if left["label"] == "clean")
    suspicious_total = sum(1 for left, _, _ in paired if left["label"] == "suspicious")
    malicious_total = sum(1 for left, _, _ in paired if left["label"] == "malicious")
    clean_agreement = ratio_count(paired, "clean", clean_total)
    suspicious_agreement = ratio_count(paired, "suspicious", suspicious_total)
    malicious_agreement = ratio_count(paired, "malicious", malicious_total)

    mapping_spec = projectx_portable_mapping_spec()
    adapter_summary = json.loads(summary_json.read_text())
    coverage_ratio = adapter_summary["feature_coverage_percentage"] / 100.0
    approximate_ratio = adapter_summary["approximate_fields"] / max(adapter_summary["projectx_feature_count"], 1)
    if coverage_ratio < 0.95 or adapter_summary["missing_or_unrecoverable_fields"] > 5 or approximate_ratio > 0.08:
        recommendation = "parity invalid"
    elif label_matches / max(len(paired), 1) < 0.99 or float(drifts.mean()) > 1e-5:
        recommendation = "parity weak"
    else:
        recommendation = "parity acceptable"

    mismatch_clusters = {}
    for left, right, record in paired:
        key = f"{left['label']} -> {right['label']}"
        mismatch_clusters[key] = mismatch_clusters.get(key, 0) + int(left["label"] != right["label"])

    payload = {
        "sample_count": len(paired),
        "benchmark_label": "NOT Rust-parity" if recommendation != "parity acceptable" else "ProjectX-adapted parity benchmark",
        "label_agreement_percentage": 100.0 * label_matches / max(len(paired), 1),
        "malicious_agreement_percentage": malicious_agreement,
        "suspicious_agreement_percentage": suspicious_agreement,
        "clean_agreement_percentage": clean_agreement,
        "correlation_coefficient": correlation,
        "mean_score_drift": float(drifts.mean()) if len(drifts) else 0.0,
        "max_score_drift": float(drifts.max()) if len(drifts) else 0.0,
        "top_mismatch_clusters": sorted(mismatch_clusters.items(), key=lambda item: item[1], reverse=True)[:10],
        "recommendation": recommendation,
        "adapter_coverage_percentage": adapter_summary["feature_coverage_percentage"],
        "fidelity_counts": adapter_summary.get("fidelity_counts"),
        "parity_confidence": "low" if recommendation == "parity invalid" else ("medium" if recommendation == "parity weak" else "high"),
        "missing_feature_risk": "high" if recommendation == "parity invalid" else "moderate",
        "approximation_ratio": approximate_ratio,
    }
    json_path = ARTIFACTS_DIR / "parity_test.json"
    md_path = ARTIFACTS_DIR / "parity_test.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Parity Test",
        "",
        f"- Sample count: {payload['sample_count']}",
        f"- Benchmark label: {payload['benchmark_label']}",
        f"- Label agreement %: {payload['label_agreement_percentage']:.6f}",
        f"- Malicious agreement %: {payload['malicious_agreement_percentage']:.6f}",
        f"- Suspicious agreement %: {payload['suspicious_agreement_percentage']:.6f}",
        f"- Clean agreement %: {payload['clean_agreement_percentage']:.6f}",
        f"- Correlation coefficient: {payload['correlation_coefficient']:.8f}",
        f"- Mean score drift: {payload['mean_score_drift']:.10f}",
        f"- Max score drift: {payload['max_score_drift']:.10f}",
        f"- Adapter coverage %: {payload['adapter_coverage_percentage']:.2f}",
        f"- Fidelity counts: {payload['fidelity_counts']}",
        f"- Recommendation: {payload['recommendation']}",
        "",
        "## Top Mismatch Clusters",
        "",
    ]
    for key, count in payload["top_mismatch_clusters"]:
        lines.append(f"- {key}: {count}")
    lines.append("")
    md_path.write_text("\n".join(lines))

    failure_payload = build_failure_analysis(payload, mapping_spec)
    (ARTIFACTS_DIR / "failure_analysis.json").write_text(json.dumps(failure_payload, indent=2) + "\n")
    failure_lines = [
        "# Failure Analysis",
        "",
        f"- True 100k Rust-parity benchmark possible now: {failure_payload['true_100k_rust_parity_possible_now']}",
        f"- Parity recommendation: {failure_payload['parity_recommendation']}",
        "",
        "## Concrete Feature Gaps",
        "",
    ]
    for name in failure_payload["feature_gaps"]["missing_in_ember"][:20]:
        failure_lines.append(f"- Missing in EMBER adaptation: `{name}`")
    for name in failure_payload["feature_gaps"]["approximate"][:20]:
        failure_lines.append(f"- Approximate only: `{name}`")
    failure_lines.extend(["", "## Recommended Next Implementation Order", ""])
    for item in failure_payload["recommended_next_implementation_order"]:
        failure_lines.append(f"- {item}")
    failure_lines.extend(["", "## Code Locations", ""])
    for item in failure_payload["code_locations_to_improve"]:
        failure_lines.append(f"- {item}")
    failure_lines.append("")
    (ARTIFACTS_DIR / "failure_analysis.md").write_text("\n".join(failure_lines))

    print(json_path)
    print(md_path)
    return 0


def ratio_count(paired: list[tuple[dict, dict, dict]], label: str, total: int) -> float:
    if total == 0:
        return 100.0
    matches = sum(1 for left, right, _ in paired if left["label"] == label and right["label"] == label)
    return 100.0 * matches / total


if __name__ == "__main__":
    raise SystemExit(main())
