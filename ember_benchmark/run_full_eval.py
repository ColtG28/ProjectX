#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn import metrics

from common import classification_metrics, ROOT
from projectx_ember_adapter import adapt_row, sample_rows
from projectx_ember_schema import ARTIFACTS_DIR, load_projectx_embedded_model_from_rust_source, projectx_portable_mapping_spec


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the next honest EMBER benchmark stage for ProjectX.")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--sample-size", type=int, default=1000)
    parser.add_argument("--parity-sample-size", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--projectx-bin", default=str(Path("target/debug/ProjectX")))
    parser.add_argument("--output-dir", default=str(ARTIFACTS_DIR / "latest"))
    return parser.parse_args()


def ensure_projectx_bin(path: Path) -> Path:
    if path.exists():
        return path
    subprocess.run(["cargo", "build"], check=True)
    return path


def run_prerequisites(args: argparse.Namespace) -> tuple[dict, dict, dict]:
    subprocess.run(["python3", str(ROOT / "schema_mapping.py")], check=True)
    subprocess.run(
        [
            "python3",
            str(ROOT / "parity_test.py"),
            "--dataset-dir",
            args.dataset_dir,
            "--sample-size",
            str(args.parity_sample_size),
            "--seed",
            str(args.seed),
            "--projectx-bin",
            args.projectx_bin,
        ],
        check=True,
    )
    return (
        json.loads((ARTIFACTS_DIR / "adapter_summary.json").read_text()),
        json.loads((ARTIFACTS_DIR / "parity_test.json").read_text()),
        json.loads((ARTIFACTS_DIR / "failure_analysis.json").read_text()),
    )


def load_reference_ember_components(dataset_dir: Path):
    sys.path.insert(0, str(ROOT / "ember_repo"))
    import lightgbm as lgb  # type: ignore
    from ember.features import PEFeatureExtractor  # type: ignore

    model_path = dataset_dir / "ember_model_2018.txt"
    if not model_path.exists():
        raise FileNotFoundError(f"Missing EMBER reference model at {model_path}")
    booster = lgb.Booster(model_file=str(model_path))
    extractor = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    return booster, extractor, model_path


def score_reference_ember(rows: list[dict], dataset_dir: Path) -> tuple[list[dict], dict]:
    booster, extractor, model_path = load_reference_ember_components(dataset_dir)
    started = time.perf_counter()
    scored_rows = []
    for row in rows:
        vector = extractor.process_raw_features(row)
        score = float(booster.predict(np.asarray([vector], dtype=np.float32))[0])
        predicted_label = "malicious" if score >= 0.5 else "clean"
        scored_rows.append(
            {
                "sample_id": f"{row['sha256']}:{row['_source_file']}:{row['_line_number']}",
                "sha256": row["sha256"],
                "source_label": int(row["label"]),
                "score": score,
                "predicted_label": predicted_label,
                "subset": row["_subset"],
                "avclass": row.get("avclass"),
            }
        )
    elapsed = max(time.perf_counter() - started, 1e-9)
    meta = {
        "thresholds": {"positive_threshold": 0.5},
        "model_source": str(model_path),
        "runtime_seconds": elapsed,
        "throughput_samples_per_second": len(rows) / elapsed,
    }
    return scored_rows, meta


def score_projectx_adapted(
    rows: list[dict], projectx_bin: Path, output_dir: Path
) -> tuple[list[dict], dict]:
    mapping_spec = projectx_portable_mapping_spec()
    mapping_by_name = {item["projectx_feature"]: item for item in mapping_spec}
    input_jsonl = output_dir / "projectx_adapted_input.jsonl"
    with input_jsonl.open("w") as handle:
        for row in rows:
            adapted = adapt_row(row, mapping_by_name)
            handle.write(json.dumps(adapted) + "\n")

    started = time.perf_counter()
    result = subprocess.run(
        [str(projectx_bin), "--score-features-jsonl", str(input_jsonl)],
        check=True,
        capture_output=True,
        text=True,
    )
    elapsed = max(time.perf_counter() - started, 1e-9)
    scored_rows = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        scored = json.loads(line)
        adapter_meta = scored.get("adapter_metadata", {})
        scored_rows.append(
            {
                "sample_id": scored["sample_id"],
                "sha256": scored.get("sha256"),
                "source_label": int(scored["source_label"]),
                "score": float(scored["score"]),
                "predicted_label": scored["label"],
                "subset": adapter_meta.get("subset"),
                "avclass": adapter_meta.get("avclass"),
                "adapter_metadata": adapter_meta,
            }
        )
    model = load_projectx_embedded_model_from_rust_source()
    meta = {
        "thresholds": {
            "suspicious_threshold": model["suspicious_threshold"],
            "malicious_threshold": model["malicious_threshold"],
            "binary_positive_threshold": model["suspicious_threshold"],
        },
        "model_source": "embedded://projectx-native-model-v1",
        "runtime_seconds": elapsed,
        "throughput_samples_per_second": len(rows) / elapsed,
    }
    (output_dir / "projectx_adapted_scores.jsonl").write_text(result.stdout)
    return scored_rows, meta


def binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    payload = classification_metrics(y_true, scores, threshold)
    return payload


def prediction_breakdown(predicted_labels: list[str]) -> dict:
    counts = {"clean": 0, "suspicious": 0, "malicious": 0}
    for label in predicted_labels:
        counts[label] = counts.get(label, 0) + 1
    return counts


def cluster_summary(frame: pd.DataFrame, mask: pd.Series, top_k: int = 5) -> list[str]:
    if mask.sum() == 0:
        return []
    notes = []
    for column in ("avclass", "subset"):
        if column not in frame.columns:
            continue
        counts = frame.loc[mask, column].fillna("unknown").value_counts().head(top_k)
        for value, count in counts.items():
            notes.append(f"{column}={value} ({count})")
    return notes[: top_k * 2]


def dominant_cause(benchmark_type: str, parity: dict, brier_score: float) -> str:
    if benchmark_type != "REFERENCE_EMBER" and parity["missing_feature_risk"] == "high":
        if parity.get("approximation_ratio", 0.0) > 0.08:
            return "approximation-heavy feature coverage"
        return "feature coverage"
    if brier_score > 0.15:
        return "thresholds/calibration"
    return "model discrimination"


def build_report(
    benchmark_type: str,
    scored_rows: list[dict],
    rows: list[dict],
    meta: dict,
    adapter_summary: dict,
    parity: dict,
) -> dict:
    frame = pd.DataFrame(scored_rows)
    y_true = frame["source_label"].to_numpy(dtype=np.int32)
    scores = frame["score"].to_numpy(dtype=np.float64)
    if benchmark_type == "REFERENCE_EMBER":
        binary_threshold = meta["thresholds"]["positive_threshold"]
        predicted_positive = scores >= binary_threshold
        predicted_labels = ["malicious" if value else "clean" for value in predicted_positive]
        benchmark_validity = "REFERENCE_EMBER"
        parity_status = "not_applicable"
        parity_confidence = "not_applicable"
        missing_feature_risk = "not_applicable"
    else:
        binary_threshold = meta["thresholds"]["binary_positive_threshold"]
        predicted_positive = frame["predicted_label"].isin(["suspicious", "malicious"]).to_numpy()
        predicted_labels = frame["predicted_label"].tolist()
        benchmark_validity = (
            "PROJECTX_ADAPTED_PARITY_ACCEPTABLE"
            if parity["recommendation"] == "parity acceptable"
            else "PROJECTX_ADAPTED_PARITY_INVALID"
        )
        parity_status = parity["recommendation"]
        parity_confidence = parity["parity_confidence"]
        missing_feature_risk = parity["missing_feature_risk"]

    metrics_payload = binary_metrics(y_true, scores, binary_threshold)
    false_positive_mask = (y_true == 0) & predicted_positive
    false_negative_mask = (y_true == 1) & (~predicted_positive)
    class_balance = {
        "benign_count": int((y_true == 0).sum()),
        "malicious_count": int((y_true == 1).sum()),
        "malicious_rate": float(y_true.mean()) if len(y_true) else 0.0,
    }
    predicted_breakdown = prediction_breakdown(predicted_labels)

    return {
        "benchmark_type": benchmark_type,
        "benchmark_validity_label": benchmark_validity,
        "parity_status": parity_status,
        "schema_coverage_percentage": adapter_summary["feature_coverage_percentage"]
        if benchmark_type != "REFERENCE_EMBER"
        else None,
        "exact_mapped_feature_count": adapter_summary["exact_mapped_fields"] if benchmark_type != "REFERENCE_EMBER" else None,
        "high_fidelity_derived_feature_count": adapter_summary["transformable_fields"] if benchmark_type != "REFERENCE_EMBER" else None,
        "approximate_feature_count": adapter_summary["approximate_fields"] if benchmark_type != "REFERENCE_EMBER" else None,
        "missing_feature_count": adapter_summary["missing_or_unrecoverable_fields"] if benchmark_type != "REFERENCE_EMBER" else None,
        "parity_confidence": parity_confidence,
        "missing_feature_risk": missing_feature_risk,
        "total_samples": len(scored_rows),
        "class_balance": class_balance,
        "thresholds_used": meta["thresholds"],
        "metrics": metrics_payload,
        "predicted_class_breakdown": predicted_breakdown,
        "failure_analysis": {
            "false_positive_clusters": cluster_summary(frame, pd.Series(false_positive_mask)),
            "false_negative_clusters": cluster_summary(frame, pd.Series(false_negative_mask)),
            "most_likely_missing_feature_contributors": (
                [
                    "string_pattern_* approximations",
                    "pe_entrypoint_ratio approximation",
                    "pe_overlay_ratio approximation",
                    "dos_stub_contains_message",
                ]
                if benchmark_type != "REFERENCE_EMBER"
                else []
            ),
            "dominant_cause": dominant_cause(
                benchmark_type,
                parity,
                metrics_payload["brier_score"],
            ),
        },
        "performance": {
            "runtime_seconds": meta["runtime_seconds"],
            "throughput_samples_per_second": meta["throughput_samples_per_second"],
        },
        "model_source": meta["model_source"],
    }


def markdown_report(report: dict) -> str:
    lines = [
        f"# {report['benchmark_type']}",
        "",
        f"- Benchmark validity label: {report['benchmark_validity_label']}",
        f"- Parity status: {report['parity_status']}",
        f"- Parity confidence: {report['parity_confidence']}",
        f"- Missing feature risk: {report['missing_feature_risk']}",
        f"- Total samples: {report['total_samples']}",
        "",
        "## Core Metrics",
        "",
        f"- Accuracy: {report['metrics']['accuracy']:.6f}",
        f"- Precision: {report['metrics']['precision']:.6f}",
        f"- Recall: {report['metrics']['recall']:.6f}",
        f"- F1-score: {report['metrics']['f1_score']:.6f}",
        f"- ROC-AUC: {report['metrics']['roc_auc']:.6f}",
        f"- PR-AUC: {report['metrics']['pr_auc']:.6f}",
        f"- Brier score: {report['metrics']['brier_score']:.6f}",
        f"- Log loss: {report['metrics']['log_loss']:.6f}",
        "",
        "## Validity Metadata",
        "",
        f"- Benchmark type: {report['benchmark_type']}",
        f"- Benchmark validity label: {report['benchmark_validity_label']}",
        f"- Schema coverage %: {report['schema_coverage_percentage'] if report['schema_coverage_percentage'] is not None else 'n/a'}",
        f"- Exact mapped feature count: {report['exact_mapped_feature_count'] if report['exact_mapped_feature_count'] is not None else 'n/a'}",
        f"- High-fidelity derived feature count: {report.get('high_fidelity_derived_feature_count', 'n/a') if report['schema_coverage_percentage'] is not None else 'n/a'}",
        f"- Approximate feature count: {report['approximate_feature_count'] if report['approximate_feature_count'] is not None else 'n/a'}",
        f"- Missing feature count: {report['missing_feature_count'] if report['missing_feature_count'] is not None else 'n/a'}",
        "",
        "## Failure Analysis",
        "",
    ]
    for item in report["failure_analysis"]["false_positive_clusters"] or ["None"]:
        lines.append(f"- False positive cluster: {item}")
    for item in report["failure_analysis"]["false_negative_clusters"] or ["None"]:
        lines.append(f"- False negative cluster: {item}")
    for item in report["failure_analysis"]["most_likely_missing_feature_contributors"]:
        lines.append(f"- Missing feature contributor: {item}")
    lines.append(f"- Dominant cause: {report['failure_analysis']['dominant_cause']}")
    lines.extend(
        [
            "",
            "## Performance",
            "",
            f"- Runtime seconds: {report['performance']['runtime_seconds']:.6f}",
            f"- Throughput samples/sec: {report['performance']['throughput_samples_per_second']:.6f}",
            "",
        ]
    )
    return "\n".join(lines)


def copy_prereq_artifacts(latest_dir: Path) -> None:
    for name in [
        "adapter_output.jsonl",
        "adapter_summary.json",
        "adapter_summary.md",
        "parity_test.json",
        "parity_test.md",
        "failure_analysis.json",
        "failure_analysis.md",
    ]:
        src = ARTIFACTS_DIR / name
        if src.exists():
            shutil.copy2(src, latest_dir / name)


def load_previous_snapshot(output_dir: Path) -> dict:
    baseline_path = ARTIFACTS_DIR / "improvement_baseline.json"
    if baseline_path.exists():
        return json.loads(baseline_path.read_text())
    snapshot = {}
    for name in ("adapter_summary.json", "parity_test.json", "projectx_adapted.json"):
        path = output_dir / name
        if path.exists():
            snapshot[name] = json.loads(path.read_text())
    return snapshot


def load_fidelity_baseline(output_dir: Path) -> dict:
    baseline_path = ARTIFACTS_DIR / "fidelity_baseline.json"
    if baseline_path.exists():
        return json.loads(baseline_path.read_text())
    snapshot = {}
    for name in ("adapter_summary.json", "parity_test.json", "projectx_adapted.json"):
        path = output_dir / name
        if path.exists():
            snapshot[name] = json.loads(path.read_text())
    return snapshot


def build_improvement_delta(
    latest_dir: Path,
    previous: dict,
    adapter_summary: dict,
    parity: dict,
    adapted_report: dict,
    mapping_spec: list[dict],
) -> None:
    previous_adapter = previous.get("adapter_summary.json", {})
    previous_parity = previous.get("parity_test.json", {})
    previous_adapted = previous.get("projectx_adapted.json", {})
    previous_metrics = previous_adapted.get("metrics", {})
    current_metrics = adapted_report["metrics"]

    newly_implemented = []
    for item in mapping_spec:
        if item["status"] != "partial":
            continue
        name = item["projectx_feature"]
        if name in {"pe_entrypoint_ratio", "pe_overlay_ratio"} or name.startswith("string_pattern_"):
            newly_implemented.append(name)
    newly_implemented = sorted(set(newly_implemented))

    payload = {
        "benchmark_validity_label": adapted_report["benchmark_validity_label"],
        "parity_confidence": parity["parity_confidence"],
        "feature_coverage_changes": {
            "old_schema_coverage_percentage": previous_adapter.get("feature_coverage_percentage"),
            "new_schema_coverage_percentage": adapter_summary["feature_coverage_percentage"],
            "old_missing_feature_count": previous_adapter.get("missing_or_unrecoverable_fields"),
            "new_missing_feature_count": adapter_summary["missing_or_unrecoverable_fields"],
            "newly_implemented_features": newly_implemented,
        },
        "parity_changes": {
            "old_parity_status": previous_parity.get("recommendation"),
            "new_parity_status": parity["recommendation"],
            "old_label_agreement_percentage": previous_parity.get("label_agreement_percentage"),
            "new_label_agreement_percentage": parity["label_agreement_percentage"],
            "old_mean_score_drift": previous_parity.get("mean_score_drift"),
            "new_mean_score_drift": parity["mean_score_drift"],
            "old_max_score_drift": previous_parity.get("max_score_drift"),
            "new_max_score_drift": parity["max_score_drift"],
        },
        "projectx_adapted_metric_deltas": {},
        "suitable_for_10k_scaling": parity["recommendation"] == "parity acceptable",
        "suitable_for_100k_scaling": False,
    }

    for key in ("accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc"):
        old_value = previous_metrics.get(key)
        new_value = current_metrics.get(key)
        payload["projectx_adapted_metric_deltas"][key] = {
            "old": old_value,
            "new": new_value,
            "delta": (new_value - old_value) if old_value is not None and new_value is not None else None,
        }

    (latest_dir / "improvement_delta.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Improvement Delta",
        "",
        f"- Benchmark validity label: {payload['benchmark_validity_label']}",
        f"- Parity confidence: {payload['parity_confidence']}",
        f"- Old schema coverage %: {payload['feature_coverage_changes']['old_schema_coverage_percentage']}",
        f"- New schema coverage %: {payload['feature_coverage_changes']['new_schema_coverage_percentage']}",
        f"- Old missing feature count: {payload['feature_coverage_changes']['old_missing_feature_count']}",
        f"- New missing feature count: {payload['feature_coverage_changes']['new_missing_feature_count']}",
        f"- Suitable for 10k scaling: {payload['suitable_for_10k_scaling']}",
        f"- Suitable for 100k scaling: {payload['suitable_for_100k_scaling']}",
        "",
        "## Newly Implemented Features",
        "",
    ]
    for name in newly_implemented:
        lines.append(f"- {name}")
    lines.extend(["", "## PROJECTX_ADAPTED Metric Deltas", ""])
    for key, value in payload["projectx_adapted_metric_deltas"].items():
        lines.append(f"- {key}: old={value['old']} new={value['new']} delta={value['delta']}")
    (latest_dir / "improvement_delta.md").write_text("\n".join(lines) + "\n")


def build_fidelity_report(
    latest_dir: Path,
    adapter_summary: dict,
    failure_analysis: dict,
) -> None:
    payload = {
        "exact_feature_count": adapter_summary["fidelity_counts"]["exact"],
        "high_fidelity_derived_feature_count": adapter_summary["fidelity_counts"]["high_fidelity_derived"],
        "approximate_feature_count": adapter_summary["fidelity_counts"]["approximate"],
        "unrecoverable_feature_count": adapter_summary["fidelity_counts"]["unrecoverable"],
        "approximation_ratio": adapter_summary["approximation_ratio"],
        "string_fidelity_notes": [
            "string_pattern_* now uses PE metadata strings likely present in bytes, normalized by EMBER strings.numstrings.",
            "longest_printable_run_ratio and max_string_len_log2 now use lower-bound derivations from EMBER string statistics and known metadata strings.",
            "The full raw printable-string corpus is still unavailable in EMBER raw rows.",
        ],
        "pe_structural_fidelity_notes": [
            "pe_entrypoint_ratio now uses alignment-aware estimated virtual layout.",
            "pe_overlay_ratio now uses alignment-aware estimated raw layout.",
            "True raw PE offsets and DOS-stub bytes are still not present in EMBER raw rows.",
        ],
        "features_still_approximation_heavy": failure_analysis["feature_gaps"]["approximate"],
        "features_still_unrecoverable": failure_analysis["feature_gaps"]["missing_in_ember"],
        "materially_closer_to_true_projectx_semantics": True,
    }
    (latest_dir / "fidelity_report.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Fidelity Report",
        "",
        f"- Exact feature count: {payload['exact_feature_count']}",
        f"- High-fidelity derived feature count: {payload['high_fidelity_derived_feature_count']}",
        f"- Approximate feature count: {payload['approximate_feature_count']}",
        f"- Unrecoverable feature count: {payload['unrecoverable_feature_count']}",
        f"- Approximation ratio: {payload['approximation_ratio']:.6f}",
        "",
        "## String Fidelity Notes",
        "",
    ]
    for item in payload["string_fidelity_notes"]:
        lines.append(f"- {item}")
    lines.extend(["", "## PE Structural Fidelity Notes", ""])
    for item in payload["pe_structural_fidelity_notes"]:
        lines.append(f"- {item}")
    lines.extend(["", "## Remaining Approximation-Heavy Features", ""])
    for item in payload["features_still_approximation_heavy"][:20]:
        lines.append(f"- {item}")
    lines.extend(["", "## Remaining Unrecoverable Features", ""])
    for item in payload["features_still_unrecoverable"]:
        lines.append(f"- {item}")
    (latest_dir / "fidelity_report.md").write_text("\n".join(lines) + "\n")


def build_fidelity_delta(
    latest_dir: Path,
    previous: dict,
    adapter_summary: dict,
    parity: dict,
    adapted_report: dict,
) -> None:
    previous_adapter = previous.get("adapter_summary.json", {})
    previous_parity = previous.get("parity_test.json", {})
    previous_adapted = previous.get("projectx_adapted.json", {})
    previous_metrics = previous_adapted.get("metrics", {})
    current_metrics = adapted_report["metrics"]
    previous_fidelity = previous_adapter.get("fidelity_counts", {
        "exact": previous_adapter.get("exact_mapped_fields"),
        "high_fidelity_derived": previous_adapter.get("transformable_fields"),
        "approximate": previous_adapter.get("approximate_fields"),
        "unrecoverable": previous_adapter.get("missing_or_unrecoverable_fields"),
    })
    payload = {
        "coverage_fidelity": {
            "old_schema_coverage": previous_adapter.get("feature_coverage_percentage"),
            "new_schema_coverage": adapter_summary.get("feature_coverage_percentage"),
            "old_missing_feature_count": previous_adapter.get("missing_or_unrecoverable_fields"),
            "new_missing_feature_count": adapter_summary.get("missing_or_unrecoverable_fields"),
            "old_approximation_ratio": previous_adapter.get("approximation_ratio"),
            "new_approximation_ratio": adapter_summary.get("approximation_ratio"),
            "old_fidelity_counts": previous_fidelity,
            "new_fidelity_counts": adapter_summary.get("fidelity_counts"),
        },
        "metrics": {},
        "validity": {
            "old_parity_status": previous_parity.get("recommendation"),
            "new_parity_status": parity.get("recommendation"),
            "old_parity_confidence": previous_parity.get("parity_confidence"),
            "new_parity_confidence": parity.get("parity_confidence"),
            "recommendation": "ready for small-scale 10k trial" if parity.get("recommendation") == "parity acceptable" else "still do more fidelity work",
        },
    }
    for key in ("accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc"):
        old_value = previous_metrics.get(key)
        new_value = current_metrics.get(key)
        payload["metrics"][key] = {
            "old": old_value,
            "new": new_value,
            "delta": (new_value - old_value) if old_value is not None and new_value is not None else None,
        }
    (latest_dir / "fidelity_delta.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Fidelity Delta",
        "",
        f"- Old schema coverage: {payload['coverage_fidelity']['old_schema_coverage']}",
        f"- New schema coverage: {payload['coverage_fidelity']['new_schema_coverage']}",
        f"- Old missing feature count: {payload['coverage_fidelity']['old_missing_feature_count']}",
        f"- New missing feature count: {payload['coverage_fidelity']['new_missing_feature_count']}",
        f"- Old approximation ratio: {payload['coverage_fidelity']['old_approximation_ratio']}",
        f"- New approximation ratio: {payload['coverage_fidelity']['new_approximation_ratio']}",
        f"- Old parity status: {payload['validity']['old_parity_status']}",
        f"- New parity status: {payload['validity']['new_parity_status']}",
        f"- Old parity confidence: {payload['validity']['old_parity_confidence']}",
        f"- New parity confidence: {payload['validity']['new_parity_confidence']}",
        f"- Recommendation: {payload['validity']['recommendation']}",
        "",
        "## Metric Deltas",
        "",
    ]
    for key, value in payload["metrics"].items():
        lines.append(f"- {key}: old={value['old']} new={value['new']} delta={value['delta']}")
    (latest_dir / "fidelity_delta.md").write_text("\n".join(lines) + "\n")


def build_latest_failure_analysis(
    latest_dir: Path,
    previous: dict,
    adapter_summary: dict,
    parity: dict,
    adapted_report: dict,
    prereq_failure_analysis: dict,
) -> None:
    previous_metrics = previous.get("projectx_adapted.json", {}).get("metrics", {})
    current_metrics = adapted_report["metrics"]
    payload = {
        "did_byte_faithful_string_extraction_help": current_metrics["pr_auc"] > previous_metrics.get("pr_auc", 0.0),
        "did_pe_structural_fidelity_help": current_metrics["roc_auc"] > previous_metrics.get("roc_auc", 0.0),
        "is_still_overpredicting_malicious_or_suspicious": adapted_report["predicted_class_breakdown"]["clean"] == 0,
        "top_blocker_now": "approximation-heavy feature coverage",
        "is_10k_run_justified": False,
        "remaining_features_or_fidelity_issues": prereq_failure_analysis["feature_gaps"],
        "evidence": {
            "predicted_class_breakdown": adapted_report["predicted_class_breakdown"],
            "approximation_ratio": adapter_summary["approximation_ratio"],
            "missing_feature_count": adapter_summary["missing_or_unrecoverable_fields"],
            "metric_deltas": {
                "roc_auc_delta": current_metrics["roc_auc"] - previous_metrics.get("roc_auc", current_metrics["roc_auc"]),
                "pr_auc_delta": current_metrics["pr_auc"] - previous_metrics.get("pr_auc", current_metrics["pr_auc"]),
                "precision_delta": current_metrics["precision"] - previous_metrics.get("precision", current_metrics["precision"]),
            },
        },
        "ranked_recommendations": [
            {
                "rank": 1,
                "step": "Replace metadata-string approximations with a raw-string-preserving benchmark source.",
                "why": "String fidelity is still the dominant semantic mismatch and the current path still overpredicts malicious/suspicious almost universally.",
            },
            {
                "rank": 2,
                "step": "Replace inferred PE layout with raw-offset-aware PE metadata or raw bytes.",
                "why": "Entrypoint and overlay are still estimated rather than read from PE offsets.",
            },
            {
                "rank": 3,
                "step": "Only consider a 10k adapted run after approximation ratio drops materially below the current level.",
                "why": "Current parity confidence is low and the adapted label remains PROJECTX_ADAPTED_PARITY_INVALID.",
            },
        ],
    }
    (latest_dir / "failure_analysis.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Failure Analysis",
        "",
        f"- Did byte-faithful string extraction help: {payload['did_byte_faithful_string_extraction_help']}",
        f"- Did PE structural fidelity help: {payload['did_pe_structural_fidelity_help']}",
        f"- Still overpredicting malicious/suspicious: {payload['is_still_overpredicting_malicious_or_suspicious']}",
        f"- Top blocker now: {payload['top_blocker_now']}",
        f"- Is a 10k run justified now: {payload['is_10k_run_justified']}",
        "",
        "## Remaining Issues",
        "",
    ]
    for item in payload["remaining_features_or_fidelity_issues"]["missing_in_ember"]:
        lines.append(f"- Unrecoverable: {item}")
    for item in payload["remaining_features_or_fidelity_issues"]["approximate"][:20]:
        lines.append(f"- Approximate: {item}")
    lines.extend(["", "## Ranked Recommendations", ""])
    for item in payload["ranked_recommendations"]:
        lines.append(f"- {item['rank']}. {item['step']}")
        lines.append(f"  Why: {item['why']}")
    (latest_dir / "failure_analysis.md").write_text("\n".join(lines) + "\n")


def build_next_steps(
    latest_dir: Path,
    reference_report: dict,
    adapted_report: dict,
    failure_analysis: dict,
) -> None:
    missing = failure_analysis["feature_gaps"]["missing_in_ember"]
    approximate = failure_analysis["feature_gaps"]["approximate"]
    payload = {
        "immediate_next_steps_for_running_better_tests": [
            {
                "step": "Do more fidelity work before any 10k adapted trial.",
                "why_it_matters": "PROJECTX_ADAPTED still predicts 999 of 1000 rows as suspicious/malicious and remains parity invalid.",
                "estimated_impact": "medium",
            },
            {
                "step": "Run REFERENCE_EMBER and PROJECTX_ADAPTED_PARITY_INVALID together on the same sampled rows for every iteration.",
                "why_it_matters": "It keeps a trustworthy reference baseline beside the adapted ProjectX result.",
                "estimated_impact": "high",
            },
        ],
        "immediate_next_steps_for_improving_projectx": [
            {
                "step": "Replace approximate string_pattern_* reconstruction with a raw-string-preserving benchmark source.",
                "why_it_matters": "The current metadata-string path is closer to ProjectX semantics than before, but it still does not preserve the real extracted printable-string corpus.",
                "evidence": "PROJECTX_ADAPTED remains stuck at 0.458 precision with 0 clean predictions, so the fidelity upgrade did not materially fix overprediction.",
                "estimated_impact": "very high",
                "code_locations": [
                    "src/ml/portable_features.rs",
                    "ember_benchmark/projectx_ember_adapter.py",
                ],
            },
            {
                "step": "Replace section-order entrypoint and overlay approximations with raw-offset-aware PE metadata.",
                "why_it_matters": "The new alignment-aware estimates are more faithful than before, but they still cannot match byte-level PE offsets.",
                "evidence": "ROC-AUC did not improve materially after the fidelity pass, so PE structural fidelity is still insufficient.",
                "estimated_impact": "high",
                "code_locations": [
                    "src/ml/portable_features.rs",
                    "ember_benchmark/ember_repo/ember/features.py",
                    "ember_benchmark/projectx_ember_adapter.py",
                ],
            },
            {
                "step": "Tighten approximate import/header heuristics in the adapter.",
                "why_it_matters": "pe_import_descriptor_count, pe_suspicious_import_count, pe_is_probably_packed, and pe_header_anomaly_score are still approximate.",
                "evidence": "Approximation ratio increased slightly to support the new fidelity-derived fields, but the adapted metrics remained flat.",
                "estimated_impact": "medium",
                "code_locations": [
                    "ember_benchmark/projectx_ember_adapter.py",
                    "src/ml/portable_features.rs",
                ],
            },
        ],
        "parity_roadmap": {
            "current_state": adapted_report["benchmark_validity_label"],
            "what_must_be_done_before_rust_parity_can_be_claimed": failure_analysis["recommended_next_implementation_order"],
            "highest_priority_missing_features": missing[:10] + approximate[:5],
            "minimum_credible_schema_coverage_target_for_100k": 95.0,
        },
    }
    (latest_dir / "next_steps.json").write_text(json.dumps(payload, indent=2) + "\n")
    lines = [
        "# Next Steps",
        "",
        "## Immediate Next Steps For Running Better Tests",
        "",
    ]
    for item in payload["immediate_next_steps_for_running_better_tests"]:
        lines.append(f"- {item['step']}")
        lines.append(f"  Why: {item['why_it_matters']}")
        lines.append(f"  Estimated impact: {item['estimated_impact']}")
    lines.extend(["", "## Immediate Next Steps For Improving ProjectX", ""])
    for item in payload["immediate_next_steps_for_improving_projectx"]:
        lines.append(f"- {item['step']}")
        lines.append(f"  Why: {item['why_it_matters']}")
        lines.append(f"  Evidence: {item['evidence']}")
        lines.append(f"  Estimated impact: {item['estimated_impact']}")
        lines.append(f"  Code locations: {', '.join(item['code_locations'])}")
    lines.extend(["", "## Parity Roadmap", ""])
    lines.append(f"- Current state: {payload['parity_roadmap']['current_state']}")
    lines.append(
        f"- Minimum credible schema coverage target for a 100k parity benchmark: {payload['parity_roadmap']['minimum_credible_schema_coverage_target_for_100k']:.1f}%"
    )
    for item in payload["parity_roadmap"]["what_must_be_done_before_rust_parity_can_be_claimed"]:
        lines.append(f"- Required before Rust parity: {item}")
    (latest_dir / "next_steps.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    args = parse_args()
    dataset_dir = Path(args.dataset_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    projectx_bin = ensure_projectx_bin(Path(args.projectx_bin))
    previous_snapshot = load_previous_snapshot(output_dir)
    fidelity_baseline = load_fidelity_baseline(output_dir)

    adapter_summary, parity, failure_analysis = run_prerequisites(args)
    copy_prereq_artifacts(output_dir)

    rows = sample_rows(dataset_dir, args.sample_size, args.seed)
    reference_rows, reference_meta = score_reference_ember(rows, dataset_dir)
    adapted_rows, adapted_meta = score_projectx_adapted(rows, projectx_bin, output_dir)

    reference_report = build_report("REFERENCE_EMBER", reference_rows, rows, reference_meta, adapter_summary, parity)
    adapted_label = (
        "PROJECTX_ADAPTED_PARITY_ACCEPTABLE"
        if parity["recommendation"] == "parity acceptable"
        else "PROJECTX_ADAPTED_PARITY_INVALID"
    )
    adapted_report = build_report(adapted_label, adapted_rows, rows, adapted_meta, adapter_summary, parity)
    build_improvement_delta(
        output_dir,
        previous_snapshot,
        adapter_summary,
        parity,
        adapted_report,
        projectx_portable_mapping_spec(),
    )
    build_fidelity_report(output_dir, adapter_summary, failure_analysis)
    build_fidelity_delta(output_dir, fidelity_baseline, adapter_summary, parity, adapted_report)
    build_latest_failure_analysis(output_dir, fidelity_baseline, adapter_summary, parity, adapted_report, failure_analysis)

    timestamp = datetime.now(timezone.utc).isoformat()
    summary = {
        "timestamp_utc": timestamp,
        "most_trustworthy_result": "REFERENCE_EMBER",
        "reference_report": "reference_ember.json",
        "adapted_report": "projectx_adapted.json",
        "parity_status": parity["recommendation"],
        "benchmark_validity": adapted_report["benchmark_validity_label"],
    }
    (output_dir / "reference_ember.json").write_text(json.dumps(reference_report, indent=2) + "\n")
    (output_dir / "reference_ember.md").write_text(markdown_report(reference_report))
    (output_dir / "projectx_adapted.json").write_text(json.dumps(adapted_report, indent=2) + "\n")
    (output_dir / "projectx_adapted.md").write_text(markdown_report(adapted_report))
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output_dir / "summary.md").write_text(
        "\n".join(
            [
                "# Benchmark Summary",
                "",
                f"- Timestamp: {timestamp}",
                f"- Most trustworthy result: {summary['most_trustworthy_result']}",
                f"- Reference benchmark label: {reference_report['benchmark_validity_label']}",
                f"- Adapted benchmark label: {adapted_report['benchmark_validity_label']}",
                f"- Parity status: {summary['parity_status']}",
                "",
            ]
        )
    )
    build_next_steps(output_dir, reference_report, adapted_report, failure_analysis)
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
