from __future__ import annotations

import json
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn import metrics


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
EMBER_REPO = ROOT / "ember_repo"
REPORTS_DIR = ROOT / "reports"
RUNS_DIR = ROOT / "runs"
CACHE_DIR = ROOT / "cache"
MPL_CACHE_DIR = CACHE_DIR / "matplotlib"
FEATURES_RS = PROJECT_ROOT / "src" / "ml" / "portable_features.rs"

for path in (REPORTS_DIR, RUNS_DIR, CACHE_DIR, MPL_CACHE_DIR):
    path.mkdir(parents=True, exist_ok=True)

os.environ.setdefault("MPLCONFIGDIR", str(MPL_CACHE_DIR))


@dataclass
class DatasetBundle:
    x_train: np.ndarray
    y_train: np.ndarray
    x_val: np.ndarray
    y_val: np.ndarray
    x_test: np.ndarray
    y_test: np.ndarray
    train_meta: pd.DataFrame
    val_meta: pd.DataFrame
    test_meta: pd.DataFrame
    feature_names: list[str]
    source: str


def slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "run"


def rust_portable_feature_names() -> list[str]:
    text = FEATURES_RS.read_text()
    match = re.search(
        r"pub const FEATURE_NAMES: \[&str; FEATURE_COUNT\] = \[(.*?)\];",
        text,
        re.S,
    )
    if not match:
        raise RuntimeError("Unable to parse Rust FEATURE_NAMES from portable_features.rs")
    return re.findall(r'"([^"]+)"', match.group(1))


def load_ember_vectorized(data_dir: Path, feature_version: int) -> DatasetBundle:
    del feature_version

    x_train_path = data_dir / "X_train.dat"
    y_train_path = data_dir / "y_train.dat"
    x_test_path = data_dir / "X_test.dat"
    y_test_path = data_dir / "y_test.dat"

    missing = [
        str(path)
        for path in (x_train_path, y_train_path, x_test_path, y_test_path)
        if not path.exists()
    ]
    if missing:
        raise FileNotFoundError(
            "Missing EMBER vectorized dataset files: "
            + ", ".join(missing)
            + ". Create them with the upstream EMBER vectorizer before running ProjectX preprocessing."
        )

    y_train = np.memmap(y_train_path, dtype=np.float32, mode="r")
    y_test = np.memmap(y_test_path, dtype=np.float32, mode="r")
    train_rows = len(y_train)
    test_rows = len(y_test)
    train_feature_count = infer_feature_count(x_train_path, train_rows)
    test_feature_count = infer_feature_count(x_test_path, test_rows)
    if train_feature_count != test_feature_count:
        raise ValueError(
            f"Feature count mismatch between train ({train_feature_count}) and test ({test_feature_count}) vectors."
        )

    x_train = np.memmap(
        x_train_path, dtype=np.float32, mode="r", shape=(train_rows, train_feature_count)
    )
    x_test = np.memmap(
        x_test_path, dtype=np.float32, mode="r", shape=(test_rows, test_feature_count)
    )

    metadata = load_ember_metadata(data_dir, train_rows, test_rows)
    train_rows = len(y_train)

    if len(metadata) >= train_rows + test_rows:
        train_meta = metadata.iloc[:train_rows].copy().reset_index(drop=True)
        test_meta = metadata.iloc[train_rows : train_rows + test_rows].copy().reset_index(drop=True)
    else:
        train_meta = pd.DataFrame(index=np.arange(train_rows))
        test_meta = pd.DataFrame(index=np.arange(test_rows))

    train_meta["subset"] = "train"
    test_meta["subset"] = "test"
    train_meta["row_index"] = np.arange(train_rows)
    test_meta["row_index"] = np.arange(test_rows)

    split_index = max(1, int(len(y_train) * 0.9))
    if split_index >= len(y_train):
        split_index = max(1, len(y_train) - 1)

    x_base = np.asarray(x_train[:split_index])
    y_base = np.asarray(y_train[:split_index])
    x_val = np.asarray(x_train[split_index:])
    y_val = np.asarray(y_train[split_index:])

    train_meta_base = train_meta.iloc[:split_index].copy().reset_index(drop=True)
    val_meta = train_meta.iloc[split_index:].copy().reset_index(drop=True)
    val_meta["subset"] = "validation"

    if len(y_val) == 0:
        x_val = x_base[: min(len(x_base), 1024)].copy()
        y_val = y_base[: min(len(y_base), 1024)].copy()
        val_meta = train_meta_base.iloc[: len(y_val)].copy().reset_index(drop=True)
        val_meta["subset"] = "validation"

    feature_names = [f"ember_feature_{index:04d}" for index in range(x_base.shape[1])]

    return DatasetBundle(
        x_train=x_base,
        y_train=y_base,
        x_val=x_val,
        y_val=y_val,
        x_test=np.asarray(x_test),
        y_test=np.asarray(y_test),
        train_meta=train_meta_base,
        val_meta=val_meta,
        test_meta=test_meta,
        feature_names=feature_names,
        source=f"ember_vectorized_v{feature_version}",
    )


def infer_feature_count(path: Path, rows: int) -> int:
    if rows <= 0:
        raise ValueError(f"Cannot infer feature count from empty vector file {path}.")
    bytes_per_value = np.dtype(np.float32).itemsize
    total_values = path.stat().st_size // bytes_per_value
    if total_values % rows != 0:
        raise ValueError(f"Vector file {path} does not divide evenly across {rows} rows.")
    return int(total_values // rows)


def load_ember_metadata(data_dir: Path, train_rows: int, test_rows: int) -> pd.DataFrame:
    metadata_path = data_dir / "metadata.csv"
    if metadata_path.exists():
        return pd.read_csv(metadata_path, index_col=0).reset_index(drop=True)

    train_metadata_path = data_dir / "train_metadata.csv"
    test_metadata_path = data_dir / "test_metadata.csv"
    if train_metadata_path.exists() and test_metadata_path.exists():
        train_meta = pd.read_csv(train_metadata_path)
        test_meta = pd.read_csv(test_metadata_path)
        train_meta["subset"] = "train"
        test_meta["subset"] = "test"
        return pd.concat([train_meta, test_meta], ignore_index=True)

    train_feature_paths = [data_dir / f"train_features_{index}.jsonl" for index in range(6)]
    test_feature_paths = [data_dir / "test_features.jsonl"]
    if all(path.exists() for path in train_feature_paths) and all(path.exists() for path in test_feature_paths):
        train_meta = pd.DataFrame(read_jsonl_metadata(train_feature_paths))
        test_meta = pd.DataFrame(read_jsonl_metadata(test_feature_paths))
        if len(train_meta) != train_rows or len(test_meta) != test_rows:
            raise ValueError(
                "Raw metadata row counts do not match vectorized data dimensions. "
                "Regenerate metadata.csv or verify the dataset extraction."
            )
        train_meta["subset"] = "train"
        test_meta["subset"] = "test"
        return pd.concat([train_meta, test_meta], ignore_index=True)

    return pd.DataFrame(index=np.arange(train_rows + test_rows))


def read_jsonl_metadata(paths: list[Path]) -> list[dict]:
    records = []
    keys = ("sha256", "appeared", "label", "avclass")
    for path in paths:
        with path.open("r") as handle:
            for line in handle:
                raw = json.loads(line)
                records.append({key: raw.get(key) for key in keys if key in raw})
    return records


def sample_test_subset(
    bundle: DatasetBundle, sample_size: int, seed: int
) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    total = len(bundle.y_test)
    if sample_size >= total:
        return bundle.x_test, bundle.y_test, bundle.test_meta.copy().reset_index(drop=True)
    rng = np.random.default_rng(seed)
    labels = pd.Series(bundle.y_test)
    keep_indices: list[int] = []
    for label_value in sorted(labels.unique()):
        label_indices = np.where(bundle.y_test == label_value)[0]
        target = max(1, round(sample_size * (len(label_indices) / total)))
        chosen = rng.choice(label_indices, size=min(target, len(label_indices)), replace=False)
        keep_indices.extend(int(index) for index in chosen)
    keep_indices = sorted(set(keep_indices))
    if len(keep_indices) > sample_size:
        keep_indices = keep_indices[:sample_size]
    elif len(keep_indices) < sample_size:
        missing_pool = [idx for idx in range(total) if idx not in keep_indices]
        additional = rng.choice(
            missing_pool, size=min(sample_size - len(keep_indices), len(missing_pool)), replace=False
        )
        keep_indices.extend(int(index) for index in additional)
        keep_indices = sorted(keep_indices)
    meta = bundle.test_meta.iloc[keep_indices].copy().reset_index(drop=True)
    return bundle.x_test[keep_indices], bundle.y_test[keep_indices], meta


def choose_threshold(y_true: np.ndarray, scores: np.ndarray) -> float:
    precision, recall, thresholds = metrics.precision_recall_curve(y_true, scores)
    best_threshold = 0.5
    best_f1 = -1.0
    for index, threshold in enumerate(thresholds):
        p = precision[index + 1]
        r = recall[index + 1]
        if p + r == 0:
            current_f1 = 0.0
        else:
            current_f1 = 2 * p * r / (p + r)
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = float(threshold)
    return float(best_threshold)


def classification_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    y_pred = (scores >= threshold).astype(int)
    confusion = metrics.confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = confusion.ravel()
    accuracy = metrics.accuracy_score(y_true, y_pred)
    precision = metrics.precision_score(y_true, y_pred, zero_division=0)
    recall = metrics.recall_score(y_true, y_pred, zero_division=0)
    f1_score = metrics.f1_score(y_true, y_pred, zero_division=0)
    roc_auc = metrics.roc_auc_score(y_true, scores) if len(np.unique(y_true)) > 1 else float("nan")
    pr_auc = metrics.average_precision_score(y_true, scores) if len(np.unique(y_true)) > 1 else float("nan")
    brier = metrics.brier_score_loss(y_true, scores)
    log_loss = metrics.log_loss(y_true, np.column_stack([1 - scores, scores]), labels=[0, 1])
    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1_score),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "brier_score": float(brier),
        "log_loss": float(log_loss),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "per_class": {
            "benign": {
                "precision": float(metrics.precision_score(y_true, y_pred, pos_label=0, zero_division=0)),
                "recall": float(metrics.recall_score(y_true, y_pred, pos_label=0, zero_division=0)),
                "f1_score": float(metrics.f1_score(y_true, y_pred, pos_label=0, zero_division=0)),
                "support": int((y_true == 0).sum()),
            },
            "malicious": {
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1_score),
                "support": int((y_true == 1).sum()),
            },
        },
    }


def tracked_category_columns(frame: pd.DataFrame) -> list[str]:
    candidates = [
        "avclass",
        "file_type",
        "appeared",
        "family",
        "packer",
        "signature",
        "sha256",
        "arch",
    ]
    return [column for column in candidates if column in frame.columns]


def category_breakdown(
    frame: pd.DataFrame, y_true: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, dict]:
    results: dict[str, dict] = {}
    y_pred = (scores >= threshold).astype(int)
    working = frame.copy()
    working["_y_true"] = y_true
    working["_y_pred"] = y_pred
    for column in tracked_category_columns(frame):
        bucket = {}
        for value, group in working.groupby(column):
            if pd.isna(value) or len(group) < 25:
                continue
            group_true = group["_y_true"].to_numpy()
            group_pred = group["_y_pred"].to_numpy()
            bucket[str(value)] = {
                "count": int(len(group)),
                "accuracy": float(metrics.accuracy_score(group_true, group_pred)),
                "malicious_rate": float(group_true.mean()),
                "predicted_malicious_rate": float(group_pred.mean()),
            }
        if bucket:
            results[column] = bucket
    return results


def top_feature_deltas(
    x: np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    feature_names: Iterable[str],
    top_k: int = 10,
) -> dict[str, list[dict]]:
    names = list(feature_names)
    results: dict[str, list[dict]] = {}
    for label_name, mask in {
        "false_positives": (y_true == 0) & (y_pred == 1),
        "false_negatives": (y_true == 1) & (y_pred == 0),
    }.items():
        if not mask.any():
            results[label_name] = []
            continue
        baseline = x[~mask].mean(axis=0)
        deltas = x[mask].mean(axis=0) - baseline
        order = np.argsort(np.abs(deltas))[::-1][:top_k]
        results[label_name] = [
            {"feature": names[index], "delta": float(deltas[index])} for index in order
        ]
    return results


def failure_analysis(
    frame: pd.DataFrame,
    x: np.ndarray,
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    feature_names: list[str],
) -> dict:
    y_pred = (scores >= threshold).astype(int)
    false_positives = frame[(y_true == 0) & (y_pred == 1)].copy()
    false_negatives = frame[(y_true == 1) & (y_pred == 0)].copy()

    notes = []
    confusion = metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    tn, fp, fn, tp = confusion
    if fp > fn * 1.5:
        notes.append("Threshold looks too aggressive for benign suppression; false positives dominate false negatives.")
    elif fn > fp * 1.5:
        notes.append("Threshold looks too conservative; false negatives dominate false positives.")
    else:
        notes.append("Threshold tradeoff is relatively balanced; primary gains likely need better features or calibration.")

    brier = metrics.brier_score_loss(y_true, scores)
    if brier > 0.18:
        notes.append("Probability calibration is weak enough to justify Platt or isotonic calibration review.")
    elif brier > 0.12:
        notes.append("Calibration is usable but still loose; threshold tuning alone is unlikely to fully solve error clusters.")
    else:
        notes.append("Calibration error is moderate; residual errors likely stem more from feature coverage than score scaling.")

    fp_clusters = []
    fn_clusters = []
    for column in tracked_category_columns(frame):
        if column in false_positives.columns and len(false_positives) > 0:
            fp_value_counts = false_positives[column].value_counts(dropna=True).head(5)
            for value, count in fp_value_counts.items():
                fp_clusters.append(f"False positives cluster in {column}={value} ({count} samples).")
        if column in false_negatives.columns and len(false_negatives) > 0:
            fn_value_counts = false_negatives[column].value_counts(dropna=True).head(5)
            for value, count in fn_value_counts.items():
                fn_clusters.append(f"False negatives cluster in {column}={value} ({count} samples).")

    feature_deltas = top_feature_deltas(x, y_true, y_pred, feature_names)
    feature_weaknesses = []
    for item in feature_deltas.get("false_positives", [])[:5]:
        feature_weaknesses.append(
            f"False positives over-index on {item['feature']} (delta {item['delta']:.4f})."
        )
    for item in feature_deltas.get("false_negatives", [])[:5]:
        feature_weaknesses.append(
            f"False negatives under-capture {item['feature']} (delta {item['delta']:.4f})."
        )

    recommendations = []
    if fp > 0:
        recommendations.append("Tune malicious threshold upward or add benign suppression for the strongest false-positive clusters.")
    if fn > 0:
        recommendations.append("Tune calibration and revisit features associated with the false-negative cluster leaders.")
    recommendations.append("Do not claim Rust scanner equivalence on EMBER unless the training feature schema matches ProjectX portable features exactly.")

    return {
        "notes": notes,
        "false_positive_clusters": fp_clusters[:10],
        "false_negative_clusters": fn_clusters[:10],
        "feature_weaknesses": feature_weaknesses[:10],
        "recommended_fixes": recommendations,
    }


def markdown_report(report: dict) -> str:
    lines = [
        f"# {report['run_name']}",
        "",
        f"- Timestamp: {report['timestamp_utc']}",
        f"- Model family: {report['model_family']}",
        f"- Data source: {report['data_source']}",
        f"- Rust-compatible portable model: {report['rust_portable_compatible']}",
        f"- Architectural status: {report['architectural_status']}",
        "",
        "## Dataset",
        "",
        f"- Train count: {report['dataset']['train_count']}",
        f"- Validation count: {report['dataset']['validation_count']}",
        f"- Test count: {report['dataset']['test_count']}",
        f"- Class balance (test malicious rate): {report['dataset']['test_malicious_rate']:.4f}",
        "",
        "## Metrics",
        "",
    ]
    for key in (
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "roc_auc",
        "pr_auc",
        "brier_score",
        "log_loss",
    ):
        lines.append(f"- {key}: {report['metrics'][key]:.6f}")
    lines.extend(
        [
            "",
            "## Confusion Matrix",
            "",
            f"- TN: {report['metrics']['confusion_matrix']['tn']}",
            f"- FP: {report['metrics']['confusion_matrix']['fp']}",
            f"- FN: {report['metrics']['confusion_matrix']['fn']}",
            f"- TP: {report['metrics']['confusion_matrix']['tp']}",
            "",
            "## Failure Analysis",
            "",
        ]
    )
    for note in report["failure_analysis"]["notes"]:
        lines.append(f"- {note}")
    lines.extend(["", "## Feature Weaknesses", ""])
    for note in report["failure_analysis"]["feature_weaknesses"] or ["- No dominant feature weaknesses were identified from the current error slices."]:
        if isinstance(note, str):
            lines.append(f"- {note}")
    lines.extend(["", "## Recommended Fixes", ""])
    for note in report["failure_analysis"]["recommended_fixes"]:
        lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def html_report(report: dict) -> str:
    sections = [
        f"<h1>{report['run_name']}</h1>",
        f"<p><strong>Timestamp:</strong> {report['timestamp_utc']}</p>",
        f"<p><strong>Model family:</strong> {report['model_family']}</p>",
        f"<p><strong>Rust-compatible portable model:</strong> {report['rust_portable_compatible']}</p>",
        "<h2>Metrics</h2>",
        "<ul>",
    ]
    for key in ("accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "brier_score", "log_loss"):
        sections.append(f"<li>{key}: {report['metrics'][key]:.6f}</li>")
    sections.append("</ul>")
    sections.append("<h2>Failure Analysis</h2><ul>")
    for note in report["failure_analysis"]["notes"]:
        sections.append(f"<li>{note}</li>")
    sections.append("</ul>")
    sections.append("<h2>Feature Weaknesses</h2><ul>")
    for note in report["failure_analysis"]["feature_weaknesses"]:
        sections.append(f"<li>{note}</li>")
    sections.append("</ul>")
    sections.append("<h2>Recommended Fixes</h2><ul>")
    for note in report["failure_analysis"]["recommended_fixes"]:
        sections.append(f"<li>{note}</li>")
    sections.append("</ul>")
    return "<html><body>" + "".join(sections) + "</body></html>\n"


def write_report_triplet(base_path: Path, report: dict) -> None:
    base_path.parent.mkdir(parents=True, exist_ok=True)
    base_path.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    base_path.with_suffix(".md").write_text(markdown_report(report))
    base_path.with_suffix(".html").write_text(html_report(report))


def safe_float(value: float) -> float:
    if value is None or (isinstance(value, float) and (math.isnan(value) or math.isinf(value))):
        return float("nan")
    return float(value)
