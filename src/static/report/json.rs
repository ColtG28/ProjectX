use std::path::Path;

use crate::r#static::context::ScanContext;
use crate::r#static::types::Severity;

pub fn render(
    ctx: &ScanContext,
    severity: Severity,
    original_path: &Path,
    quarantine_path: &Path,
    restored_to_original_path: bool,
) -> String {
    value(
        ctx,
        severity,
        original_path,
        quarantine_path,
        restored_to_original_path,
    )
    .to_string()
}

pub fn value(
    ctx: &ScanContext,
    severity: Severity,
    original_path: &Path,
    quarantine_path: &Path,
    restored_to_original_path: bool,
) -> serde_json::Value {
    serde_json::json!({
        "scanner": {
            "name": "ProjectX Static Scanner",
            "rules_version": ctx.rules_version,
        },
        "file": {
            "original_path": original_path.to_string_lossy(),
            "analyzed_path": ctx.input_path.to_string_lossy(),
            "quarantine_path": quarantine_path.to_string_lossy(),
            "name": ctx.file_name,
            "extension": ctx.extension,
            "size_bytes": ctx.original_size_bytes,
            "analyzed_bytes": ctx.bytes.len(),
            "input_truncated": ctx.input_truncated,
            "sha256": ctx.sha256,
            "sniffed_mime": ctx.sniffed_mime,
            "detected_format": ctx.detected_format,
        },
        "verdict": {
            "severity": format!("{severity:?}"),
            "risk": ctx.score.risk,
            "safety": ctx.score.safety,
            "retained_in_quarantine": !restored_to_original_path,
            "restored_to_original_path": restored_to_original_path,
        },
        "cache": ctx.cache,
        "emulation": ctx.emulation,
        "ml": ctx.ml_assessment,
        "threat_severity": ctx.threat_severity,
        "sandbox_plan": ctx.sandbox_plan,
        "dynamic_analysis": ctx.dynamic_analysis,
        "findings": ctx.findings.iter().map(|finding| serde_json::json!({
            "code": finding.code,
            "message": finding.message,
            "weight": finding.weight,
        })).collect::<Vec<_>>(),
        "stages": ctx.stage_timings.iter().map(|stage| serde_json::json!({
            "name": stage.name,
            "duration_ms": stage.duration_ms,
        })).collect::<Vec<_>>(),
        "artifacts": ctx.artifacts.iter().map(|artifact| serde_json::json!({
            "path": artifact.path,
            "kind": artifact.kind,
            "depth": artifact.depth,
            "size_bytes": artifact.size_bytes,
        })).collect::<Vec<_>>(),
        "telemetry": ctx.telemetry.iter().map(|entry| serde_json::json!({
            "stage": entry.stage,
            "message": entry.message,
        })).collect::<Vec<_>>(),
    })
}
