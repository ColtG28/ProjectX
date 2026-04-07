use std::path::Path;

use crate::r#static::context::ScanContext;
use crate::r#static::report::{
    normalize_reason_description, normalize_reason_name, normalize_reason_source,
    normalize_severity,
};
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
            "normalized_severity": normalize_severity(severity, ctx.score.risk).as_str(),
            "risk": ctx.score.risk,
            "safety": ctx.score.safety,
            "retained_in_quarantine": !restored_to_original_path,
            "restored_to_original_path": restored_to_original_path,
        },
        "summary": {
            "warning_count": warning_count(ctx),
            "error_count": error_count(ctx),
            "signal_sources": signal_sources(ctx),
            "intelligence_status": ctx
                .intelligence
                .as_ref()
                .map(|summary| summary.external_intelligence_status.clone())
                .unwrap_or_else(|| "disabled".to_string()),
            "intelligence_store_version": ctx
                .intelligence
                .as_ref()
                .and_then(|summary| summary.store_version.clone())
                .unwrap_or_else(|| "none".to_string()),
            "reputation_hit_count": ctx
                .intelligence
                .as_ref()
                .map(|summary| summary.reputation_hits.len())
                .unwrap_or(0),
            "trust_reason_count": ctx
                .intelligence
                .as_ref()
                .map(|summary| summary.trust_reasons.len())
                .unwrap_or(0),
            "trust_category_count": ctx
                .intelligence
                .as_ref()
                .map(|summary| summary.trust_categories.len())
                .unwrap_or(0),
            "trust_ecosystem_count": ctx
                .intelligence
                .as_ref()
                .map(|summary| summary.trust_ecosystems.len())
                .unwrap_or(0),
            "trust_vendor_count": ctx
                .intelligence
                .as_ref()
                .map(|summary| summary.trust_vendors.len())
                .unwrap_or(0),
        },
        "cache": ctx.cache,
        "emulation": ctx.emulation,
        "intelligence": ctx.intelligence,
        "ml": ctx.ml_assessment,
        "threat_severity": ctx.threat_severity,
        "findings": ctx.findings.iter().map(|finding| serde_json::json!({
            "code": finding.code,
            "message": finding.message,
            "weight": finding.weight,
        })).collect::<Vec<_>>(),
        "reasons": ctx.findings.iter().map(|finding| serde_json::json!({
            "reason_type": normalize_reason_source(&finding.code),
            "source": normalize_reason_source(&finding.code),
            "name": normalize_reason_name(&finding.code),
            "description": normalize_reason_description(&finding.message),
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

fn signal_sources(ctx: &ScanContext) -> Vec<&'static str> {
    let mut sources = Vec::new();
    if ctx.cache.as_ref().map(|cache| cache.hit).unwrap_or(false) {
        sources.push("cache");
    }
    for finding in &ctx.findings {
        let source = normalize_reason_source(&finding.code);
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    sources
}

fn warning_count(ctx: &ScanContext) -> usize {
    ctx.findings.len()
}

fn error_count(ctx: &ScanContext) -> usize {
    ctx.telemetry
        .iter()
        .filter(|entry| {
            let message = entry.message.to_ascii_lowercase();
            message.contains("error") || message.contains("failed")
        })
        .count()
}
