use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::r#static::config::ScanConfig;
use crate::r#static::context::ScanContext;
use crate::r#static::types::{CacheMetadata, Finding, Score, Severity, StringPool, View};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScan {
    pub severity: Severity,
    pub score: Score,
    pub findings: Vec<Finding>,
    pub views: Vec<View>,
    pub strings: StringPool,
    pub normalized_strings: Vec<String>,
    pub decoded_strings: Vec<String>,
    pub sniffed_mime: String,
    pub detected_format: Option<String>,
    pub artifacts: Vec<crate::r#static::types::ExtractedArtifact>,
    pub rules_version: String,
    pub emulation: Option<crate::r#static::types::EmulationSummary>,
    pub ml_assessment: Option<crate::r#static::types::MlAssessment>,
    pub threat_severity: Option<crate::r#static::types::ThreatSeveritySummary>,
}

pub fn cache_key(sha256: &str, config: &ScanConfig, rules_version: &str) -> String {
    let config_json = serde_json::to_string(config).unwrap_or_default();
    crate::r#static::file::hash::sha256_hex(
        format!("projectx-static-v13|{sha256}|{rules_version}|{config_json}").as_bytes(),
    )
}

pub fn load(key: &str) -> Option<CachedScan> {
    let path = cache_file_path(key);
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn store(key: &str, ctx: &ScanContext, severity: Severity) -> std::io::Result<PathBuf> {
    fs::create_dir_all(cache_dir())?;
    let path = cache_file_path(key);
    let max_view_bytes = ctx.config.limits.max_view_bytes;
    let max_view_items = ctx.config.limits.max_view_items;
    let entry = CachedScan {
        severity,
        score: ctx.score.clone(),
        findings: ctx.findings.clone(),
        views: ctx
            .views
            .iter()
            .take(max_view_items)
            .map(|view| View {
                name: view.name.clone(),
                content: truncate_string(&view.content, max_view_bytes),
            })
            .collect(),
        strings: StringPool {
            values: ctx
                .strings
                .values
                .iter()
                .take(ctx.config.limits.max_string_values)
                .map(|value| truncate_string(value, max_view_bytes))
                .collect(),
        },
        normalized_strings: ctx
            .normalized_strings
            .iter()
            .take(ctx.config.limits.max_string_values)
            .map(|value| truncate_string(value, max_view_bytes))
            .collect(),
        decoded_strings: ctx
            .decoded_strings
            .iter()
            .take(ctx.config.limits.max_decoded_strings)
            .map(|value| truncate_string(value, max_view_bytes))
            .collect(),
        sniffed_mime: ctx.sniffed_mime.clone(),
        detected_format: ctx.detected_format.clone(),
        artifacts: ctx.artifacts.clone(),
        rules_version: ctx.rules_version.clone(),
        emulation: ctx.emulation.clone(),
        ml_assessment: ctx.ml_assessment.clone(),
        threat_severity: ctx.threat_severity.clone(),
    };
    let json = serde_json::to_string_pretty(&entry).unwrap_or_else(|_| "{}".to_string());
    fs::write(&path, json)?;
    Ok(path)
}

pub fn apply(ctx: &mut ScanContext, key: &str, cached: CachedScan) -> Severity {
    ctx.score = cached.score;
    ctx.findings = cached.findings;
    ctx.views = cached.views;
    ctx.strings = cached.strings;
    ctx.normalized_strings = cached.normalized_strings;
    ctx.decoded_strings = cached.decoded_strings;
    ctx.sniffed_mime = cached.sniffed_mime;
    ctx.detected_format = cached.detected_format;
    ctx.artifacts = cached.artifacts;
    ctx.rules_version = cached.rules_version.clone();
    ctx.emulation = cached.emulation;
    ctx.ml_assessment = cached.ml_assessment;
    ctx.threat_severity = cached.threat_severity;
    ctx.cache = Some(CacheMetadata {
        key: key.to_string(),
        hit: true,
        rules_version: cached.rules_version,
    });
    ctx.stage_timings.clear();
    ctx.record_stage_timing("Fingerprint cache hit", 0);
    ctx.log_event("cache", format!("Fingerprint cache hit for key {key}"));
    cached.severity
}

pub fn cache_dir() -> &'static Path {
    Path::new("quarantine/cache")
}

fn cache_file_path(key: &str) -> PathBuf {
    cache_dir().join(format!("{key}.json"))
}

fn truncate_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = value[..end].to_string();
    truncated.push_str("... [truncated]");
    truncated
}
