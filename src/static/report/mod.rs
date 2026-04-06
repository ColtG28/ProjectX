pub mod finding;
pub mod json;
pub mod summary;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::r#static::context::ScanContext;
use crate::r#static::types::Severity;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum SummaryVerdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

impl SummaryVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "Clean",
            Self::Suspicious => "Suspicious",
            Self::Malicious => "Malicious",
            Self::Error => "Error",
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    serde::Serialize,
    serde::Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum NormalizedSeverity {
    #[default]
    Clean,
    Low,
    Medium,
    High,
    Error,
}

impl NormalizedSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Clean => "Clean",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Error => "Error",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub enum QuarantineStatus {
    #[default]
    Unknown,
    Restored,
    InQuarantine,
    Deleted,
}

impl QuarantineStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Restored => "Back in place",
            Self::InQuarantine => "In quarantine",
            Self::Deleted => "Deleted",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct QuarantineMetadata {
    pub retained_in_quarantine: bool,
    pub restored_to_original_path: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ReportReason {
    #[serde(default)]
    pub reason_type: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub weight: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSummary {
    pub scan_id: String,
    pub path: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub extension: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub sniffed_mime: Option<String>,
    #[serde(default)]
    pub detected_format: Option<String>,
    #[serde(default)]
    pub quarantine_path: Option<String>,
    #[serde(default)]
    pub report_path: Option<String>,
    #[serde(default)]
    pub storage_state: QuarantineStatus,
    #[serde(default)]
    pub quarantine: QuarantineMetadata,
    #[serde(default)]
    pub last_modified_epoch: u64,
    pub scanned_at_epoch: u64,
    #[serde(default)]
    pub started_at_epoch: Option<u64>,
    #[serde(default)]
    pub finished_at_epoch: Option<u64>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub file_size_bytes: u64,
    pub verdict: SummaryVerdict,
    #[serde(default)]
    pub severity: NormalizedSeverity,
    #[serde(default)]
    pub summary_text: String,
    #[serde(default)]
    pub action_note: String,
    #[serde(default)]
    pub risk_score: Option<f64>,
    #[serde(default)]
    pub safety_score: Option<f64>,
    #[serde(default)]
    pub signal_sources: Vec<String>,
    #[serde(default)]
    pub detection_reasons: Vec<ReportReason>,
    #[serde(default)]
    pub warning_count: usize,
    #[serde(default)]
    pub error_count: usize,
}

impl ReportSummary {
    pub fn record_id(&self) -> String {
        if !self.scan_id.is_empty() {
            self.scan_id.clone()
        } else {
            format!("{}::{}", self.scanned_at_epoch, self.path)
        }
    }

    pub fn resolved_storage_state(&self) -> QuarantineStatus {
        if let Some(path) = self.quarantine_path.as_deref() {
            if Path::new(path).is_file() {
                return QuarantineStatus::InQuarantine;
            }
        }

        match self.storage_state {
            QuarantineStatus::Deleted => QuarantineStatus::Deleted,
            QuarantineStatus::Restored => QuarantineStatus::Restored,
            QuarantineStatus::InQuarantine => {
                if Path::new(&self.path).is_file() {
                    QuarantineStatus::Restored
                } else {
                    QuarantineStatus::Unknown
                }
            }
            QuarantineStatus::Unknown => {
                if matches!(self.verdict, SummaryVerdict::Clean) && Path::new(&self.path).is_file()
                {
                    QuarantineStatus::Restored
                } else {
                    QuarantineStatus::Unknown
                }
            }
        }
    }

    pub fn display_note(&self) -> String {
        match (self.summary_text.trim(), self.action_note.trim()) {
            ("", "") => String::new(),
            ("", action) => action.to_string(),
            (note, "") => note.to_string(),
            (note, action) => format!("{note} | {action}"),
        }
    }

    pub fn display_name(&self) -> &str {
        if self.file_name.is_empty() {
            &self.path
        } else {
            &self.file_name
        }
    }

    pub fn quick_type_label(&self) -> &str {
        self.detected_format
            .as_deref()
            .or(self.sniffed_mime.as_deref())
            .or(self.extension.as_deref())
            .unwrap_or("unknown")
    }
}

pub fn normalize_reason_source(code: &str) -> &'static str {
    if code.contains("YARA") {
        "rule"
    } else if code.contains("EMU") || code.contains("EMUL") {
        "emulation"
    } else if code.contains("ML") {
        "ml"
    } else if code.contains("CACHE") {
        "cache"
    } else {
        "heuristic"
    }
}

pub fn source_label(source: &str) -> &'static str {
    match source {
        "heuristic" => "Heuristic",
        "rule" => "Local rule",
        "emulation" => "Emulation",
        "ml" => "ML",
        "cache" => "Cached result",
        _ => "Signal",
    }
}

pub fn normalize_reason_name(code: &str) -> String {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return "Observed signal".to_string();
    }

    trimmed
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let lower = part.to_ascii_lowercase();
            let mut chars = lower.chars();
            match chars.next() {
                Some(first) => {
                    let mut word = String::new();
                    word.extend(first.to_uppercase());
                    word.push_str(chars.as_str());
                    word
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn normalize_reason_description(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        "Passive analysis flagged a suspicious signal.".to_string()
    } else if trimmed == trimmed.to_ascii_uppercase() && trimmed.contains('_') {
        normalize_reason_name(trimmed)
    } else {
        trimmed.to_string()
    }
}

pub fn normalize_severity(severity: Severity, risk: f64) -> NormalizedSeverity {
    match severity {
        Severity::Clean => NormalizedSeverity::Clean,
        Severity::Malicious => NormalizedSeverity::High,
        Severity::Suspicious => {
            if risk >= 5.0 {
                NormalizedSeverity::High
            } else if risk >= 3.5 {
                NormalizedSeverity::Medium
            } else {
                NormalizedSeverity::Low
            }
        }
    }
}

pub fn verdict_from_severity(severity: Severity) -> SummaryVerdict {
    match severity {
        Severity::Clean => SummaryVerdict::Clean,
        Severity::Suspicious => SummaryVerdict::Suspicious,
        Severity::Malicious => SummaryVerdict::Malicious,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_reason_description, normalize_reason_name, normalize_reason_source,
        normalize_severity, source_label, verdict_from_severity, NormalizedSeverity,
        SummaryVerdict,
    };
    use crate::r#static::types::Severity;

    #[test]
    fn normalizes_reason_sources_consistently() {
        assert_eq!(normalize_reason_source("YARA_RULE_MATCH"), "rule");
        assert_eq!(normalize_reason_source("EMULATED_JS_CHAIN"), "emulation");
        assert_eq!(normalize_reason_source("ML_SCORE_HIGH"), "ml");
        assert_eq!(normalize_reason_source("CACHE_HIT"), "cache");
        assert_eq!(normalize_reason_source("SCRIPT_CONCAT_EVAL"), "heuristic");
    }

    #[test]
    fn normalizes_severity_levels() {
        assert_eq!(
            normalize_severity(Severity::Clean, 0.1),
            NormalizedSeverity::Clean
        );
        assert_eq!(
            normalize_severity(Severity::Suspicious, 2.0),
            NormalizedSeverity::Low
        );
        assert_eq!(
            normalize_severity(Severity::Suspicious, 4.0),
            NormalizedSeverity::Medium
        );
        assert_eq!(
            normalize_severity(Severity::Suspicious, 6.0),
            NormalizedSeverity::High
        );
        assert_eq!(
            normalize_severity(Severity::Malicious, 8.0),
            NormalizedSeverity::High
        );
        assert_eq!(
            verdict_from_severity(Severity::Suspicious),
            SummaryVerdict::Suspicious
        );
    }

    #[test]
    fn normalizes_reason_names_and_labels() {
        assert_eq!(
            normalize_reason_name("SCRIPT_CONCAT_EVAL"),
            "Script Concat Eval"
        );
        assert_eq!(
            normalize_reason_description("Suspicious script concatenation pattern"),
            "Suspicious script concatenation pattern"
        );
        assert_eq!(source_label("rule"), "Local rule");
    }
}

pub fn run(ctx: &ScanContext, severity: Severity) {
    let emit_stdout = std::env::var("PROJECTX_REPORT_STDOUT")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if emit_stdout {
        let summary = summary::build(ctx, severity);
        println!("{}", summary);
    }
}

pub fn persist(
    ctx: &ScanContext,
    severity: Severity,
    original_path: &Path,
    quarantine_path: &Path,
    restored_to_original_path: bool,
) -> Result<(String, PathBuf), String> {
    let report_json = json::render(
        ctx,
        severity,
        original_path,
        quarantine_path,
        restored_to_original_path,
    );
    let report_path = write_report_file(&report_json, &ctx.file_name)?;
    append_telemetry(&json::value(
        ctx,
        severity,
        original_path,
        quarantine_path,
        restored_to_original_path,
    ))?;
    Ok((report_json, report_path))
}

fn write_report_file(report_json: &str, file_name: &str) -> Result<PathBuf, String> {
    let reports_dir = Path::new("quarantine/reports");
    fs::create_dir_all(reports_dir)
        .map_err(|error| format!("Failed to create reports directory: {error}"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let sanitized_name = file_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let path = reports_dir.join(format!("{timestamp}_{sanitized_name}.json"));
    fs::write(&path, report_json)
        .map_err(|error| format!("Failed to write JSON report: {error}"))?;
    Ok(path)
}

fn append_telemetry(value: &serde_json::Value) -> Result<(), String> {
    let telemetry_path = Path::new("quarantine/scan_telemetry.jsonl");
    if let Some(parent) = telemetry_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create telemetry directory: {error}"))?;
    }

    let line = serde_json::to_string(value)
        .map_err(|error| format!("Failed to serialize telemetry entry: {error}"))?;
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(telemetry_path)
        .map_err(|error| format!("Failed to open telemetry log: {error}"))?;
    writeln!(file, "{line}").map_err(|error| format!("Failed to append telemetry log: {error}"))?;
    Ok(())
}
