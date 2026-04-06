use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use projectx::r#static::types::MlAssessment;
use projectx::r#static::{self, config::ScanConfig};

#[test]
fn scan_outcome_exposes_richer_summary_metadata() {
    let path = unique_path("scan_outcome_exposes_richer_summary_metadata.ps1");
    fs::write(&path, "IEX(New-Object Net.WebClient)").unwrap();

    let outcome = r#static::scan_path(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap();

    assert!(!outcome.sha256.is_empty());
    assert!(!outcome.sniffed_mime.is_empty());
    assert!(!outcome.file_name.is_empty());
    assert!(!outcome.signal_sources.is_empty());
    assert_eq!(outcome.findings.len(), outcome.finding_details.len());
    assert!(matches!(
        outcome.normalized_severity,
        projectx::r#static::report::NormalizedSeverity::Clean
            | projectx::r#static::report::NormalizedSeverity::Low
            | projectx::r#static::report::NormalizedSeverity::Medium
            | projectx::r#static::report::NormalizedSeverity::High
    ));
    assert_eq!(outcome.reason_entries.len(), outcome.finding_details.len());

    cleanup_outcome(&path, &outcome);
}

#[test]
fn scan_parallel_still_returns_json_report_for_gui_history() {
    let path = unique_path("scan_parallel_still_returns_json_report_for_gui_history.txt");
    fs::write(&path, "hello projectx").unwrap();

    let results = r#static::scan_inputs_parallel(&[path.clone()], None, Some(1), 8);
    assert_eq!(results.len(), 1);

    let outcome = results[0].outcome.as_ref().unwrap();
    let report = serde_json::from_str::<serde_json::Value>(&outcome.json_report).unwrap();
    assert!(report.get("verdict").is_some());
    assert!(report["file"]["sha256"].is_string());
    assert!(report["verdict"]["normalized_severity"].is_string());
    assert!(report["reasons"].is_array());
    assert!(report["summary"]["warning_count"].is_u64());
    assert!(report.get("sandbox_plan").is_none());
    assert!(report.get("dynamic_analysis").is_none());
    assert!(outcome.report_path.is_file());

    cleanup_outcome(&path, outcome);
}

#[test]
fn ml_assessment_accepts_legacy_dynamic_score_field() {
    let value = serde_json::json!({
        "static_signal_score": 0.1,
        "heuristic_signal_score": 0.2,
        "static_score": 0.3,
        "dynamic_score": 0.4,
        "intel_score": 0.0,
        "evasion_score": 0.1,
        "ensemble_score": 0.5,
        "blended_score": 0.5,
        "label": "suspicious",
        "reasons": ["test"]
    });

    let assessment: MlAssessment = serde_json::from_value(value).unwrap();
    assert_eq!(assessment.runtime_signal_score, 0.4);
}

fn unique_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("projectx_{nanos}_{name}"))
}

fn cleanup_outcome(path: &PathBuf, outcome: &projectx::r#static::ScanOutcome) {
    let _ = fs::remove_file(path);
    if outcome.quarantine_path.is_file() {
        let _ = fs::remove_file(&outcome.quarantine_path);
    }
    if outcome.report_path.is_file() {
        let _ = fs::remove_file(&outcome.report_path);
    }
}
