use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ml::features::FeatureVector;
use crate::r#static::context::ScanContext;
use crate::r#static::types::MlAssessment;
use crate::r#static::types::ThreatSeveritySummary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    pub sha256: String,
    pub path: Option<String>,
    pub blended_score: f64,
    pub ensemble_score: f64,
    pub threat_severity_score: f64,
    pub label: String,
    pub analyst_label: Option<String>,
    pub reasons: Vec<String>,
    pub features: Option<FeatureVector>,
    pub recommended_for_retraining: bool,
}

pub fn record_scan_observation(
    ctx: &ScanContext,
    features: &FeatureVector,
    assessment: &MlAssessment,
    threat_severity: &ThreatSeveritySummary,
) -> Result<(), String> {
    let record = FeedbackRecord {
        sha256: ctx.sha256.clone(),
        path: Some(ctx.input_path.display().to_string()),
        blended_score: assessment.blended_score,
        ensemble_score: assessment.ensemble_score,
        threat_severity_score: threat_severity.severity_score,
        label: assessment.label.clone(),
        analyst_label: None,
        reasons: assessment.reasons.clone(),
        features: Some(features.clone()),
        recommended_for_retraining: should_queue_for_retraining(assessment, threat_severity),
    };
    append(&record)?;
    if record.recommended_for_retraining {
        append_active_learning_candidate(&record)?;
    }
    Ok(())
}

pub fn record_analyst_feedback(
    sha256: &str,
    predicted: &MlAssessment,
    analyst_label: &str,
) -> Result<(), String> {
    append(&FeedbackRecord {
        sha256: sha256.to_string(),
        path: None,
        blended_score: predicted.blended_score,
        ensemble_score: predicted.ensemble_score,
        threat_severity_score: predicted.ensemble_score,
        label: predicted.label.clone(),
        analyst_label: Some(analyst_label.to_string()),
        reasons: predicted.reasons.clone(),
        features: None,
        recommended_for_retraining: true,
    })
}

fn should_queue_for_retraining(
    assessment: &MlAssessment,
    threat_severity: &ThreatSeveritySummary,
) -> bool {
    let uncertainty = (assessment.ensemble_score - 0.5).abs();
    uncertainty <= 0.15
        || assessment.label == "suspicious"
        || threat_severity.recommended_action == "review_or_triage"
}

fn append(record: &FeedbackRecord) -> Result<(), String> {
    let path = Path::new("quarantine/ml_feedback.jsonl");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create ML feedback directory: {error}"))?;
    }

    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("Failed to open ML feedback file: {error}"))?;
    let line = serde_json::to_string(record)
        .map_err(|error| format!("Failed to serialize ML feedback: {error}"))?;
    writeln!(file, "{line}").map_err(|error| format!("Failed to write ML feedback: {error}"))
}

fn append_active_learning_candidate(record: &FeedbackRecord) -> Result<(), String> {
    let path = Path::new("quarantine/ml_active_learning_queue.jsonl");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create active-learning directory: {error}"))?;
    }
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("Failed to open active-learning queue: {error}"))?;
    let line = serde_json::to_string(record)
        .map_err(|error| format!("Failed to serialize active-learning record: {error}"))?;
    writeln!(file, "{line}")
        .map_err(|error| format!("Failed to write active-learning record: {error}"))
}
