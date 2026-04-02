use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::r#static::types::MlAssessment;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRecord {
    pub sha256: String,
    pub blended_score: f64,
    pub label: String,
    pub analyst_label: Option<String>,
    pub reasons: Vec<String>,
}

pub fn record_scan_observation(sha256: &str, assessment: &MlAssessment) -> Result<(), String> {
    append(FeedbackRecord {
        sha256: sha256.to_string(),
        blended_score: assessment.blended_score,
        label: assessment.label.clone(),
        analyst_label: None,
        reasons: assessment.reasons.clone(),
    })
}

pub fn record_analyst_feedback(
    sha256: &str,
    predicted: &MlAssessment,
    analyst_label: &str,
) -> Result<(), String> {
    append(FeedbackRecord {
        sha256: sha256.to_string(),
        blended_score: predicted.blended_score,
        label: predicted.label.clone(),
        analyst_label: Some(analyst_label.to_string()),
        reasons: predicted.reasons.clone(),
    })
}

fn append(record: FeedbackRecord) -> Result<(), String> {
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
    let line = serde_json::to_string(&record)
        .map_err(|error| format!("Failed to serialize ML feedback: {error}"))?;
    writeln!(file, "{line}").map_err(|error| format!("Failed to write ML feedback: {error}"))
}
