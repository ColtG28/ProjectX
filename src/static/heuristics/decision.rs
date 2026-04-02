use crate::r#static::config::Thresholds;
use crate::r#static::types::Severity;

pub fn classify(risk: f64, thresholds: &Thresholds) -> Severity {
    if risk >= thresholds.malicious_min {
        Severity::Malicious
    } else if risk >= thresholds.suspicious_min {
        Severity::Suspicious
    } else {
        Severity::Clean
    }
}
