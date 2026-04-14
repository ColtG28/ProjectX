use super::features::FeatureVector;

pub const MALICIOUS_LABEL_THRESHOLD: f64 = 0.80;
pub const SUSPICIOUS_LABEL_THRESHOLD: f64 = 0.45;

#[derive(Debug, Clone, Default)]
pub struct Assessment {
    pub static_signal_score: f64,
    pub heuristic_signal_score: f64,
    pub static_score: f64,
    pub runtime_signal_score: f64,
    pub intel_score: f64,
    pub evasion_score: f64,
    pub ensemble_score: f64,
    pub blended_score: f64,
    pub label: String,
    pub reasons: Vec<String>,
}

pub fn score(features: &FeatureVector) -> Assessment {
    let heuristic_signal_score = (features.suspicious_weight / 12.0).clamp(0.0, 1.0);
    let static_signal_score = ((features.yara_hits as f64 * 0.08)
        + (features.decoded_count.min(25) as f64 * 0.01)
        + (features.artifact_count.min(20) as f64 * 0.015)
        + (features.nested_depth.min(6) as f64 * 0.03))
        .clamp(0.0, 1.0);
    let static_score = (heuristic_signal_score * 0.45 + static_signal_score * 0.55).clamp(0.0, 1.0);
    let runtime_signal_score = ((features.emulation_runtime_hits as f64 * 0.25)
        + f64::from(features.has_network_indicator) * 0.35
        + f64::from(features.has_macro_indicator) * 0.25)
        .clamp(0.0, 1.0);
    let evasion_score = ((features.nested_depth.min(6) as f64 * 0.08)
        + (features.decoded_count.min(25) as f64 * 0.012)
        + (features.artifact_count.min(20) as f64 * 0.02)
        + f64::from(features.has_macro_indicator) * 0.15)
        .clamp(0.0, 1.0);
    let intel_score = 0.0;
    let ensemble_score = (static_score * 0.25
        + runtime_signal_score * 0.45
        + heuristic_signal_score * 0.15
        + evasion_score * 0.15)
        .clamp(0.0, 1.0);
    let blended_score = ensemble_score;

    let mut reasons = Vec::new();
    if features.yara_hits > 0 {
        reasons.push(format!(
            "{} YARA-style signature hit(s)",
            features.yara_hits
        ));
    }
    if features.emulation_runtime_hits > 0 {
        reasons.push(format!(
            "{} emulation pattern hit(s)",
            features.emulation_runtime_hits
        ));
    }
    if features.has_macro_indicator {
        reasons.push("Office macro indicators observed".to_string());
    }
    if features.has_network_indicator {
        reasons.push("Network-behavior markers observed".to_string());
    }
    if evasion_score >= 0.35 {
        reasons.push("Potential evasion / packing indicators observed".to_string());
    }

    let label = if blended_score >= MALICIOUS_LABEL_THRESHOLD {
        "malicious"
    } else if blended_score >= SUSPICIOUS_LABEL_THRESHOLD {
        "suspicious"
    } else {
        "clean"
    };

    Assessment {
        static_signal_score,
        heuristic_signal_score,
        static_score,
        runtime_signal_score,
        intel_score,
        evasion_score,
        ensemble_score,
        blended_score,
        label: label.to_string(),
        reasons,
    }
}
