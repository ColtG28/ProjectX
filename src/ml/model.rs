use super::features::FeatureVector;

#[derive(Debug, Clone, Default)]
pub struct Assessment {
    pub static_score: f64,
    pub dynamic_score: f64,
    pub blended_score: f64,
    pub label: String,
    pub reasons: Vec<String>,
}

pub fn score(features: &FeatureVector) -> Assessment {
    let static_score = ((features.suspicious_weight / 12.0)
        + (features.yara_hits as f64 * 0.08)
        + (features.decoded_count.min(25) as f64 * 0.01)
        + (features.artifact_count.min(20) as f64 * 0.015)
        + (features.nested_depth.min(6) as f64 * 0.03))
        .clamp(0.0, 1.0);
    let dynamic_score = ((features.emulation_runtime_hits as f64 * 0.12)
        + (features.dynamic_runtime_yara_hits as f64 * 0.18)
        + (features.dynamic_network_events.min(5) as f64 * 0.08)
        + (features.dynamic_process_events.min(5) as f64 * 0.05)
        + (features.dynamic_file_events.min(10) as f64 * 0.02)
        + f64::from(features.has_network_indicator) * 0.25
        + f64::from(features.has_macro_indicator) * 0.2)
        .clamp(0.0, 1.0);
    let blended_score = (static_score * 0.7 + dynamic_score * 0.3).clamp(0.0, 1.0);

    let mut reasons = Vec::new();
    if features.yara_hits > 0 {
        reasons.push(format!(
            "{} YARA-style signature hit(s)",
            features.yara_hits
        ));
    }
    if features.emulation_runtime_hits > 0 {
        reasons.push(format!(
            "{} runtime-emulation YARA hit(s)",
            features.emulation_runtime_hits
        ));
    }
    if features.dynamic_runtime_yara_hits > 0 {
        reasons.push(format!(
            "{} dynamic sandbox YARA hit(s)",
            features.dynamic_runtime_yara_hits
        ));
    }
    if features.dynamic_network_events > 0 {
        reasons.push(format!(
            "{} dynamic network event(s)",
            features.dynamic_network_events
        ));
    }
    if features.has_macro_indicator {
        reasons.push("Office macro indicators observed".to_string());
    }
    if features.has_network_indicator {
        reasons.push("Network-behavior markers observed".to_string());
    }

    let label = if blended_score >= 0.85 {
        "malicious"
    } else if blended_score >= 0.45 {
        "suspicious"
    } else {
        "clean"
    };

    Assessment {
        static_score,
        dynamic_score,
        blended_score,
        label: label.to_string(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::score;
    use crate::ml::features::FeatureVector;

    #[test]
    fn scores_high_risk_feature_sets() {
        let assessment = score(&FeatureVector {
            finding_count: 8,
            suspicious_weight: 12.0,
            decoded_count: 10,
            artifact_count: 6,
            nested_depth: 3,
            yara_hits: 2,
            emulation_runtime_hits: 1,
            has_macro_indicator: true,
            has_network_indicator: true,
            dynamic_network_events: 2,
            dynamic_process_events: 1,
            dynamic_file_events: 1,
            dynamic_runtime_yara_hits: 1,
        });
        assert_eq!(assessment.label, "malicious");
        assert!(assessment.blended_score >= 0.85);
    }
}
