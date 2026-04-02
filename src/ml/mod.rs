pub mod features;
pub mod feedback;
pub mod model;
pub mod threat_intel;

use crate::r#static::context::ScanContext;
use crate::r#static::types::{Finding, MlAssessment};

pub fn run(ctx: &mut ScanContext) {
    let feature_vector = features::extract(ctx);
    let mut assessment = model::score(&feature_vector);

    let threat_matches = threat_intel::lookup_hash(&ctx.sha256);
    if !threat_matches.is_empty() {
        let providers = threat_matches
            .iter()
            .map(|item| item.provider)
            .collect::<Vec<_>>()
            .join(", ");
        assessment
            .reasons
            .push(format!("Threat-intel hash hit from {}", providers));
        assessment.dynamic_score = assessment.dynamic_score.max(0.95);
        assessment.blended_score = assessment.blended_score.max(0.97);
        assessment.label = "malicious".to_string();
        for threat_match in threat_matches {
            ctx.push_finding(Finding::new(
                "THREAT_INTEL_HASH_MATCH",
                format!(
                    "Threat-intel provider {} matched file hash {} ({})",
                    threat_match.provider, ctx.sha256, threat_match.detail
                ),
                3.0,
            ));
        }
    }

    if assessment.blended_score >= 0.8 {
        ctx.push_finding(Finding::new(
            "ML_HIGH_RISK",
            format!(
                "ML risk model flagged the sample as {} ({:.2})",
                assessment.label, assessment.blended_score
            ),
            1.5,
        ));
    }

    let assessment_for_feedback = MlAssessment {
        static_score: assessment.static_score,
        dynamic_score: assessment.dynamic_score,
        blended_score: assessment.blended_score,
        label: assessment.label.clone(),
        reasons: assessment.reasons.clone(),
    };
    let _ = feedback::record_scan_observation(&ctx.sha256, &assessment_for_feedback);
    ctx.ml_assessment = Some(assessment_for_feedback);
    ctx.push_view(crate::r#static::types::View::new(
        "ml.assessment",
        serde_json::to_string(&ctx.ml_assessment).unwrap_or_else(|_| "{}".to_string()),
    ));
    ctx.log_event(
        "ml",
        format!(
            "ML assessment {} with blended score {:.2}",
            assessment.label, assessment.blended_score
        ),
    );
}
