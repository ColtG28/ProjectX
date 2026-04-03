pub mod features;
pub mod feedback;
pub mod model;
pub mod native_scanner;
pub mod portable_features;
pub mod portable_model;
pub mod threat_intel;

use crate::r#static::context::ScanContext;
use crate::r#static::types::{Finding, MlAssessment, ThreatSeveritySummary};
use model::{MALICIOUS_LABEL_THRESHOLD, SUSPICIOUS_LABEL_THRESHOLD};

pub fn run(ctx: &mut ScanContext) {
    let feature_vector = features::extract(ctx);
    let mut assessment = model::score(&feature_vector);
    let mut intel_score = 0.0f64;

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
        intel_score = 1.0;
        assessment.intel_score = intel_score;
        assessment.dynamic_score = assessment.dynamic_score.max(0.95);
        assessment.ensemble_score = assessment.ensemble_score.max(0.97);
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

    if ctx.config.features.enable_ensemble_scoring {
        assessment.blended_score = (assessment.static_score * 0.35
            + assessment.dynamic_score * 0.25
            + assessment.heuristic_signal_score * 0.15
            + assessment.evasion_score * 0.10
            + intel_score * 0.15)
            .clamp(0.0, 1.0);
        assessment.ensemble_score = assessment.blended_score;
        assessment.label = if assessment.blended_score >= MALICIOUS_LABEL_THRESHOLD {
            "malicious".to_string()
        } else if assessment.blended_score >= SUSPICIOUS_LABEL_THRESHOLD {
            "suspicious".to_string()
        } else {
            "clean".to_string()
        };
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
        static_signal_score: assessment.static_signal_score,
        heuristic_signal_score: assessment.heuristic_signal_score,
        static_score: assessment.static_score,
        dynamic_score: assessment.dynamic_score,
        intel_score: assessment.intel_score,
        evasion_score: assessment.evasion_score,
        ensemble_score: assessment.ensemble_score,
        blended_score: assessment.blended_score,
        label: assessment.label.clone(),
        reasons: assessment.reasons.clone(),
    };
    let threat_severity = build_threat_severity(ctx, &assessment_for_feedback);
    if ctx.config.features.enable_active_learning {
        let _ = feedback::record_scan_observation(
            ctx,
            &feature_vector,
            &assessment_for_feedback,
            &threat_severity,
        );
    }
    ctx.ml_assessment = Some(assessment_for_feedback);
    ctx.threat_severity = Some(threat_severity);
    ctx.push_view(crate::r#static::types::View::new(
        "ml.assessment",
        serde_json::to_string(&ctx.ml_assessment).unwrap_or_else(|_| "{}".to_string()),
    ));
    ctx.push_view(crate::r#static::types::View::new(
        "ml.threat_severity",
        serde_json::to_string(&ctx.threat_severity).unwrap_or_else(|_| "{}".to_string()),
    ));
    ctx.log_event(
        "ml",
        format!(
            "ML assessment {} with blended score {:.2}",
            assessment.label, assessment.blended_score
        ),
    );
}

fn build_threat_severity(ctx: &ScanContext, assessment: &MlAssessment) -> ThreatSeveritySummary {
    let heuristic_risk = (ctx.score.risk / 10.0).clamp(0.0, 1.0);
    let dynamic_pressure = ctx
        .dynamic_analysis
        .as_ref()
        .map(|summary| {
            ((summary.behavior.network_events.min(5) as f64 * 0.08)
                + (summary.behavior.process_events.min(5) as f64 * 0.05)
                + (summary.runtime_yara_hits.len().min(4) as f64 * 0.12))
                .clamp(0.0, 1.0)
        })
        .unwrap_or(0.0);

    let severity_score = (assessment.ensemble_score * 0.55
        + heuristic_risk * 0.25
        + dynamic_pressure * 0.20)
        .clamp(0.0, 1.0);
    let recommended_action = if severity_score >= 0.9 {
        "block_and_escalate"
    } else if severity_score >= 0.7 {
        "quarantine_and_review"
    } else if severity_score >= 0.45 {
        "sandbox_or_triage"
    } else {
        "allow_with_logging"
    };
    let mut contributing_signals = Vec::new();
    if assessment.intel_score > 0.0 {
        contributing_signals.push("threat_intel".to_string());
    }
    if assessment.dynamic_score >= 0.4 {
        contributing_signals.push("dynamic_behavior".to_string());
    }
    if assessment.evasion_score >= 0.3 {
        contributing_signals.push("evasion_indicators".to_string());
    }
    if assessment.heuristic_signal_score >= 0.3 {
        contributing_signals.push("heuristics".to_string());
    }
    if assessment.static_signal_score >= 0.3 {
        contributing_signals.push("static_signals".to_string());
    }
    ThreatSeveritySummary {
        severity_score,
        recommended_action: recommended_action.to_string(),
        contributing_signals,
        auto_sandbox_triggered: false,
    }
}
