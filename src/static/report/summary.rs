use crate::r#static::context::ScanContext;
use crate::r#static::report::{
    normalize_reason_description, normalize_reason_name, normalize_reason_source, source_label,
};
use crate::r#static::types::Severity;

pub fn build(ctx: &ScanContext, severity: Severity) -> String {
    let headline = match severity {
        Severity::Clean if !ctx.findings.is_empty() => {
            "Low-risk passive signals were observed, but no suspicious verdict was produced"
                .to_string()
        }
        Severity::Clean => "No concerning passive signals were identified".to_string(),
        Severity::Suspicious => {
            "File should be reviewed because passive signals warrant closer attention".to_string()
        }
        Severity::Malicious => {
            "File is likely malicious because multiple passive indicators corroborate each other"
                .to_string()
        }
    };

    let top_reason = ctx
        .findings
        .iter()
        .max_by(|left, right| {
            left.weight
                .partial_cmp(&right.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|finding| {
            let source = source_label(normalize_reason_source(&finding.code));
            let name = normalize_reason_name(&finding.code);
            let description = normalize_reason_description(&finding.message);
            format!("{source}: {name}. {description}")
        })
        .unwrap_or_else(|| "No detailed finding text was recorded.".to_string());

    let triage_note = ctx
        .threat_severity
        .as_ref()
        .map(|summary| format!(" Triage score {:.2}.", summary.severity_score))
        .unwrap_or_default();
    let intelligence_note = ctx
        .intelligence
        .as_ref()
        .map(|summary| {
            let mut notes = Vec::new();
            if !summary.reputation_hits.is_empty() {
                notes.push("Local reputation data increased confidence".to_string());
            }
            if !summary.trust_reasons.is_empty() {
                let categories = if summary.trust_categories.is_empty() {
                    "known-safe context".to_string()
                } else {
                    summary.trust_categories.join(", ")
                };
                let ecosystems = if summary.trust_ecosystems.is_empty() {
                    String::new()
                } else {
                    format!(" across {}", summary.trust_ecosystems.join(", "))
                };
                let vendors = if summary.trust_vendors.is_empty() {
                    String::new()
                } else {
                    format!(" from {}", summary.trust_vendors.join(", "))
                };
                notes.push(format!(
                    "Trust context ({categories}{ecosystems}{vendors}) reduced confidence only in weak standalone signals"
                ));
            }
            if summary.external_intelligence_enabled {
                notes.push(format!(
                    "External intelligence status: {}",
                    summary.external_intelligence_status
                ));
            } else {
                notes.push("External intelligence remained disabled".to_string());
            }
            if notes.is_empty() {
                String::new()
            } else {
                format!(" {}.", notes.join(". "))
            }
        })
        .unwrap_or_default();
    let top_signal_label = if matches!(severity, Severity::Clean) {
        "Most notable observed signal"
    } else {
        "Top signal"
    };

    format!(
        "{headline}. {} finding(s) recorded. Risk {:.2}, safety {:.2}. {top_signal_label}: {}{}{}",
        ctx.findings.len(),
        ctx.score.risk,
        ctx.score.safety,
        top_reason,
        triage_note,
        intelligence_note
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#static::config::ScanConfig;
    use crate::r#static::types::Finding;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn clean_summary_with_findings_explains_low_risk_observation() {
        let root = std::env::temp_dir().join(format!(
            "projectx_summary_test_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("root");
        let sample = root.join("messages.json");
        fs::write(&sample, b"{\"hello\":\"world\"}").expect("sample");

        let mut ctx = ScanContext::from_path(&sample, ScanConfig::default()).expect("context");
        ctx.score.risk = 0.0;
        ctx.score.safety = 10.0;
        ctx.findings.push(Finding::new(
            "DECODED_ACTIVE_CONTENT",
            "Observed a decoded script-like string in an otherwise clean JSON file.",
            0.35,
        ));

        let summary = build(&ctx, Severity::Clean);
        assert!(summary.contains("no suspicious verdict"));
        assert!(summary.contains("Most notable observed signal"));

        let _ = fs::remove_dir_all(&root);
    }
}
