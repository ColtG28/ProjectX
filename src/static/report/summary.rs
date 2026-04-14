use crate::r#static::context::ScanContext;
use crate::r#static::report::{
    normalize_reason_description, normalize_reason_name, normalize_reason_source, source_label,
};
use crate::r#static::types::Severity;

pub fn build(ctx: &ScanContext, severity: Severity) -> String {
    let headline = match severity {
        Severity::Clean => "No strong malicious signals were identified".to_string(),
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

    format!(
        "{headline}. {} finding(s) recorded. Risk {:.2}, safety {:.2}. Top signal: {}{}{}",
        ctx.findings.len(),
        ctx.score.risk,
        ctx.score.safety,
        top_reason,
        triage_note,
        intelligence_note
    )
}
