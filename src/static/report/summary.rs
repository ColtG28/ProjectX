use crate::r#static::context::ScanContext;
use crate::r#static::report::{
    normalize_reason_description, normalize_reason_name, normalize_reason_source, source_label,
};
use crate::r#static::types::Severity;

pub fn build(ctx: &ScanContext, severity: Severity) -> String {
    let headline = match severity {
        Severity::Clean => "No strong malicious signals were identified".to_string(),
        Severity::Suspicious => "File should be reviewed due to suspicious signals".to_string(),
        Severity::Malicious => {
            "File shows multiple high-confidence malicious indicators".to_string()
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

    format!(
        "{headline}. {} finding(s) recorded. Risk {:.2}, safety {:.2}. Top signal: {}{}",
        ctx.findings.len(),
        ctx.score.risk,
        ctx.score.safety,
        top_reason,
        triage_note
    )
}

#[cfg(test)]
mod tests {
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;
    use crate::r#static::types::{Finding, Severity};

    use super::build;

    #[test]
    fn summary_highlights_top_signal_in_plain_language() {
        let path =
            std::env::temp_dir().join(format!("projectx_summary_{}.txt", std::process::id()));
        std::fs::write(&path, "hello").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        ctx.score.risk = 6.2;
        ctx.score.safety = 3.8;
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "Script builds code from string fragments before evaluating it",
            1.5,
        ));
        ctx.push_finding(Finding::new(
            "YARA_MATCH",
            "Local rule matched: suspicious.downloader.pattern",
            2.0,
        ));

        let summary = build(&ctx, Severity::Suspicious);
        assert!(summary.contains("File should be reviewed"));
        assert!(summary.contains("Top signal: Local rule"));
        assert!(summary.contains("Local rule matched"));

        let _ = std::fs::remove_file(path);
    }
}
