use crate::r#static::context::ScanContext;
use crate::r#static::types::Severity;

pub fn build(ctx: &ScanContext, severity: Severity) -> String {
    let threat = ctx
        .threat_severity
        .as_ref()
        .map(|summary| format!(" threat={:.2}", summary.severity_score))
        .unwrap_or_default();
    format!(
        "Scan Summary: file={} severity={:?} findings={} risk={:.2} safety={:.2}{}",
        ctx.file_name,
        severity,
        ctx.findings.len(),
        ctx.score.risk,
        ctx.score.safety,
        threat,
    )
}
