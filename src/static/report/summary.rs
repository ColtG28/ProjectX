use crate::r#static::context::ScanContext;
use crate::r#static::types::Severity;

pub fn build(ctx: &ScanContext, severity: Severity) -> String {
    format!(
        "Scan Summary: file={} severity={:?} findings={} risk={:.2} safety={:.2}",
        ctx.file_name,
        severity,
        ctx.findings.len(),
        ctx.score.risk,
        ctx.score.safety
    )
}
