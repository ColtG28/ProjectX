use crate::r#static::types::Finding;

pub fn format_line(finding: &Finding) -> String {
    format!(
        "[{}] {} (weight={:.2})",
        finding.code, finding.message, finding.weight
    )
}
