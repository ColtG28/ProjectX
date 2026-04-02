use crate::r#static::types::Finding;

pub fn suspicious_traits(findings: &[Finding]) -> usize {
    findings.iter().filter(|f| f.weight >= 1.0).count()
}
