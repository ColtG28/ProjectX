use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if bytes.len() > 30 * 1024 * 1024 {
        findings.push(Finding::new("PE_LARGE", "Unusually large PE file", 1.0));
    }
    findings
}
