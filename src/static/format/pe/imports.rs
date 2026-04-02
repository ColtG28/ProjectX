use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();
    if text.contains("virtualalloc") && text.contains("createremotethread") {
        findings.push(Finding::new(
            "PE_INJECTION_IMPORTS",
            "Potential process-injection API combination",
            2.5,
        ));
    }
    findings
}
