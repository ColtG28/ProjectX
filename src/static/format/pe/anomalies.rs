use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if bytes.len() > 30 * 1024 * 1024 {
        findings.push(Finding::new(
            "PE_LARGE",
            "File is unusually large for a Windows executable, which can indicate bundled payloads or padded content",
            1.0,
        ));
    }
    findings
}

