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

#[cfg(test)]
mod tests {
    use super::check;

    #[test]
    fn large_pe_message_is_human_readable() {
        let findings = check(&vec![0u8; 31 * 1024 * 1024]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.starts_with("File is unusually large"));
    }
}
