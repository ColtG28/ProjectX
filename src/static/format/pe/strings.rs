use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();
    if text.contains("powershell") {
        findings.push(Finding::new(
            "PE_EMBEDDED_POWERSHELL",
            "File contains PowerShell-related strings, which can indicate scripted post-launch behavior",
            1.5,
        ));
    }
    if contains_all(&text, &["powershell", "-enc", "downloadstring"]) {
        findings.push(Finding::new(
            "PE_SCRIPTED_DOWNLOADER_STRINGS",
            "File contains PowerShell downloader strings that suggest an encoded scripted follow-on stage",
            2.2,
        ));
    }
    if contains_all(&text, &["rundll32", "urlmon", "http"]) {
        findings.push(Finding::new(
            "PE_LAUNCHER_NETWORK_STRINGS",
            "File contains launcher and network-related strings that suggest a staged execution chain",
            2.0,
        ));
    }
    findings
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::check;

    #[test]
    fn powershell_marker_message_is_clear() {
        let findings = check(b"powershell -enc");
        assert!(findings[0]
            .message
            .starts_with("File contains PowerShell-related strings"));
    }
}
