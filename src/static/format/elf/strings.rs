use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();
    if text.contains("/bin/sh") {
        findings.push(Finding::new(
            "ELF_SHELL",
            "File references /bin/sh, which can indicate shell-launch behavior on Unix-like systems",
            1.0,
        ));
    }
    if contains_all(&text, &["/bin/sh", "curl "]) || contains_all(&text, &["/bin/sh", "wget "]) {
        findings.push(Finding::new(
            "ELF_SHELL_DOWNLOADER",
            "File combines shell-launch and downloader strings in a way commonly used to fetch follow-on content",
            2.2,
        ));
    }
    if contains_all(&text, &["/bin/sh", "nc "]) || contains_all(&text, &["/bin/sh", "socket"]) {
        findings.push(Finding::new(
            "ELF_SHELL_NETWORK_CHAIN",
            "File combines shell-launch and network-control strings that suggest interactive follow-on behavior",
            2.0,
        ));
    }
    findings
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}
