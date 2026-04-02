use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if text.contains("powershell") {
        vec![Finding::new(
            "PE_EMBEDDED_POWERSHELL",
            "PE contains PowerShell marker",
            1.5,
        )]
    } else {
        Vec::new()
    }
}
