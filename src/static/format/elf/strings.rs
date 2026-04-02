use crate::r#static::types::Finding;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    if text.contains("/bin/sh") {
        vec![Finding::new("ELF_SHELL", "ELF references /bin/sh", 1.0)]
    } else {
        Vec::new()
    }
}
