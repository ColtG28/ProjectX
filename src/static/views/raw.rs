use crate::r#static::types::View;

pub fn build(bytes: &[u8]) -> View {
    let preview = bytes
        .iter()
        .take(256)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    View::new("raw.hex", preview)
}
