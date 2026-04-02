use crate::r#static::types::View;

pub fn build(bytes: &[u8]) -> View {
    let first_kb = bytes.iter().take(1024).count();
    View::new(
        "sections.summary",
        format!("bytes_in_first_block={}", first_kb),
    )
}
