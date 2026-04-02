use crate::r#static::types::View;

pub fn build(bytes: &[u8]) -> View {
    const MAX_PRINTABLE_BYTES: usize = 4096;

    let printable = bytes
        .iter()
        .take(MAX_PRINTABLE_BYTES)
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect::<String>();

    let content = if bytes.len() > MAX_PRINTABLE_BYTES {
        format!(
            "{printable}\n... truncated printable preview ({MAX_PRINTABLE_BYTES} of {} bytes shown)",
            bytes.len()
        )
    } else {
        printable
    };

    View::new("raw.printable", content)
}
