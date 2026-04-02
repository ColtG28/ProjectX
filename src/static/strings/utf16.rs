pub fn extract(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();

    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        match char::from_u32(unit as u32) {
            Some(ch) if !ch.is_control() && !ch.is_ascii_control() => current.push(ch),
            Some(ch) if ch == '\t' || ch == '\n' || ch == '\r' || ch == ' ' => current.push(ch),
            _ => {
                flush_if_long_enough(&mut out, &mut current, min_len);
            }
        }
    }

    flush_if_long_enough(&mut out, &mut current, min_len);
    out
}

fn flush_if_long_enough(out: &mut Vec<String>, current: &mut String, min_len: usize) {
    let trimmed = current.trim();
    if trimmed.chars().count() >= min_len {
        out.push(trimmed.to_string());
    }
    current.clear();
}

#[cfg(test)]
mod tests {
    use super::extract;

    #[test]
    fn extracts_wide_ascii_fragments_from_mixed_data() {
        let bytes = b"X\0Y\0Z\0\0\0p\0o\0w\0e\0r\0s\0h\0e\0l\0l\0";
        let values = extract(bytes, 4);
        assert!(values.iter().any(|value| value.contains("powershell")));
    }
}
