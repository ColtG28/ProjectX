pub fn extract(bytes: &[u8], min_len: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    text.split(|c: char| c.is_control())
        .filter_map(|s| {
            let trimmed = s.trim();
            (trimmed.chars().count() >= min_len).then(|| trimmed.to_string())
        })
        .collect()
}
