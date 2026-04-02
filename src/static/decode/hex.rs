pub fn try_decode(input: &str) -> Vec<String> {
    let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() < 8 || cleaned.len() % 2 != 0 {
        return Vec::new();
    }

    let mut bytes = Vec::new();
    for pair in cleaned.as_bytes().chunks(2) {
        let h = std::str::from_utf8(pair).ok();
        let Some(h) = h else { return Vec::new() };
        let Ok(value) = u8::from_str_radix(h, 16) else {
            return Vec::new();
        };
        bytes.push(value);
    }

    match String::from_utf8(bytes) {
        Ok(s) => vec![s],
        Err(_) => Vec::new(),
    }
}
