pub fn extract(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();

    for &b in bytes {
        let c = b as char;
        if c.is_ascii() && !c.is_ascii_control() {
            current.push(c);
        } else {
            if current.len() >= min_len {
                out.push(current.clone());
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        out.push(current);
    }

    out
}
