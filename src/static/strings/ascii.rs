pub fn extract(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();

    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else {
            if current.len() >= min_len {
                out.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        out.push(String::from_utf8_lossy(&current).to_string());
    }

    out
}
