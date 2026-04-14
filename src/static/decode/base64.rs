const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn try_decode(input: &str) -> Vec<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '+' | '/' | '=' | '-' | '_'))
        .collect();
    if cleaned.len() < 8 {
        return Vec::new();
    }

    let mut out = Vec::new();
    for candidate in candidate_encodings(&cleaned) {
        let Some(bytes) = decode_bytes(&candidate) else {
            continue;
        };
        if let Some(text) = text_from_bytes(&bytes) {
            out.push(text);
        }
    }
    out
}

fn candidate_encodings(input: &str) -> Vec<String> {
    let mut candidates = Vec::new();

    for variant in [input.to_string(), input.replace('-', "+").replace('_', "/")] {
        let remainder = variant.len() % 4;
        let padded = if remainder == 0 {
            variant
        } else {
            format!("{variant}{}", "=".repeat(4 - remainder))
        };

        if !candidates.iter().any(|existing| existing == &padded) {
            candidates.push(padded);
        }
    }

    candidates
}

fn decode_bytes(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for chunk in input.as_bytes().chunks(4) {
        let mut vals = [0u8; 4];
        let mut pad = 0;

        for (i, b) in chunk.iter().enumerate() {
            if *b == b'=' {
                vals[i] = 0;
                pad += 1;
                continue;
            }
            vals[i] = B64_TABLE.iter().position(|x| x == b)? as u8;
        }

        out.push((vals[0] << 2) | (vals[1] >> 4));
        if pad < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if pad == 0 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

fn text_from_bytes(bytes: &[u8]) -> Option<String> {
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        return Some(text);
    }

    let printable = bytes
        .iter()
        .filter(|b| matches!(**b, b'\n' | b'\r' | b'\t') || b.is_ascii_graphic() || **b == b' ')
        .count();

    (printable * 100 / bytes.len().max(1) >= 85)
        .then(|| String::from_utf8_lossy(bytes).into_owned())
}
