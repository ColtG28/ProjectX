pub fn decode_percent_hex(input: &str) -> String {
    let mut out = String::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                let value = (high << 4) | low;
                out.push(value as char);
                i += 3;
                continue;
            }
        }

        let remaining = &input[i..];
        if let Some(ch) = remaining.chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::decode_percent_hex;

    #[test]
    fn decodes_ascii_percent_sequences() {
        assert_eq!(decode_percent_hex("a%20b"), "a b");
    }

    #[test]
    fn handles_non_ascii_without_panicking() {
        assert_eq!(decode_percent_hex("$4�%�"), "$4�%�");
    }
}
