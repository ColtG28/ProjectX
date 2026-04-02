pub fn try_decode(input: &str) -> Vec<String> {
    let decoded = crate::r#static::normalize::unicode::decode_percent_hex(input);
    if decoded == input {
        Vec::new()
    } else {
        vec![decoded]
    }
}
