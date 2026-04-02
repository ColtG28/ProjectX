pub fn extract_all(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(super::ascii::extract(bytes, 4));
    out.extend(super::utf8::extract(bytes, 4));
    out.extend(super::utf16::extract(bytes, 4));
    out.extend(super::raw::extract(bytes, 4));
    out
}
