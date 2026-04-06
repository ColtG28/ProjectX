use regex::Regex;
use std::sync::OnceLock;

pub fn contains_charcode_pattern(input: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(fromcharcode|\[char\][ \t\r\n]*[0-9]{2,3})").expect("regex")
    })
    .is_match(input)
}
