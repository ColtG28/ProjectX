use regex::Regex;

pub fn contains_charcode_pattern(input: &str) -> bool {
    let re = Regex::new(r"(?i)(fromcharcode|\[char\]\s*\d{2,3})").expect("regex compiles");
    re.is_match(input)
}
