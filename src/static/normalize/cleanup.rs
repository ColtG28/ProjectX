pub fn trim_noise(input: &str) -> String {
    input
        .trim_matches(|c: char| c.is_ascii_control())
        .trim()
        .to_string()
}
