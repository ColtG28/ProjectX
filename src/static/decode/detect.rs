pub fn should_try(input: &str) -> bool {
    let len = input.len();
    len >= 6
        && (input.contains('%')
            || input.contains('&')
            || input.contains("=")
            || input.starts_with("0x")
            || input
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=_-".contains(c)))
}
