pub fn contains_concat_eval(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    lower.contains("eval(") && (lower.contains("+") || lower.contains("concat("))
}
