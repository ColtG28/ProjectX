pub fn simplify_js_concat(input: &str) -> String {
    input
        .replace("\"+\"", "")
        .replace("'+\"", "")
        .replace("\"+'", "")
}
