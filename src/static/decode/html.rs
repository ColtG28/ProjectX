pub fn decode_entities(input: &str) -> Vec<String> {
    let decoded = input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");

    if decoded == input {
        Vec::new()
    } else {
        vec![decoded]
    }
}
