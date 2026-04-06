pub fn is_suspicious(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let obfuscation = [
        "eval(",
        "fromcharcode",
        "atob(",
        "unescape(",
        "new function",
    ];
    let runtime_like_markers = [
        "activexobject",
        "wscript.shell",
        "xmlhttp",
        "adodb.stream",
        "window.location",
    ];

    let obfuscation_hits = obfuscation
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();
    let runtime_like_hits = runtime_like_markers
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();

    obfuscation_hits >= 2 || (obfuscation_hits >= 1 && runtime_like_hits >= 1)
}

pub fn strong_indicators(input: &str) -> Vec<&'static str> {
    let lower = input.to_ascii_lowercase();
    let mut indicators = Vec::new();

    if contains_all(&lower, &["wscript.shell", "msxml2.xmlhttp", "adodb.stream"]) {
        indicators.push("scripted downloader chain");
    }
    if contains_all(&lower, &["fromcharcode", "activexobject", "wscript.shell"]) {
        indicators.push("obfuscated launcher chain");
    }
    if contains_all(&lower, &["atob(", "xmlhttp", "window.location"]) {
        indicators.push("decoded network redirect chain");
    }

    indicators
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}
