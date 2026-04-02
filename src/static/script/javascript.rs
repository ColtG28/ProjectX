pub fn is_suspicious(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let obfuscation = [
        "eval(",
        "fromcharcode",
        "atob(",
        "unescape(",
        "new function",
    ];
    let execution = [
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
    let execution_hits = execution
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();

    obfuscation_hits >= 2 || (obfuscation_hits >= 1 && execution_hits >= 1)
}
