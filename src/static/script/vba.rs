pub fn is_suspicious(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let autorun = ["autoopen", "document_open", "workbook_open"];
    let execution = [
        "shell(",
        "createobject",
        "wscript.shell",
        "adodb.stream",
        "msxml2.xmlhttp",
        "urldownloadtofile",
    ];

    let autorun_hits = autorun
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();
    let execution_hits = execution
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();

    execution_hits >= 2 || (autorun_hits >= 1 && execution_hits >= 1)
}
