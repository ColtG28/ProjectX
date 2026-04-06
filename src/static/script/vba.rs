pub fn is_suspicious(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let autorun = ["autoopen", "document_open", "workbook_open"];
    let automation_markers = [
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
    let automation_hits = automation_markers
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();

    automation_hits >= 2 || (autorun_hits >= 1 && automation_hits >= 1)
}

pub fn strong_indicators(input: &str) -> Vec<&'static str> {
    let lower = input.to_ascii_lowercase();
    let mut indicators = Vec::new();

    if contains_all(&lower, &["autoopen", "createobject", "urldownloadtofile"]) {
        indicators.push("auto-run download sequence");
    }
    if contains_all(
        &lower,
        &["document_open", "createobject", "urldownloadtofile"],
    ) {
        indicators.push("document-open download sequence");
    }
    if contains_all(&lower, &["document_open", "wscript.shell", "adodb.stream"]) {
        indicators.push("auto-run launcher sequence");
    }
    if contains_all(&lower, &["workbook_open", "msxml2.xmlhttp", "createobject"]) {
        indicators.push("auto-run network automation sequence");
    }
    if contains_all(&lower, &["document_open", "msxml2.xmlhttp", "adodb.stream"]) {
        indicators.push("document-open network automation sequence");
    }

    indicators
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}
