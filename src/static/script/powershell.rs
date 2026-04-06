pub fn is_suspicious(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let primary = [
        "invoke-expression",
        "iex",
        "-encodedcommand",
        "frombase64string",
        "downloadstring",
        "downloadfile",
        "invoke-webrequest",
        "new-object net.webclient",
        "system.net.webclient",
    ];
    let secondary = [
        "hidden",
        "windowstyle hidden",
        "bypass",
        "noprofile",
        "noninteractive",
        "start-bitstransfer",
        "invoke-command",
    ];

    let primary_hits = primary
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();
    let secondary_hits = secondary
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();

    primary_hits >= 2 || (primary_hits >= 1 && secondary_hits >= 1)
}

pub fn strong_indicators(input: &str) -> Vec<&'static str> {
    let lower = input.to_ascii_lowercase();
    let mut indicators = Vec::new();

    if contains_all(
        &lower,
        &["-encodedcommand", "frombase64string", "downloadstring"],
    ) {
        indicators.push("encoded downloader reconstruction");
    }
    if contains_all(
        &lower,
        &[
            "invoke-expression",
            "new-object net.webclient",
            "downloadstring",
        ],
    ) {
        indicators.push("download-and-launch chain");
    }
    if contains_all(&lower, &["invoke-webrequest", "start-process", "hidden"]) {
        indicators.push("hidden web retrieval and launch chain");
    }

    indicators
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}
