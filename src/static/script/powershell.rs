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
