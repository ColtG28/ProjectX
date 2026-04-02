pub fn is_suspicious(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let markers = [
        "powershell -enc",
        "powershell -encodedcommand",
        "certutil -decode",
        "bitsadmin",
        "regsvr32",
        "rundll32",
        "mshta",
        "curl ",
        "wget ",
        "cmd /c",
    ];

    markers
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count()
        >= 2
}
