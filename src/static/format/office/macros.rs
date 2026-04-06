pub fn suspicious_macro_markers(bytes: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let markers = [
        ("vbaraw", "vbaraw"),
        ("vbaproject.bin", "vbaProject.bin"),
        ("word/vba", "word/vba"),
        ("xl/vba", "xl/vba"),
        ("ppt/vba", "ppt/vba"),
        ("autoopen", "autoopen"),
        ("document_open", "document_open"),
        ("workbook_open", "workbook_open"),
    ];

    markers
        .into_iter()
        .filter_map(|(needle, label)| text.contains(needle).then_some(label))
        .collect()
}

pub fn high_risk_macro_markers(bytes: &[u8]) -> Vec<&'static str> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let markers = [
        ("wscript.shell", "WScript.Shell"),
        ("adodb.stream", "ADODB.Stream"),
        ("msxml2.xmlhttp", "MSXML2.XMLHTTP"),
        ("urldownloadtofile", "URLDownloadToFile"),
        ("shell(", "Shell("),
    ];

    markers
        .into_iter()
        .filter_map(|(needle, label)| text.contains(needle).then_some(label))
        .collect()
}
