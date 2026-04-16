pub fn guess_from_extension(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "exe" => "application/x-msdownload",
        "dll" => "application/x-msdownload",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "m4v" => "video/x-m4v",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "elf" => "application/x-elf",
        "lzfse" => "application/x-apple-lzfse",
        "car" => "application/x-apple-asset-catalog",
        "icns" => "image/icns",
        "plist" => "application/x-plist",
        "js" => "text/javascript",
        "ps1" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        _ => "application/octet-stream",
    }
}

pub fn sniff_from_bytes(bytes: &[u8], ext: &str) -> &'static str {
    if bytes.starts_with(b"MZ") {
        return "application/x-msdownload";
    }
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return "application/x-elf";
    }
    if bytes.starts_with(b"%PDF") {
        return "application/pdf";
    }
    if looks_like_mp4_family(bytes) {
        return match ext.to_ascii_lowercase().as_str() {
            "mov" => "video/quicktime",
            "m4v" => "video/x-m4v",
            _ => "video/mp4",
        };
    }
    if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"AVI ") {
        return "video/x-msvideo";
    }
    if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return match ext.to_ascii_lowercase().as_str() {
            "webm" => "video/webm",
            _ => "video/x-matroska",
        };
    }
    if bytes.starts_with(b"BOMStore") {
        return "application/x-apple-asset-catalog";
    }
    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return "application/vnd.ms-office";
    }
    if bytes.starts_with(b"PK\x03\x04") {
        let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if lower.contains("[content_types].xml")
            && (lower.contains("word/") || lower.contains("xl/") || lower.contains("ppt/"))
        {
            return "application/vnd.openxmlformats-officedocument";
        }
        return "application/zip";
    }

    let sample = &bytes[..bytes.len().min(2048)];
    if std::str::from_utf8(sample).is_ok() {
        match ext.to_ascii_lowercase().as_str() {
            "json" => "application/json",
            "xml" => "application/xml",
            "plist" => "application/x-plist",
            "html" | "htm" => "text/html",
            "js" => "text/javascript",
            _ => "text/plain",
        }
    } else {
        guess_from_extension(ext)
    }
}

fn looks_like_mp4_family(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && bytes.get(4..8) == Some(b"ftyp")
}
