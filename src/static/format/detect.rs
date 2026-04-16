use super::office;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    Pe,
    Elf,
    Macho,
    Pdf,
    Zip,
    Office,
    MediaContainer,
    Unknown,
}

pub fn kind(bytes: &[u8], extension: &str) -> FormatKind {
    let ext = extension.to_ascii_lowercase();

    if bytes.starts_with(b"MZ") || ext == "exe" || ext == "dll" {
        return FormatKind::Pe;
    }
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return FormatKind::Elf;
    }
    if is_macho(bytes) {
        return FormatKind::Macho;
    }
    if bytes.starts_with(b"%PDF") || ext == "pdf" {
        return FormatKind::Pdf;
    }
    if is_media_container(bytes, &ext) {
        return FormatKind::MediaContainer;
    }
    if office::ole::is_ole(bytes)
        && (matches!(
            ext.as_str(),
            "doc" | "xls" | "ppt" | "docm" | "xlsm" | "pptm"
        ) || looks_like_legacy_office(bytes))
    {
        return FormatKind::Office;
    }
    if bytes.starts_with(b"PK\x03\x04") {
        if matches!(
            ext.as_str(),
            "docx" | "xlsx" | "pptx" | "xlsm" | "docm" | "pptm"
        ) || looks_like_office_zip(bytes)
        {
            return FormatKind::Office;
        }
        return FormatKind::Zip;
    }

    FormatKind::Unknown
}

fn is_media_container(bytes: &[u8], ext: &str) -> bool {
    matches!(ext, "mp4" | "m4v" | "mov" | "avi" | "mkv" | "webm")
        || (bytes.len() >= 12 && bytes.get(4..8) == Some(b"ftyp"))
        || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"AVI "))
        || bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
}

fn looks_like_legacy_office(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    text.contains("worddocument")
        || text.contains("workbook")
        || text.contains("powerpoint document")
        || text.contains("vba")
}

fn looks_like_office_zip(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    (text.contains("word/") || text.contains("xl/") || text.contains("ppt/"))
        && (text.contains("[content_types].xml") || text.contains("vbaproject.bin"))
}

fn is_macho(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(0..4),
        Some([0xFE, 0xED, 0xFA, 0xCE])
            | Some([0xCE, 0xFA, 0xED, 0xFE])
            | Some([0xFE, 0xED, 0xFA, 0xCF])
            | Some([0xCF, 0xFA, 0xED, 0xFE])
            | Some([0xCA, 0xFE, 0xBA, 0xBE])
            | Some([0xBE, 0xBA, 0xFE, 0xCA])
            | Some([0xCA, 0xFE, 0xBA, 0xBF])
            | Some([0xBF, 0xBA, 0xFE, 0xCA])
    )
}
