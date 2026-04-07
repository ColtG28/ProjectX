use super::office;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    Pe,
    Elf,
    Macho,
    Pdf,
    Zip,
    Office,
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

#[cfg(test)]
mod tests {
    use super::{kind, FormatKind};

    #[test]
    fn detects_office_openxml_by_contents_even_if_extension_is_generic_zip() {
        let bytes = b"PK\x03\x04[Content_Types].xmlword/document.xmldocProps/app.xml";
        assert_eq!(kind(bytes, "zip"), FormatKind::Office);
    }

    #[test]
    fn detects_legacy_ole_office_documents() {
        let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        bytes.extend_from_slice(b"WordDocument VBA");
        assert_eq!(kind(&bytes, "bin"), FormatKind::Office);
    }

    #[test]
    fn detects_macho_headers() {
        assert_eq!(
            kind(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0], "dylib"),
            FormatKind::Macho
        );
        assert_eq!(
            kind(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1], "macho"),
            FormatKind::Macho
        );
    }
}
