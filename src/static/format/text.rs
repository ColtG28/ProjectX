use std::path::Path;

use crate::r#static::script::detect::{kind as script_kind, ScriptKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextLikeKind {
    PlainText,
    TextConfig,
    TextResource,
    TextMetadata,
    LogText,
}

impl TextLikeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::PlainText => "Plain Text",
            Self::TextConfig => "Text Config",
            Self::TextResource => "Text Resource",
            Self::TextMetadata => "Text Metadata",
            Self::LogText => "Log Text",
        }
    }
}

pub fn detect(
    path: &Path,
    file_name: &str,
    extension: &str,
    sniffed_mime: &str,
    bytes: &[u8],
) -> Option<TextLikeKind> {
    if !looks_text_like(extension, sniffed_mime, bytes) {
        return None;
    }

    let text = whole_text(bytes)?;
    if script_kind(&text) != ScriptKind::Unknown {
        return None;
    }

    let extension = extension.to_ascii_lowercase();
    let file_name = file_name.to_ascii_lowercase();
    let path_text = path.to_string_lossy().to_ascii_lowercase();

    if matches!(extension.as_str(), "log" | "trace") {
        return Some(TextLikeKind::LogText);
    }
    if is_text_config(&file_name, &extension, &path_text) {
        return Some(TextLikeKind::TextConfig);
    }
    if is_text_metadata(&file_name, &path_text) {
        return Some(TextLikeKind::TextMetadata);
    }
    if is_text_resource(&file_name, &path_text) {
        return Some(TextLikeKind::TextResource);
    }

    Some(TextLikeKind::PlainText)
}

fn looks_text_like(extension: &str, sniffed_mime: &str, bytes: &[u8]) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "txt"
            | "text"
            | "md"
            | "rst"
            | "log"
            | "cfg"
            | "conf"
            | "ini"
            | "properties"
            | "list"
            | "lst"
            | "env"
    ) || (sniffed_mime == "text/plain" && seems_text(bytes))
        || sniffed_mime == "application/xml"
}

fn whole_text(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).trim().to_string();
    (text.len() >= 8 && seems_text(text.as_bytes())).then_some(text)
}

fn seems_text(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(4096)];
    if sample.is_empty() {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|byte| {
            matches!(**byte, b'\n' | b'\r' | b'\t') || byte.is_ascii_graphic() || **byte == b' '
        })
        .count();
    printable * 100 / sample.len().max(1) >= 90
}

fn is_text_config(file_name: &str, extension: &str, path_text: &str) -> bool {
    matches!(
        extension,
        "cfg" | "conf" | "ini" | "properties" | "env" | "list" | "lst"
    ) || file_name.contains("config")
        || file_name.contains("settings")
        || file_name.contains("preferences")
        || path_contains_any(
            path_text,
            &[
                "/config/",
                "/configs/",
                "/settings/",
                "/preferences/",
                "/profiles/",
            ],
        )
}

fn is_text_metadata(file_name: &str, path_text: &str) -> bool {
    matches!(
        file_name,
        "license.txt"
            | "copying.txt"
            | "readme.txt"
            | "changelog.txt"
            | "notice.txt"
            | "credits.txt"
    ) || file_name.contains("license")
        || file_name.contains("readme")
        || file_name.contains("changelog")
        || file_name.contains("notice")
        || file_name.contains("credits")
        || path_contains_any(
            path_text,
            &[
                "/licenses/",
                "/docs/",
                "/metadata/",
                "/version/",
                "/notices/",
            ],
        )
}

fn is_text_resource(file_name: &str, path_text: &str) -> bool {
    file_name.contains("locale")
        || file_name.contains("messages")
        || file_name.contains("dictionary")
        || file_name.contains("resource")
        || path_contains_any(
            path_text,
            &[
                "/_locales/",
                "/locales/",
                "/resources/",
                "/assets/",
                "/metadata/",
                "/extensions/",
                "/mods/",
                "/mod/",
                "/lang/",
            ],
        )
}

fn path_contains_any(path_text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path_text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_text_resource_for_extension_locale_file() {
        let kind = detect(
            Path::new("/tmp/extensions/uBlock/_locales/en/messages.txt"),
            "messages.txt",
            "txt",
            "text/plain",
            b"Open dashboard\nAdvanced settings\n",
        );

        assert_eq!(kind, Some(TextLikeKind::TextResource));
    }

    #[test]
    fn avoids_benign_text_classification_for_script_like_txt() {
        let kind = detect(
            Path::new("/tmp/dropper.txt"),
            "dropper.txt",
            "txt",
            "text/plain",
            b"powershell -enc abc123",
        );

        assert_eq!(kind, None);
    }
}
