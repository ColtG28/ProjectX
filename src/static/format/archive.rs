use std::path::Path;

use crate::r#static::config::ResourceLimits;
use crate::r#static::script::patterns;
use crate::r#static::types::{ExtractedArtifact, Finding};

use super::detect::{self, FormatKind};
use super::{pdf, zip};

#[derive(Debug, Clone, Default)]
pub struct ContainerInspection {
    pub findings: Vec<Finding>,
    pub artifacts: Vec<ExtractedArtifact>,
}

pub fn inspect_bytes(
    bytes: &[u8],
    display_path: &str,
    depth: usize,
    limits: &ResourceLimits,
) -> ContainerInspection {
    if depth > limits.max_recursion_depth {
        return ContainerInspection {
            findings: vec![Finding::new(
                "RESOURCE_RECURSION_LIMIT",
                format!(
                    "Archive contains deeply nested content in {display_path}, so inspection stopped at depth {} to stay within the safety limit of {}",
                    depth, limits.max_recursion_depth
                ),
                0.5,
            )],
            artifacts: Vec::new(),
        };
    }

    let extension = Path::new(display_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    let kind = detect::kind(bytes, extension);

    match kind {
        FormatKind::Zip | FormatKind::Office => inspect_zip(bytes, display_path, depth, limits),
        FormatKind::Pdf => inspect_pdf(bytes, display_path, depth, limits),
        _ => inspect_script_like(bytes, display_path, depth),
    }
}

pub fn nested_extract_depth(bytes: &[u8], limits: &ResourceLimits) -> usize {
    max_depth(bytes, "container", 0, limits)
}

fn inspect_zip(
    bytes: &[u8],
    display_path: &str,
    depth: usize,
    limits: &ResourceLimits,
) -> ContainerInspection {
    let extraction = zip::extract_entries(bytes, limits);
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();

    if extraction.hit_entry_limit {
        findings.push(Finding::new(
            "RESOURCE_ARCHIVE_ENTRY_LIMIT",
            format!(
                "Archive inspection stopped after {} entries in {}, which suggests the container may be unusually large or repetitive",
                limits.max_archive_entries, display_path
            ),
            1.0,
        ));
    }
    if extraction.hit_decompression_limit {
        findings.push(Finding::new(
            "RESOURCE_DECOMPRESS_LIMIT",
            format!(
                "Archive extraction reached the configured decompression safety limit while inspecting {}",
                display_path
            ),
            1.0,
        ));
    }
    if extraction.unsupported_entries > 0 {
        findings.push(Finding::new(
            "ZIP_UNSUPPORTED_METHOD",
            format!(
                "Skipped {} archive entries in {} because their compression method is not supported by this scanner",
                extraction.unsupported_entries, display_path
            ),
            0.5,
        ));
    }

    for entry in extraction.entries {
        let full_path = format!("{display_path}!{}", entry.name);
        let entry_kind = entry_kind_label(&entry.name, &entry.data);
        artifacts.push(ExtractedArtifact::new(
            full_path.clone(),
            entry_kind,
            depth + 1,
            entry.data.len(),
        ));

        let lower_name = entry.name.to_ascii_lowercase();
        if looks_executable_name(&lower_name) {
            if looks_script_name(&lower_name) {
                findings.push(Finding::new(
                    "ZIP_EMBEDDED_SCRIPT",
                    format!(
                        "Archive entry {} contains a script file, which is common in installers and automation packages but still worth reviewing in context",
                        full_path
                    ),
                    1.0,
                ));
            } else {
                findings.push(Finding::new(
                    "ZIP_EMBEDDED_EXECUTABLE",
                    format!(
                        "Archive entry {} looks like an executable payload",
                        full_path
                    ),
                    2.0,
                ));
            }
        }
        if lower_name.contains("vbaproject.bin")
            || lower_name.contains("/vba")
            || lower_name.ends_with(".vba")
        {
            findings.push(Finding::new(
                "OFFICE_MACRO_CONTAINER",
                format!("Embedded Office macro component found inside {}", full_path),
                2.5,
            ));
        }

        findings.extend(inspect_script_like(&entry.data, &full_path, depth + 1).findings);

        let nested_kind = detect::kind(&entry.data, extension_hint(&entry.name));
        if matches!(
            nested_kind,
            FormatKind::Zip | FormatKind::Office | FormatKind::Pdf
        ) {
            let nested = inspect_bytes(&entry.data, &full_path, depth + 1, limits);
            findings.extend(nested.findings);
            artifacts.extend(nested.artifacts);
        }
    }

    ContainerInspection {
        findings,
        artifacts,
    }
}

fn inspect_pdf(
    bytes: &[u8],
    display_path: &str,
    depth: usize,
    limits: &ResourceLimits,
) -> ContainerInspection {
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();

    let scripts = pdf::extract_javascript_fragments(
        bytes,
        limits.max_archive_entries.min(16),
        limits.max_extracted_entry_bytes,
    );
    for (index, script) in scripts.iter().enumerate() {
        let artifact_path = format!("{display_path}#javascript[{index}]");
        artifacts.push(ExtractedArtifact::new(
            artifact_path.clone(),
            "pdf-javascript",
            depth + 1,
            script.len(),
        ));
        if script_contains_suspicious_marker(script) {
            findings.push(Finding::new(
                "PDF_EMBEDDED_SCRIPT",
                format!(
                    "Embedded PDF JavaScript in {} contains suspicious automation or launch markers",
                    artifact_path
                ),
                2.0,
            ));
        }
    }

    let streams = pdf::extract_embedded_streams(
        bytes,
        limits.max_archive_entries.min(16),
        limits.max_extracted_entry_bytes,
    );
    for (index, stream) in streams.iter().enumerate() {
        let artifact_path = format!("{display_path}#embedded[{index}]");
        artifacts.push(ExtractedArtifact::new(
            artifact_path.clone(),
            entry_kind_label(&artifact_path, stream),
            depth + 1,
            stream.len(),
        ));
        if matches!(
            detect::kind(stream, extension_hint(&artifact_path)),
            FormatKind::Zip | FormatKind::Office | FormatKind::Pdf
        ) {
            let nested = inspect_bytes(stream, &artifact_path, depth + 1, limits);
            findings.extend(nested.findings);
            artifacts.extend(nested.artifacts);
        } else {
            findings.extend(inspect_script_like(stream, &artifact_path, depth + 1).findings);
        }
    }

    ContainerInspection {
        findings,
        artifacts,
    }
}

fn inspect_script_like(bytes: &[u8], display_path: &str, depth: usize) -> ContainerInspection {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut hits = patterns::suspicious_markers()
        .iter()
        .filter(|marker| text.contains(**marker))
        .take(4)
        .cloned()
        .collect::<Vec<_>>();

    let has_network_url = text.contains("http://") || text.contains("https://");
    if has_network_url {
        hits.push("network-url");
    }

    let mut findings = Vec::new();
    let mut artifacts = Vec::new();
    let meaningful_hits = hits.iter().filter(|hit| **hit != "network-url").count();
    if meaningful_hits > 0 {
        findings.push(Finding::new(
            "EMBEDDED_SCRIPT_MARKERS",
            format!(
                "Embedded content {} contains script markers associated with obfuscation, automation, or network activity: {}",
                display_path,
                hits.join(", ")
            ),
            1.5,
        ));
    }

    if is_text(bytes) && !display_path.is_empty() {
        artifacts.push(ExtractedArtifact::new(
            display_path,
            "text-content",
            depth,
            bytes.len(),
        ));
    }

    ContainerInspection {
        findings,
        artifacts,
    }
}

fn max_depth(bytes: &[u8], display_path: &str, depth: usize, limits: &ResourceLimits) -> usize {
    if depth > limits.max_recursion_depth {
        return depth.saturating_sub(1);
    }

    let extension = Path::new(display_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    match detect::kind(bytes, extension) {
        FormatKind::Zip | FormatKind::Office => {
            let extraction = zip::extract_entries(bytes, limits);
            let mut deepest = depth;
            for entry in extraction.entries {
                deepest = deepest.max(max_depth(&entry.data, &entry.name, depth + 1, limits));
            }
            deepest
        }
        FormatKind::Pdf => {
            let mut deepest = depth;
            for stream in pdf::extract_embedded_streams(
                bytes,
                limits.max_archive_entries.min(16),
                limits.max_extracted_entry_bytes,
            ) {
                deepest = deepest.max(max_depth(&stream, "embedded", depth + 1, limits));
            }
            deepest
        }
        _ => depth,
    }
}

fn extension_hint(name: &str) -> &str {
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
}

fn looks_executable_name(name: &str) -> bool {
    [
        ".exe", ".dll", ".sys", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

fn looks_script_name(name: &str) -> bool {
    [".js", ".vbs", ".ps1", ".bat", ".cmd"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn entry_kind_label(name: &str, data: &[u8]) -> &'static str {
    match detect::kind(data, extension_hint(name)) {
        FormatKind::Zip => "zip",
        FormatKind::Office => "office-container",
        FormatKind::Pdf => "pdf",
        FormatKind::Pe => "portable-executable",
        FormatKind::Elf => "elf",
        FormatKind::Macho => "mach-o",
        FormatKind::MediaContainer => "media-container",
        FormatKind::Unknown => {
            if is_text(data) {
                "text"
            } else {
                "binary"
            }
        }
    }
}

fn is_text(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(1024)];
    !sample.is_empty()
        && sample
            .iter()
            .filter(|byte| {
                byte.is_ascii_graphic() || matches!(**byte, b'\n' | b'\r' | b'\t' | b' ')
            })
            .count()
            * 100
            / sample.len()
            >= 85
}

fn script_contains_suspicious_marker(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();
    patterns::suspicious_markers()
        .iter()
        .any(|marker| lower.contains(marker))
}
