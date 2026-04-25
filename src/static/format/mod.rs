pub mod archive;
pub mod detect;
pub mod elf;
pub mod macho;
pub mod office;
pub mod pdf;
pub mod pe;
pub mod structured;
pub mod zip;

use super::context::ScanContext;
use super::types::Finding;

pub fn run(ctx: &mut ScanContext) {
    if apple_bundle_resource_format(&ctx.input_path, &ctx.file_name, &ctx.extension) {
        ctx.detected_format = Some("AppleBundleResource".to_string());
        ctx.push_view(super::types::View::new(
            "format.kind",
            "AppleBundleResource",
        ));
        ctx.log_event(
            "format",
            "Detected format kind AppleBundleResource".to_string(),
        );
        return;
    }

    if let Some(kind) = structured::detect(
        &ctx.input_path,
        &ctx.file_name,
        &ctx.extension,
        &ctx.sniffed_mime,
        &ctx.bytes,
    ) {
        let label = kind.label().to_string();
        ctx.detected_format = Some(label.clone());
        ctx.push_view(super::types::View::new("format.kind", label.clone()));
        ctx.log_event("format", format!("Detected format kind {label}"));
        return;
    }

    if let Some(kind) = structured::detect_from_metadata(
        &ctx.input_path,
        &ctx.file_name,
        &ctx.extension,
        &ctx.sniffed_mime,
    ) {
        let label = kind.label().to_string();
        ctx.detected_format = Some(label.clone());
        ctx.push_view(super::types::View::new("format.kind", label.clone()));
        ctx.log_event("format", format!("Detected format kind {label}"));
        return;
    }

    let kind = detect::kind(&ctx.bytes, &ctx.extension);
    ctx.detected_format = Some(format!("{kind:?}"));
    ctx.push_view(super::types::View::new("format.kind", format!("{kind:?}")));
    ctx.log_event("format", format!("Detected format kind {kind:?}"));

    match kind {
        detect::FormatKind::Pe => {
            let pe_findings = pe::analyze(&ctx.bytes);
            ctx.findings.extend(pe_findings);
        }
        detect::FormatKind::Elf => {
            let elf_findings = elf::analyze(&ctx.bytes);
            ctx.findings.extend(elf_findings);
        }
        detect::FormatKind::Macho => {
            let macho_findings = macho::analyze(&ctx.bytes);
            ctx.findings.extend(macho_findings);
        }
        detect::FormatKind::Pdf => {
            let markers = pdf::suspicious_markers(&ctx.bytes);
            if !markers.is_empty() {
                ctx.push_finding(Finding::new(
                    "PDF_ACTIVE_CONTENT",
                    format!(
                        "PDF includes embedded script or launch markers: {}",
                        markers.join(", ")
                    ),
                    2.0,
                ));
            }
        }
        detect::FormatKind::Zip => {
            if zip::has_many_entries(&ctx.bytes) {
                ctx.push_finding(Finding::new(
                    "ZIP_DENSE",
                    "Archive is unusually dense and may expand into a large number of files",
                    1.5,
                ));
            }

            let suspicious_entries = zip::suspicious_entries(&ctx.bytes);
            if !suspicious_entries.is_empty() {
                ctx.push_finding(Finding::new(
                    "ZIP_SUSPICIOUS_ENTRIES",
                    format!(
                        "Archive contains embedded files with risky names or payload types: {}",
                        suspicious_entries.join(", ")
                    ),
                    1.5,
                ));
            }

            let nested_archive_markers = zip::nested_archive_markers(&ctx.bytes);
            if nested_archive_markers >= 2 {
                ctx.push_finding(Finding::new(
                    "ZIP_NESTED_ARCHIVES",
                    "Archive appears to contain multiple nested archive layers",
                    1.0,
                ));
            }
        }
        detect::FormatKind::Office => {
            let macro_markers = office::macros::suspicious_macro_markers(&ctx.bytes);
            let high_risk_markers = office::macros::high_risk_macro_markers(&ctx.bytes);
            if !macro_markers.is_empty() && !high_risk_markers.is_empty() {
                ctx.push_finding(Finding::new(
                    "OFFICE_MACRO",
                    format!(
                        "Office document includes auto-run macros plus automation or download markers: {} | {}",
                        macro_markers.join(", "),
                        high_risk_markers.join(", ")
                    ),
                    2.5,
                ));
            } else if !macro_markers.is_empty() {
                ctx.push_finding(Finding::new(
                    "OFFICE_MACRO_CONTAINER",
                    format!(
                        "Office document includes macro storage or auto-run markers that should be reviewed: {}",
                        macro_markers.join(", ")
                    ),
                    1.2,
                ));
            }
        }
        detect::FormatKind::MediaContainer => {
            ctx.log_event(
                "format",
                "Recognized media/container structure; keeping passive analysis focused on corroborated signals."
                    .to_string(),
            );
        }
        detect::FormatKind::Unknown => {}
    }

    if matches!(
        kind,
        detect::FormatKind::Zip | detect::FormatKind::Office | detect::FormatKind::Pdf
    ) {
        let inspection = archive::inspect_bytes(&ctx.bytes, &ctx.file_name, 0, &ctx.config.limits);
        for finding in inspection.findings {
            ctx.push_finding(finding);
        }
        for artifact in inspection.artifacts {
            ctx.push_artifact(artifact);
        }

        let nested_depth = archive::nested_extract_depth(&ctx.bytes, &ctx.config.limits);
        ctx.push_view(super::types::View::new(
            "format.nested_depth",
            nested_depth.to_string(),
        ));
    }
}

fn apple_bundle_resource_format(path: &std::path::Path, file_name: &str, extension: &str) -> bool {
    let ext = extension.to_ascii_lowercase();
    let file_name = file_name.to_ascii_lowercase();
    let path_text = path.to_string_lossy();
    let in_bundle = path
        .components()
        .any(|component| component.as_os_str().to_string_lossy().contains(".app"))
        || path
            .components()
            .any(|component| component.as_os_str().to_string_lossy().contains(".bundle"))
        || path_text.contains(".framework/");

    in_bundle
        && (matches!(ext.as_str(), "lzfse" | "car" | "icns" | "plist")
            || matches!(
                file_name.as_str(),
                "coderesources" | ".localized" | "assets"
            ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#static::config::ScanConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_root(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "projectx_format_test_{}_{}_{}",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn run_labels_generic_json_as_json_data() {
        let root = unique_test_root("json_data");
        fs::create_dir_all(&root).expect("root");
        let sample = root.join("messages.json");
        fs::write(&sample, br#"{"hello":"world"}"#).expect("sample");

        let mut ctx = ScanContext::from_path(&sample, ScanConfig::default()).expect("context");
        run(&mut ctx);

        assert_eq!(ctx.detected_format.as_deref(), Some("JSON Data"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn run_labels_extension_locale_json_clearly() {
        let root = unique_test_root("locale_json");
        let locale_dir = root.join("ext").join("_locales").join("cs");
        fs::create_dir_all(&locale_dir).expect("locale dir");
        let sample = locale_dir.join("messages.json");
        fs::write(
            &sample,
            br#"{
                "extension_name":{"message":"Example"},
                "extension_description":{"message":"Demo"}
            }"#,
        )
        .expect("sample");

        let mut ctx = ScanContext::from_path(&sample, ScanConfig::default()).expect("context");
        run(&mut ctx);

        assert_eq!(
            ctx.detected_format.as_deref(),
            Some("Extension Locale JSON")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn run_keeps_json_label_for_decoded_like_content() {
        let root = unique_test_root("json_signal");
        fs::create_dir_all(&root).expect("root");
        let sample = root.join("payload.json");
        fs::write(
            &sample,
            br#"{"script":"javascript:alert('demo')","encoded":"ZXZhbChhbGVydCgxKSk="}"#,
        )
        .expect("sample");

        let mut ctx = ScanContext::from_path(&sample, ScanConfig::default()).expect("context");
        run(&mut ctx);

        assert_eq!(ctx.detected_format.as_deref(), Some("JSON Data"));

        let _ = fs::remove_dir_all(&root);
    }
}
