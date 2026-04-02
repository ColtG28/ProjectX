pub mod archive;
pub mod detect;
pub mod elf;
pub mod office;
pub mod pdf;
pub mod pe;
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
        detect::FormatKind::Pdf => {
            let markers = pdf::suspicious_markers(&ctx.bytes);
            if !markers.is_empty() {
                ctx.push_finding(Finding::new(
                    "PDF_ACTIVE_CONTENT",
                    format!(
                        "PDF contains active-content markers: {}",
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
                    "Potential archive bomb characteristics",
                    1.5,
                ));
            }

            let suspicious_entries = zip::suspicious_entries(&ctx.bytes);
            if !suspicious_entries.is_empty() {
                ctx.push_finding(Finding::new(
                    "ZIP_SUSPICIOUS_ENTRIES",
                    format!(
                        "Archive contains suspicious embedded entries: {}",
                        suspicious_entries.join(", ")
                    ),
                    1.5,
                ));
            }

            let nested_archive_markers = zip::nested_archive_markers(&ctx.bytes);
            if nested_archive_markers >= 2 {
                ctx.push_finding(Finding::new(
                    "ZIP_NESTED_ARCHIVES",
                    "Archive advertises multiple nested archive payload markers",
                    1.0,
                ));
            }
        }
        detect::FormatKind::Office => {
            let markers = office::macros::suspicious_macro_markers(&ctx.bytes);
            if !markers.is_empty() {
                ctx.push_finding(Finding::new(
                    "OFFICE_MACRO",
                    format!(
                        "Suspicious Office macro markers found: {}",
                        markers.join(", ")
                    ),
                    2.5,
                ));
            }
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
