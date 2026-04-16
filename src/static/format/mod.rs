pub mod archive;
pub mod detect;
pub mod elf;
pub mod macho;
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
