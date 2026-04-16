pub mod bundle;
pub mod cache;
pub mod discovery;
pub mod entropy;
pub mod hash;
pub mod magic;
pub mod mime;
pub mod permissions;
pub mod size;

use super::context::ScanContext;
use super::types::Finding;

pub fn run(ctx: &mut ScanContext) {
    let file_size = size::bytes_len(&ctx.bytes);
    let bundle_resource =
        apple_bundle_resource_context(&ctx.input_path, &ctx.file_name, &ctx.extension);
    ctx.log_event(
        "file",
        format!("Profiling {} bytes with sha256 {}", file_size, ctx.sha256),
    );
    if size::is_unusually_small(file_size) && !bundle_resource.suppress_small_file {
        ctx.push_finding(Finding::new(
            "FILE_SMALL",
            format!(
                "File is unusually small ({} bytes), which can indicate a stub, launcher, or incomplete payload",
                file_size
            ),
            ctx.config.weights.size,
        ));
    }

    ctx.sniffed_mime = mime::sniff_from_bytes(&ctx.bytes, &ctx.extension).to_string();
    ctx.push_view(super::types::View::new("file.sha256", ctx.sha256.clone()));
    ctx.push_view(super::types::View::new(
        "file.metadata",
        format!(
            "extension={} mime={} executable={} size_bytes={} analyzed_bytes={} input_truncated={}",
            ctx.extension,
            ctx.sniffed_mime,
            permissions::is_executable(&ctx.input_path),
            ctx.original_size_bytes,
            ctx.bytes.len(),
            ctx.input_truncated
        ),
    ));
    if bundle_resource.is_known_resource {
        ctx.push_view(super::types::View::new(
            "file.bundle_context",
            format!(
                "apple_bundle_resource=true protected_install_path={} resource_kind={}",
                bundle_resource.protected_install_path, bundle_resource.resource_kind
            ),
        ));
        ctx.log_event(
            "file",
            format!(
                "Recognized Apple bundle resource context: {}",
                bundle_resource.resource_kind
            ),
        );
    }

    if !bundle_resource.suppress_magic_mismatch
        && !magic::find_header_bytes(&ctx.bytes, &ctx.extension)
    {
        ctx.push_finding(Finding::new(
            "MAGIC_MISMATCH",
            "File contents do not match the expected format for its extension",
            ctx.config.weights.magic,
        ));
    }

    let entropy = entropy::shannon(&ctx.bytes);
    if entropy > 7.5 && !bundle_resource.suppress_high_entropy {
        ctx.push_finding(Finding::new(
            "HIGH_ENTROPY",
            format!(
                "File contains compressed, encrypted, or heavily obfuscated content ({entropy:.2})"
            ),
            1.0,
        ));
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct BundleResourceContext {
    is_known_resource: bool,
    protected_install_path: bool,
    suppress_small_file: bool,
    suppress_magic_mismatch: bool,
    suppress_high_entropy: bool,
    resource_kind: &'static str,
}

fn apple_bundle_resource_context(
    path: &std::path::Path,
    file_name: &str,
    extension: &str,
) -> BundleResourceContext {
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
    let protected_install_path = path_text.starts_with("/Applications/")
        || path_text.starts_with("/System/Applications/")
        || path_text.starts_with("/Library/");

    if !in_bundle {
        return BundleResourceContext::default();
    }

    let is_code_resources = file_name == "coderesources";
    let is_localized_marker = file_name == ".localized";
    let is_info_plist = file_name == "info.plist" || ext == "plist";
    let is_lzfse_localization = ext == "lzfse";
    let is_asset_catalog = file_name == "assets.car" || ext == "car";
    let is_bundle_binary = file_name == "assets";
    let is_bundle_icon = ext == "icns";
    let compressed_strings_path = path_text.contains("/CompressedStrings/");

    let is_known_resource = is_code_resources
        || is_localized_marker
        || is_info_plist
        || is_lzfse_localization
        || is_asset_catalog
        || is_bundle_binary
        || is_bundle_icon;

    let resource_kind = if is_lzfse_localization && compressed_strings_path {
        "compressed-localization"
    } else if is_asset_catalog {
        "asset-catalog"
    } else if is_code_resources {
        "code-signature-resource"
    } else if is_localized_marker {
        "bundle-localization-marker"
    } else if is_info_plist {
        "bundle-metadata"
    } else if is_bundle_binary {
        "framework-binary"
    } else if is_bundle_icon {
        "bundle-icon"
    } else {
        "unknown"
    };

    BundleResourceContext {
        is_known_resource,
        protected_install_path,
        suppress_small_file: is_localized_marker || file_name == ".gitignore",
        suppress_magic_mismatch: is_known_resource,
        suppress_high_entropy: is_lzfse_localization || is_asset_catalog,
        resource_kind,
    }
}
