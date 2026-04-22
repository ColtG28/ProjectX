use std::path::Path;

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredDataKind {
    BrowserExtensionManifest,
    PackageMetadata,
    JsonLockfile,
    JsonConfig,
    ManifestData,
    ResourceConfigData,
    JsonData,
}

impl StructuredDataKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::BrowserExtensionManifest => "Browser Extension Manifest",
            Self::PackageMetadata => "Package Metadata",
            Self::JsonLockfile => "JSON Lockfile",
            Self::JsonConfig => "JSON Config",
            Self::ManifestData => "Manifest Data",
            Self::ResourceConfigData => "Resource Config Data",
            Self::JsonData => "JSON Data",
        }
    }
}

pub fn detect(
    path: &Path,
    file_name: &str,
    extension: &str,
    sniffed_mime: &str,
    bytes: &[u8],
) -> Option<StructuredDataKind> {
    if !looks_json_like(extension, sniffed_mime, bytes) {
        return None;
    }

    let value = parse_json(bytes)?;
    let file_name = file_name.to_ascii_lowercase();
    let path_text = path.to_string_lossy().to_ascii_lowercase();

    if is_browser_extension_manifest(&file_name, &path_text, &value) {
        return Some(StructuredDataKind::BrowserExtensionManifest);
    }
    if is_json_lockfile(&file_name, &value) {
        return Some(StructuredDataKind::JsonLockfile);
    }
    if is_package_metadata(&file_name, &value) {
        return Some(StructuredDataKind::PackageMetadata);
    }
    if is_json_config(&file_name, &path_text, &value) {
        return Some(StructuredDataKind::JsonConfig);
    }
    if is_manifest_data(&file_name, &value) {
        return Some(StructuredDataKind::ManifestData);
    }
    if is_resource_config_data(&file_name, &path_text, &value) {
        return Some(StructuredDataKind::ResourceConfigData);
    }

    Some(StructuredDataKind::JsonData)
}

fn looks_json_like(extension: &str, sniffed_mime: &str, bytes: &[u8]) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "json" | "json5" | "har" | "webmanifest" | "lock"
    ) || sniffed_mime.contains("json")
        || parse_json(bytes).is_some()
}

fn parse_json(bytes: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if !(text.starts_with('{') || text.starts_with('[')) {
        return None;
    }
    serde_json::from_str(text).ok()
}

fn is_browser_extension_manifest(file_name: &str, path_text: &str, value: &Value) -> bool {
    if !matches!(file_name, "manifest.json" | "manifest.webmanifest") {
        return false;
    }

    has_any_key(
        value,
        &[
            "manifest_version",
            "browser_specific_settings",
            "background",
            "content_scripts",
            "permissions",
            "host_permissions",
            "action",
            "browser_action",
        ],
    ) || path_contains_any(
        path_text,
        &[
            "/extensions/",
            "/chrome/",
            "/firefox/",
            "/mozilla/",
            "/browser-extension/",
            "/web-ext/",
        ],
    )
}

fn is_package_metadata(file_name: &str, value: &Value) -> bool {
    matches!(
        file_name,
        "package.json"
            | "composer.json"
            | "deno.json"
            | "deno.jsonc"
            | "bun.lock"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
    ) || has_any_key(
        value,
        &[
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
            "scripts",
            "packageManager",
            "lockfileVersion",
        ],
    )
}

fn is_json_lockfile(file_name: &str, value: &Value) -> bool {
    matches!(
        file_name,
        "package-lock.json" | "npm-shrinkwrap.json" | "composer.lock"
    ) || (value.get("lockfileVersion").is_some() && value.get("packages").is_some())
}

fn is_json_config(file_name: &str, path_text: &str, value: &Value) -> bool {
    file_name.contains("config")
        || file_name.contains("settings")
        || matches!(
            file_name,
            "tsconfig.json"
                | "jsconfig.json"
                | "launch.json"
                | "tasks.json"
                | ".babelrc"
                | ".eslintrc"
                | ".prettierrc"
        )
        || path_contains_any(
            path_text,
            &[
                "/config/",
                "/configs/",
                "/settings/",
                "/preferences/",
                "/profiles/",
                "/resources/app/",
            ],
        ) && has_any_key(
            value,
            &[
                "compilerOptions",
                "extends",
                "include",
                "exclude",
                "settings",
                "preferences",
                "files",
            ],
        )
}

fn is_manifest_data(file_name: &str, value: &Value) -> bool {
    file_name.contains("manifest")
        || matches!(file_name, "appxmanifest.json" | "site.webmanifest")
        || has_any_key(value, &["short_name", "start_url", "scope", "icons"])
}

fn is_resource_config_data(file_name: &str, path_text: &str, value: &Value) -> bool {
    matches!(
        file_name,
        "asset-manifest.json" | "metadata.json" | "modinfo.json" | "resource.json" | "locale.json"
    ) || path_contains_any(
        path_text,
        &[
            "/resources/",
            "/resource/",
            "/metadata/",
            "/locales/",
            "/mods/",
            "/mod/",
            "/build/",
            "/dist/",
            "/assets/",
            "/framework/",
        ],
    ) && has_any_key(
        value,
        &[
            "assets",
            "resources",
            "metadata",
            "locales",
            "files",
            "entries",
            "modid",
        ],
    )
}

fn has_any_key(value: &Value, keys: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    keys.iter().any(|key| object.contains_key(*key))
}

fn path_contains_any(path_text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path_text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_browser_extension_manifest() {
        let bytes = br#"{"manifest_version":3,"name":"Example","permissions":["storage"]}"#;
        let kind = detect(
            Path::new("/tmp/extensions/my-addon/manifest.json"),
            "manifest.json",
            "json",
            "application/json",
            bytes,
        );

        assert_eq!(kind, Some(StructuredDataKind::BrowserExtensionManifest));
    }

    #[test]
    fn detects_package_metadata_for_package_json() {
        let bytes = br#"{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.0.0"}}"#;
        let kind = detect(
            Path::new("/tmp/app/package.json"),
            "package.json",
            "json",
            "application/json",
            bytes,
        );

        assert_eq!(kind, Some(StructuredDataKind::PackageMetadata));
    }

    #[test]
    fn detects_json_config_for_tsconfig() {
        let bytes = br#"{"compilerOptions":{"module":"esnext"},"include":["src"]}"#;
        let kind = detect(
            Path::new("/tmp/app/tsconfig.json"),
            "tsconfig.json",
            "json",
            "application/json",
            bytes,
        );

        assert_eq!(kind, Some(StructuredDataKind::JsonConfig));
    }
}
