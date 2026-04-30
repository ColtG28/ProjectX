use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Default)]
pub struct AppBundleScanPlan {
    pub bundle_path: PathBuf,
    pub info_plist_path: Option<PathBuf>,
    pub primary_executable: PathBuf,
    pub helper_executables: Vec<PathBuf>,
    pub limited_access_notes: Vec<String>,
    pub skipped_items: Vec<String>,
}

pub fn is_app_bundle(path: &Path) -> bool {
    path.is_dir()
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("app"))
            .unwrap_or(false)
}

pub fn bundle_target_size(path: &Path) -> Option<u64> {
    let plan = resolve_app_bundle_plan(path).ok()?;
    fs::metadata(plan.primary_executable)
        .ok()
        .map(|metadata| metadata.len())
}

pub fn bundle_target_modified_epoch(path: &Path) -> Option<u64> {
    let plan = resolve_app_bundle_plan(path).ok()?;
    fs::metadata(plan.primary_executable)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
}

pub fn resolve_app_bundle_plan(path: &Path) -> Result<AppBundleScanPlan, String> {
    if !is_app_bundle(path) {
        return Err(format!("{} is not a macOS .app bundle.", path.display()));
    }

    let contents = path.join("Contents");
    if !contents.is_dir() {
        return Err(format!(
            "macOS app bundle is missing Contents/: {}",
            path.display()
        ));
    }

    let info_plist = contents.join("Info.plist");
    let info_plist_path = info_plist.exists().then_some(info_plist.clone());
    let mut limited_access_notes = Vec::new();
    let mut skipped_items = Vec::new();

    let macos_dir = contents.join("MacOS");
    let primary_executable =
        resolve_primary_executable(path, &macos_dir, info_plist_path.as_deref()).map_err(
            |error| format!("macOS app bundle entrypoint could not be resolved: {error}"),
        )?;

    let mut helper_executables = Vec::new();
    collect_regular_files(
        &macos_dir,
        &primary_executable,
        &mut helper_executables,
        &mut limited_access_notes,
        &mut skipped_items,
        "Contents/MacOS",
    );

    collect_regular_files(
        &contents.join("Helpers"),
        &primary_executable,
        &mut helper_executables,
        &mut limited_access_notes,
        &mut skipped_items,
        "Contents/Helpers",
    );

    collect_nested_bundle_helpers(
        &contents.join("XPCServices"),
        &mut helper_executables,
        &mut limited_access_notes,
        &mut skipped_items,
        "Contents/XPCServices",
    );

    let frameworks_dir = contents.join("Frameworks");
    if frameworks_dir.exists() {
        skipped_items.push(
            "Embedded frameworks were detected but are not scanned by default in the macOS app-bundle path."
                .to_string(),
        );
    }

    helper_executables.sort();
    helper_executables.dedup();

    Ok(AppBundleScanPlan {
        bundle_path: path.to_path_buf(),
        info_plist_path,
        primary_executable,
        helper_executables,
        limited_access_notes,
        skipped_items,
    })
}

fn resolve_primary_executable(
    bundle_path: &Path,
    macos_dir: &Path,
    info_plist_path: Option<&Path>,
) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();

    if let Some(info_plist_path) = info_plist_path {
        if let Ok(text) = fs::read_to_string(info_plist_path) {
            if let Some(executable_name) = parse_cf_bundle_executable(&text) {
                candidates.push(macos_dir.join(executable_name));
            }
        }
    }

    if let Some(stem) = bundle_path.file_stem().and_then(|value| value.to_str()) {
        candidates.push(macos_dir.join(stem));
    }

    if let Ok(entries) = fs::read_dir(macos_dir) {
        let mut files = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                fs::metadata(path)
                    .map(|metadata| metadata.is_file())
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        files.sort();
        candidates.extend(files);
    }

    candidates
        .into_iter()
        .find(|candidate| {
            fs::metadata(candidate)
                .map(|metadata| metadata.is_file())
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            format!(
                "Could not resolve a readable app bundle executable under {}",
                macos_dir.display()
            )
        })
}

fn parse_cf_bundle_executable(plist_text: &str) -> Option<String> {
    let key_index = plist_text.find("<key>CFBundleExecutable</key>")?;
    let tail = &plist_text[key_index..];
    let string_start = tail.find("<string>")?;
    let string_tail = &tail[string_start + "<string>".len()..];
    let string_end = string_tail.find("</string>")?;
    let value = string_tail[..string_end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn collect_regular_files(
    dir: &Path,
    primary_executable: &Path,
    targets: &mut Vec<PathBuf>,
    limited_access_notes: &mut Vec<String>,
    skipped_items: &mut Vec<String>,
    label: &str,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            if dir.exists() {
                limited_access_notes.push(format!(
                    "Skipped {label} because macOS denied access or it could not be read: {error}"
                ));
            }
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                limited_access_notes.push(format!(
                    "Skipped unreadable bundle component {}: {error}",
                    path.display()
                ));
                continue;
            }
        };

        if metadata.file_type().is_symlink() {
            skipped_items.push(format!(
                "Skipped symlinked bundle component {}.",
                path.display()
            ));
            continue;
        }

        if metadata.is_file() && path != primary_executable {
            targets.push(path);
        }
    }
}

fn collect_nested_bundle_helpers(
    dir: &Path,
    targets: &mut Vec<PathBuf>,
    limited_access_notes: &mut Vec<String>,
    skipped_items: &mut Vec<String>,
    label: &str,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            if dir.exists() {
                limited_access_notes.push(format!(
                    "Skipped {label} because macOS denied access or it could not be read: {error}"
                ));
            }
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !is_app_bundle(&path) && path.extension().and_then(|ext| ext.to_str()) != Some("xpc") {
            continue;
        }
        match resolve_primary_executable(&path, &path.join("Contents").join("MacOS"), None) {
            Ok(executable) => targets.push(executable),
            Err(error) => limited_access_notes.push(format!(
                "Skipped nested helper bundle {}: {error}",
                path.display()
            )),
        }
    }

    skipped_items.extend(
        targets
            .iter()
            .map(|path| format!("Identified nested helper executable {}.", path.display())),
    );
}
