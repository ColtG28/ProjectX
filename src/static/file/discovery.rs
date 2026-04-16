use std::fs;
use std::path::{Path, PathBuf};

use super::bundle;

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_epoch: u64,
}

pub fn collect_files(inputs: &[PathBuf], max_files: usize) -> Vec<DiscoveredFile> {
    let mut files = Vec::new();
    let mut stack = Vec::with_capacity(inputs.len());
    stack.extend(inputs.iter().rev().cloned());

    while let Some(path) = stack.pop() {
        if files.len() >= max_files {
            break;
        }

        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };

        if metadata.file_type().is_symlink() {
            continue;
        }

        if metadata.is_file() {
            files.push(DiscoveredFile {
                path,
                size_bytes: metadata.len(),
                modified_epoch: modified_epoch(&metadata),
            });
            continue;
        }

        if metadata.is_dir() {
            if bundle::is_app_bundle(&path) {
                files.push(DiscoveredFile {
                    size_bytes: bundle::bundle_target_size(&path).unwrap_or(metadata.len()),
                    modified_epoch: bundle::bundle_target_modified_epoch(&path)
                        .unwrap_or_else(|| modified_epoch(&metadata)),
                    path,
                });
                continue;
            }
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
        }
    }

    files
}

pub fn file_metadata(path: &Path) -> Option<DiscoveredFile> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some(DiscoveredFile {
        path: path.to_path_buf(),
        size_bytes: metadata.len(),
        modified_epoch: modified_epoch(&metadata),
    })
}

fn modified_epoch(metadata: &fs::Metadata) -> u64 {
    use std::time::UNIX_EPOCH;

    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_files_treats_app_bundle_as_single_target() {
        let root = std::env::temp_dir().join(format!(
            "projectx_discovery_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        let bundle = root.join("Example.app");
        let macos = bundle.join("Contents").join("MacOS");
        fs::create_dir_all(&macos).expect("macos dir");
        fs::write(macos.join("Example"), b"primary").expect("primary");
        fs::write(
            bundle.join("Contents").join("Info.plist"),
            b"<plist></plist>",
        )
        .expect("plist");

        let discovered = collect_files(std::slice::from_ref(&root), 32);
        fs::remove_dir_all(root).ok();

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].path, bundle);
    }
}
