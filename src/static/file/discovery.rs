use std::fs;
use std::path::{Path, PathBuf};

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
