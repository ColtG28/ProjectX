use std::path::Path;

pub fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            return metadata.permissions().mode() & 0o111 != 0;
        }
    }

    #[cfg(windows)]
    {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            return matches!(
                ext.to_ascii_lowercase().as_str(),
                "exe" | "bat" | "cmd" | "ps1"
            );
        }
    }

    false
}
