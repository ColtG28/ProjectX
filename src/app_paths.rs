use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const APP_DIR_NAME: &str = "ProjectX";
const ENV_DATA_DIR: &str = "PROJECTX_DATA_DIR";
const ENV_CONFIG_DIR: &str = "PROJECTX_CONFIG_DIR";
const ENV_CACHE_DIR: &str = "PROJECTX_CACHE_DIR";

#[derive(Debug, Clone)]
struct AppPaths {
    config_root: PathBuf,
    data_root: PathBuf,
    cache_root: PathBuf,
}

static APP_PATHS: OnceLock<AppPaths> = OnceLock::new();

pub fn config_root() -> &'static Path {
    &paths().config_root
}

pub fn data_root() -> &'static Path {
    &paths().data_root
}

pub fn cache_root() -> &'static Path {
    &paths().cache_root
}

pub fn quarantine_dir() -> PathBuf {
    data_root().join("quarantine")
}

pub fn reports_dir() -> PathBuf {
    data_root().join("reports")
}

pub fn download_monitor_dir() -> PathBuf {
    data_root().join("download_monitor")
}

pub fn telemetry_path() -> PathBuf {
    data_root().join("scan_telemetry.jsonl")
}

pub fn gui_history_path() -> PathBuf {
    data_root().join("gui_scan_history.json")
}

pub fn gui_index_path() -> PathBuf {
    data_root().join("gui_index.json")
}

pub fn gui_settings_path() -> PathBuf {
    config_root().join("gui_settings.json")
}

pub fn protection_events_path() -> PathBuf {
    data_root().join("gui_protection_events.json")
}

pub fn protection_backlog_path() -> PathBuf {
    data_root().join("gui_protection_backlog.json")
}

pub fn update_cache_path() -> PathBuf {
    config_root().join("update_check_cache.json")
}

pub fn update_log_path() -> PathBuf {
    data_root().join("update_events.log")
}

pub fn update_download_dir() -> PathBuf {
    data_root().join("updates")
}

pub fn intelligence_dir() -> PathBuf {
    data_root().join("intelligence")
}

pub fn threat_intel_iocs_path() -> PathBuf {
    data_root().join("threat_intel_iocs.json")
}

pub fn known_bad_hashes_override_path() -> PathBuf {
    data_root().join("known_bad_hashes.txt")
}

pub fn known_good_hashes_override_path() -> PathBuf {
    intelligence_dir().join("known_good_hashes.txt")
}

pub fn intelligence_store_override_path() -> PathBuf {
    intelligence_dir().join("store.json")
}

pub fn intelligence_known_bad_override_path() -> PathBuf {
    intelligence_dir().join("known_bad_hashes.txt")
}

pub fn yara_cache_path() -> PathBuf {
    cache_root().join("yara_keywords_cache.json")
}

pub fn cache_dir() -> PathBuf {
    cache_root().join("scan_cache")
}

pub fn ml_feedback_path() -> PathBuf {
    data_root().join("ml_feedback.jsonl")
}

pub fn ml_active_learning_queue_path() -> PathBuf {
    data_root().join("ml_active_learning_queue.jsonl")
}

pub fn yara_rules_override_dir() -> PathBuf {
    config_root().join("yara").join("rules")
}

pub fn ensure_app_dirs() -> Result<(), String> {
    let required = [
        config_root().to_path_buf(),
        data_root().to_path_buf(),
        cache_root().to_path_buf(),
        quarantine_dir(),
        reports_dir(),
        intelligence_dir(),
        download_monitor_dir(),
        update_download_dir(),
        cache_dir(),
    ];

    for dir in required {
        fs::create_dir_all(&dir).map_err(|error| {
            format!(
                "Failed to create ProjectX app directory {}: {error}",
                dir.display()
            )
        })?;
    }

    Ok(())
}

fn paths() -> &'static AppPaths {
    APP_PATHS.get_or_init(|| {
        let env_map = env::vars().collect::<HashMap<String, String>>();
        compute_paths(std::env::consts::OS, &env_map)
    })
}

fn compute_paths(os: &str, env_map: &HashMap<String, String>) -> AppPaths {
    if let Some(base) = non_empty_path(env_map, ENV_DATA_DIR) {
        let config_root = non_empty_path(env_map, ENV_CONFIG_DIR).unwrap_or_else(|| base.clone());
        let cache_root =
            non_empty_path(env_map, ENV_CACHE_DIR).unwrap_or_else(|| base.join("cache"));
        return AppPaths {
            config_root,
            data_root: base,
            cache_root,
        };
    }

    match os {
        "macos" => {
            let home = home_dir(env_map).unwrap_or_else(fallback_root);
            AppPaths {
                config_root: home
                    .join("Library")
                    .join("Application Support")
                    .join(APP_DIR_NAME),
                data_root: home
                    .join("Library")
                    .join("Application Support")
                    .join(APP_DIR_NAME),
                cache_root: home.join("Library").join("Caches").join(APP_DIR_NAME),
            }
        }
        "windows" => {
            let data_base = env_path(env_map, "LOCALAPPDATA")
                .or_else(|| env_path(env_map, "APPDATA"))
                .unwrap_or_else(fallback_root);
            let config_base = env_path(env_map, "APPDATA")
                .or_else(|| env_path(env_map, "LOCALAPPDATA"))
                .unwrap_or_else(|| data_base.clone());
            AppPaths {
                config_root: config_base.join(APP_DIR_NAME),
                data_root: data_base.join(APP_DIR_NAME),
                cache_root: data_base.join(APP_DIR_NAME).join("Cache"),
            }
        }
        _ => {
            let home = home_dir(env_map).unwrap_or_else(fallback_root);
            let data_base = env_path(env_map, "XDG_DATA_HOME")
                .unwrap_or_else(|| home.join(".local").join("share"));
            let config_base =
                env_path(env_map, "XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
            let cache_base =
                env_path(env_map, "XDG_CACHE_HOME").unwrap_or_else(|| home.join(".cache"));
            AppPaths {
                config_root: config_base.join(APP_DIR_NAME),
                data_root: data_base.join(APP_DIR_NAME),
                cache_root: cache_base.join(APP_DIR_NAME),
            }
        }
    }
}

fn home_dir(env_map: &HashMap<String, String>) -> Option<PathBuf> {
    env_path(env_map, "HOME").or_else(|| env_path(env_map, "USERPROFILE"))
}

fn env_path(env_map: &HashMap<String, String>, key: &str) -> Option<PathBuf> {
    env_map
        .get(key)
        .map(String::as_str)
        .and_then(non_empty_str)
        .map(PathBuf::from)
}

fn non_empty_path(env_map: &HashMap<String, String>, key: &str) -> Option<PathBuf> {
    env_path(env_map, key)
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn fallback_root() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".projectx")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_map(values: &[(&str, &str)]) -> HashMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn macos_paths_default_to_application_support_and_caches() {
        let paths = compute_paths("macos", &env_map(&[("HOME", "/Users/tester")]));
        assert_eq!(
            paths.data_root,
            PathBuf::from("/Users/tester/Library/Application Support/ProjectX")
        );
        assert_eq!(
            paths.cache_root,
            PathBuf::from("/Users/tester/Library/Caches/ProjectX")
        );
    }

    #[test]
    fn windows_paths_split_config_and_local_data() {
        let paths = compute_paths(
            "windows",
            &env_map(&[
                ("APPDATA", r"C:\Users\tester\AppData\Roaming"),
                ("LOCALAPPDATA", r"C:\Users\tester\AppData\Local"),
            ]),
        );
        assert_eq!(
            paths.config_root,
            PathBuf::from(r"C:\Users\tester\AppData\Roaming").join("ProjectX")
        );
        assert_eq!(
            paths.data_root,
            PathBuf::from(r"C:\Users\tester\AppData\Local").join("ProjectX")
        );
    }

    #[test]
    fn linux_paths_follow_xdg_directories() {
        let paths = compute_paths(
            "linux",
            &env_map(&[
                ("XDG_DATA_HOME", "/home/tester/.data"),
                ("XDG_CONFIG_HOME", "/home/tester/.cfg"),
                ("XDG_CACHE_HOME", "/home/tester/.cache-alt"),
            ]),
        );
        assert_eq!(
            paths.data_root,
            PathBuf::from("/home/tester/.data/ProjectX")
        );
        assert_eq!(
            paths.config_root,
            PathBuf::from("/home/tester/.cfg/ProjectX")
        );
        assert_eq!(
            paths.cache_root,
            PathBuf::from("/home/tester/.cache-alt/ProjectX")
        );
    }

    #[test]
    fn explicit_data_override_wins() {
        let paths = compute_paths(
            "linux",
            &env_map(&[
                ("PROJECTX_DATA_DIR", "/tmp/projectx-data"),
                ("PROJECTX_CONFIG_DIR", "/tmp/projectx-config"),
                ("PROJECTX_CACHE_DIR", "/tmp/projectx-cache"),
            ]),
        );
        assert_eq!(paths.data_root, PathBuf::from("/tmp/projectx-data"));
        assert_eq!(paths.config_root, PathBuf::from("/tmp/projectx-config"));
        assert_eq!(paths.cache_root, PathBuf::from("/tmp/projectx-cache"));
    }
}
