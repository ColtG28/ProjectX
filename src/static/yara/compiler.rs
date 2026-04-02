use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone)]
pub struct RuleBundle {
    pub rules: Vec<String>,
    pub version: String,
}

#[derive(Debug, Clone)]
struct CachedBundle {
    signature: String,
    bundle: RuleBundle,
}

static RULE_BUNDLE: OnceLock<Mutex<Option<CachedBundle>>> = OnceLock::new();

pub fn load_rule_strings() -> Vec<String> {
    load_rule_bundle().rules
}

pub fn load_rule_bundle() -> RuleBundle {
    let rules_dir = Path::new("src/static/yara/rules");
    if !rules_dir.exists() {
        return RuleBundle {
            rules: Vec::new(),
            version: "no_rules".to_string(),
        };
    }

    let mut files = Vec::new();
    let entries = fs::read_dir(rules_dir);
    let Ok(entries) = entries else {
        return RuleBundle {
            rules: Vec::new(),
            version: "rules_unreadable".to_string(),
        };
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }

    files.sort();
    let signature = dir_signature(&files);
    let cache = RULE_BUNDLE.get_or_init(|| Mutex::new(None));
    if let Ok(mut cached) = cache.lock() {
        if let Some(bundle) = cached.as_ref() {
            if bundle.signature == signature {
                return bundle.bundle.clone();
            }
        }

        let bundle = build_bundle(&files);
        *cached = Some(CachedBundle {
            signature,
            bundle: bundle.clone(),
        });
        return bundle;
    }

    build_bundle(&files)
}

pub fn refresh_rule_bundle() -> RuleBundle {
    let cache = RULE_BUNDLE.get_or_init(|| Mutex::new(None));
    if let Ok(mut cached) = cache.lock() {
        *cached = None;
    }
    load_rule_bundle()
}

pub fn current_rule_version() -> String {
    load_rule_bundle().version
}

fn build_bundle(files: &[std::path::PathBuf]) -> RuleBundle {
    let mut rules = Vec::new();
    let mut version_material = String::new();

    for path in files {
        if let Ok(contents) = fs::read_to_string(path) {
            version_material.push_str(&path.to_string_lossy());
            version_material.push('\n');
            version_material.push_str(&contents);
            version_material.push('\n');
            rules.push(contents);
        }
    }

    let version = if version_material.is_empty() {
        "empty_rules".to_string()
    } else {
        crate::r#static::file::hash::sha256_hex(version_material.as_bytes())
    };

    RuleBundle { rules, version }
}

fn dir_signature(files: &[std::path::PathBuf]) -> String {
    use std::time::UNIX_EPOCH;

    let mut signature = String::new();
    for path in files {
        if let Ok(metadata) = fs::metadata(path) {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            signature.push_str(&format!(
                "{}:{}:{}\n",
                path.to_string_lossy(),
                metadata.len(),
                modified
            ));
        }
    }
    crate::r#static::file::hash::sha256_hex(signature.as_bytes())
}
