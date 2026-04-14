use std::fs;
use std::path::PathBuf;
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

const BUNDLED_RULES: &[(&str, &str)] = &[(
    "passive_triage_rules.yar",
    include_str!("rules/passive_triage_rules.yar"),
)];

pub fn load_rule_strings() -> Vec<String> {
    load_rule_bundle().rules
}

pub fn load_rule_bundle() -> RuleBundle {
    let sources = load_rule_sources();
    if sources.is_empty() {
        return RuleBundle {
            rules: Vec::new(),
            version: "no_rules".to_string(),
        };
    }

    let signature = source_signature(&sources);
    let cache = RULE_BUNDLE.get_or_init(|| Mutex::new(None));
    if let Ok(mut cached) = cache.lock() {
        if let Some(bundle) = cached.as_ref() {
            if bundle.signature == signature {
                return bundle.bundle.clone();
            }
        }

        let bundle = build_bundle(&sources);
        *cached = Some(CachedBundle {
            signature,
            bundle: bundle.clone(),
        });
        return bundle;
    }

    build_bundle(&sources)
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

fn load_rule_sources() -> Vec<(String, String)> {
    let override_dir = crate::app_paths::yara_rules_override_dir();
    let mut files = override_rule_files(&override_dir);
    if files.is_empty() {
        return BUNDLED_RULES
            .iter()
            .map(|(name, contents)| ((*name).to_string(), (*contents).to_string()))
            .collect();
    }

    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

fn override_rule_files(dir: &PathBuf) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let extension = path.extension()?.to_str()?;
            if extension != "yar" && extension != "yara" {
                return None;
            }
            let contents = fs::read_to_string(&path).ok()?;
            Some((path.to_string_lossy().to_string(), contents))
        })
        .collect()
}

fn build_bundle(sources: &[(String, String)]) -> RuleBundle {
    let mut rules = Vec::new();
    let mut version_material = String::new();

    for (name, contents) in sources {
        version_material.push_str(name);
        version_material.push('\n');
        version_material.push_str(contents);
        version_material.push('\n');
        rules.extend(split_rules(contents));
    }

    let version = if version_material.is_empty() {
        "empty_rules".to_string()
    } else {
        crate::r#static::file::hash::sha256_hex(version_material.as_bytes())
    };

    RuleBundle { rules, version }
}

fn split_rules(contents: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let mut current = String::new();

    for line in contents.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("rule ") && !current.trim().is_empty() {
            rules.push(current.trim().to_string());
            current.clear();
        }

        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);
    }

    if !current.trim().is_empty() {
        rules.push(current.trim().to_string());
    }

    rules
}

fn source_signature(sources: &[(String, String)]) -> String {
    let mut signature = String::new();
    for (name, contents) in sources {
        signature.push_str(name);
        signature.push(':');
        signature.push_str(&contents.len().to_string());
        signature.push(':');
        signature.push_str(&crate::r#static::file::hash::sha256_hex(
            contents.as_bytes(),
        ));
        signature.push('\n');
    }
    crate::r#static::file::hash::sha256_hex(signature.as_bytes())
}
