use crate::r#static::types::View;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub name: String,
    pub family: Option<String>,
    pub confidence: RuleConfidence,
    pub matched_literals: Vec<String>,
    pub view_name: String,
}

static KEYWORDS: OnceLock<Vec<String>> = OnceLock::new();
static HTTP_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
static KEYWORD_RE: OnceLock<Regex> = OnceLock::new();

pub fn run_on_views(rules: &[String], views: &[View]) -> Vec<RuleMatch> {
    let mut hits = Vec::new();

    for rule in rules {
        let literals = quoted_literals(rule);
        if literals.is_empty() {
            continue;
        }
        let required_count = required_literal_count(rule, literals.len());
        let rule_name = short_rule_name(rule);
        let family = meta_value(rule, "family");
        let confidence = rule_confidence(rule);

        for view in views {
            let lowered_view = view.content.to_ascii_lowercase();
            let matched_literals = literals
                .iter()
                .filter(|literal| lowered_view.contains(literal.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            let matched = if required_count >= literals.len() {
                matched_literals.len() == literals.len()
            } else {
                matched_literals.len() >= required_count
            };

            if matched {
                hits.push(RuleMatch {
                    name: rule_name.clone(),
                    family: family.clone(),
                    confidence,
                    matched_literals,
                    view_name: view.name.clone(),
                });
            }
        }
    }

    hits
}

pub fn check_file_contents(contents: &str) -> bool {
    let keywords = keywords();

    for keyword in keywords {
        if contents.contains(keyword.as_str()) {
            println!("Suspicious keyword found: {}", keyword);
            return true;
        }
    }
    false
}

pub fn preload_keywords() -> usize {
    keywords().len()
}

fn keywords() -> &'static Vec<String> {
    KEYWORDS.get_or_init(fetch_yara_keywords)
}

fn fetch_yara_keywords() -> Vec<String> {
    if allow_online_rule_preload() {
        let fresh = fetch_yara_keywords_from_network();
        if !fresh.is_empty() {
            save_cached_keywords(&fresh);
            println!("Loaded {} keywords from YARA rules", fresh.len());
            return fresh;
        }
    }

    let cached = load_cached_keywords();
    if !cached.is_empty() {
        eprintln!(
            "YARA network preload unavailable; loaded {} cached keywords.",
            cached.len()
        );
        return cached;
    }

    eprintln!("YARA keyword preload failed (network + cache unavailable).");
    Vec::new()
}

fn allow_online_rule_preload() -> bool {
    std::env::var("PROJECTX_ALLOW_ONLINE_RULE_PRELOAD")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn fetch_yara_keywords_from_network() -> Vec<String> {
    let urls = fetch_yara_file_urls();
    if urls.is_empty() {
        return Vec::new();
    }

    let client = HTTP_CLIENT.get_or_init(reqwest::blocking::Client::new);
    let keyword_re = KEYWORD_RE.get_or_init(|| Regex::new(r#""([^"]{4,50})""#).expect("regex"));
    let mut keywords = Vec::new();

    for url in urls {
        let Ok(response) = client.get(url).send() else {
            continue;
        };
        let Ok(text) = response.text() else { continue };

        for cap in keyword_re.captures_iter(&text) {
            let kw = cap[1].to_string();
            if !keywords.contains(&kw) {
                keywords.push(kw);
            }
        }
    }

    keywords
}

fn cache_path() -> &'static Path {
    Path::new("quarantine/yara_keywords_cache.json")
}

fn save_cached_keywords(keywords: &[String]) {
    if let Some(parent) = cache_path().parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(serialized) = serde_json::to_string(keywords) {
        let _ = fs::write(cache_path(), serialized);
    }
}

fn load_cached_keywords() -> Vec<String> {
    let Ok(text) = fs::read_to_string(cache_path()) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<String>>(&text).unwrap_or_default()
}

fn fetch_yara_file_urls() -> Vec<String> {
    let client = HTTP_CLIENT.get_or_init(reqwest::blocking::Client::new);
    let mut urls = Vec::new();

    let dirs = vec![
        "malware",
        "webshells",
        "antidebug_antivm",
        "exploit_kits",
        "email",
    ];

    for dir in dirs {
        let api_url = format!(
            "https://api.github.com/repos/Yara-Rules/rules/contents/{}",
            dir
        );

        let Ok(response) = client.get(&api_url).header("User-Agent", "ProjectX").send() else {
            continue;
        };

        let Ok(text) = response.text() else {
            continue;
        };

        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };

        if let Some(files) = json.as_array() {
            for file in files {
                if let Some(name) = file["name"].as_str() {
                    if (name.ends_with(".yar") || name.ends_with(".yara"))
                        && file["download_url"].as_str().is_some()
                    {
                        urls.push(
                            file["download_url"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string(),
                        );
                    }
                }
            }
        }
    }
    urls
}

fn quoted_literals(rule: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut in_strings = false;

    for line in rule.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("strings:") {
            in_strings = true;
            continue;
        }
        if trimmed.starts_with("condition:") {
            break;
        }
        if !in_strings || !trimmed.contains('=') {
            continue;
        }

        let bytes = trimmed.as_bytes();
        let mut start = None;
        for (idx, b) in bytes.iter().enumerate() {
            if *b == b'"' {
                if let Some(s) = start {
                    if idx > s + 1 {
                        let literal = trimmed[s + 1..idx].to_ascii_lowercase();
                        if !literals.contains(&literal) {
                            literals.push(literal);
                        }
                    }
                    start = None;
                } else {
                    start = Some(idx);
                }
            }
        }
    }

    literals
}

fn short_rule_name(rule: &str) -> String {
    for line in rule.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            return trimmed
                .replacen("rule ", "", 1)
                .trim_end_matches('{')
                .trim()
                .to_string();
        }
    }
    "unknown_rule".to_string()
}

fn meta_value(rule: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = ");
    for line in rule.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix(&needle) {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

fn rule_confidence(rule: &str) -> RuleConfidence {
    match meta_value(rule, "confidence")
        .unwrap_or_else(|| "medium".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "high" => RuleConfidence::High,
        "low" => RuleConfidence::Low,
        _ => RuleConfidence::Medium,
    }
}

fn required_literal_count(rule: &str, literal_count: usize) -> usize {
    let lowered = rule.to_ascii_lowercase();
    if lowered.contains("all of them") {
        return literal_count.max(1);
    }

    for count in 2..=literal_count.max(2) {
        let needle = format!("{count} of them");
        if lowered.contains(&needle) {
            return count;
        }
    }

    1
}

#[cfg(test)]
mod tests {
    use crate::r#static::types::View;

    use super::run_on_views;

    #[test]
    fn multi_literal_rules_require_corroboration_when_requested() {
        let rule = r#"
            rule suspicious_combo {
                strings:
                    $a = "VirtualAlloc"
                    $b = "CreateRemoteThread"
                condition:
                    all of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "VirtualAlloc and CreateRemoteThread appear here",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "suspicious_combo");
    }

    #[test]
    fn multi_literal_rules_do_not_fire_on_partial_matches() {
        let rule = r#"
            rule suspicious_combo {
                strings:
                    $a = "VirtualAlloc"
                    $b = "CreateRemoteThread"
                condition:
                    all of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new("strings", "VirtualAlloc only")],
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn partial_count_rules_require_requested_literal_count() {
        let rule = r#"
            rule suspicious_combo {
                strings:
                    $a = "bitsadmin"
                    $b = "Start-BitsTransfer"
                    $c = "Start-Process"
                condition:
                    2 of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "bitsadmin and Start-BitsTransfer appear here",
            )],
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn family_and_confidence_metadata_are_preserved() {
        let rule = r#"
            rule suspicious_combo {
                meta:
                    confidence = "high"
                    family = "powershell_hidden_webrequest"
                strings:
                    $a = "Invoke-WebRequest"
                    $b = "WindowStyle Hidden"
                    $c = "Start-Process"
                    $d = "UseBasicParsing"
                condition:
                    3 of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "Invoke-WebRequest with WindowStyle Hidden and Start-Process",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].family.as_deref(),
            Some("powershell_hidden_webrequest")
        );
        assert!(matches!(hits[0].confidence, super::RuleConfidence::High));
    }

    #[test]
    fn cross_platform_loader_config_family_requires_corroboration() {
        let rule = r#"
            rule suspicious_cross_platform_loader_config_stage {
                meta:
                    confidence = "medium"
                    family = "cross_platform_loader_config"
                strings:
                    $a = "LoadLibrary"
                    $b = "payload"
                    $c = "config"
                condition:
                    all of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "LoadLibrary reads a config and a payload manifest before execution",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].family.as_deref(),
            Some("cross_platform_loader_config")
        );
        assert!(matches!(hits[0].confidence, super::RuleConfidence::Medium));
    }

    #[test]
    fn office_encoded_shell_stage_family_is_tagged() {
        let rule = r#"
            rule suspicious_office_encoded_shell_stage {
                meta:
                    confidence = "medium"
                    family = "office_encoded_shell_stage"
                strings:
                    $a = "Document_Open"
                    $b = "WScript.Shell"
                    $c = "FromBase64String"
                condition:
                    all of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "Document_Open uses WScript.Shell and FromBase64String",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].family.as_deref(),
            Some("office_encoded_shell_stage")
        );
    }

    #[test]
    fn powershell_archive_download_launcher_family_is_tagged() {
        let rule = r#"
            rule suspicious_powershell_archive_download_launcher {
                meta:
                    confidence = "high"
                    family = "powershell_archive_launcher"
                strings:
                    $a = "Invoke-WebRequest"
                    $b = "Expand-Archive"
                    $c = "Start-Process"
                condition:
                    all of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "Invoke-WebRequest then Expand-Archive before Start-Process",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].family.as_deref(),
            Some("powershell_archive_launcher")
        );
        assert!(matches!(hits[0].confidence, super::RuleConfidence::High));
    }

    #[test]
    fn high_signal_pe_injection_network_family_requires_three_literals() {
        let rule = r#"
            rule suspicious_pe_injection_network_chain {
                meta:
                    confidence = "high"
                    family = "pe_injection_network"
                strings:
                    $a = "VirtualAlloc"
                    $b = "WriteProcessMemory"
                    $c = "CreateRemoteThread"
                    $d = "WinHttpOpen"
                condition:
                    3 of them
            }
        "#;
        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "VirtualAlloc, WriteProcessMemory, and CreateRemoteThread appear here",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].family.as_deref(), Some("pe_injection_network"));
        assert!(matches!(hits[0].confidence, super::RuleConfidence::High));
    }

    #[test]
    fn realworld_high_signal_rule_families_require_multi_literal_chains() {
        let rule = r#"
            rule suspicious_multi_stage_download_pattern {
                meta:
                    confidence = "high"
                    family = "multi_stage_download_pattern"
                    rationale = "Requires multi-stage download, staging, and execution-style markers"
                strings:
                    $a = "DownloadFile"
                    $b = "Invoke-WebRequest"
                    $c = "stage"
                    $d = "Start-Process"
                    $e = "WriteAllBytes"
                condition:
                    4 of them
            }
        "#;
        let partial = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "DownloadFile and Invoke-WebRequest only",
            )],
        );
        assert!(partial.is_empty());

        let hits = run_on_views(
            &[rule.to_string()],
            &[View::new(
                "strings",
                "DownloadFile then Invoke-WebRequest stage and Start-Process",
            )],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].family.as_deref(),
            Some("multi_stage_download_pattern")
        );
        assert!(matches!(hits[0].confidence, super::RuleConfidence::High));
    }
}
