use crate::r#static::types::View;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

static KEYWORDS: OnceLock<Vec<String>> = OnceLock::new();
static HTTP_CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
static KEYWORD_RE: OnceLock<Regex> = OnceLock::new();

pub fn run_on_views(rules: &[String], views: &[View]) -> Vec<String> {
    let mut hits = Vec::new();

    for rule in rules {
        let needle = first_quoted_literal(rule);
        let Some(needle) = needle else { continue };

        for view in views {
            if view.content.contains(&needle) {
                hits.push(format!(
                    "{} matched '{}' in {}",
                    short_rule_name(rule),
                    needle,
                    view.name
                ));
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
    let fresh = fetch_yara_keywords_from_network();
    if !fresh.is_empty() {
        save_cached_keywords(&fresh);
        println!("Loaded {} keywords from YARA rules", fresh.len());
        return fresh;
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

fn first_quoted_literal(rule: &str) -> Option<String> {
    let bytes = rule.as_bytes();
    let mut start = None;

    for (idx, b) in bytes.iter().enumerate() {
        if *b == b'"' {
            if let Some(s) = start {
                if idx > s + 1 {
                    return Some(rule[s + 1..idx].to_string());
                }
                start = None;
            } else {
                start = Some(idx);
            }
        }
    }

    None
}

fn short_rule_name(rule: &str) -> String {
    for line in rule.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("rule ") {
            return trimmed.replacen("rule ", "", 1);
        }
    }
    "unknown_rule".to_string()
}
