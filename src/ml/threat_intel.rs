use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::r#static::file::hash::{check_malware_hash, MalwareHashStatus};

#[derive(Debug, Clone)]
pub struct ThreatIntelMatch {
    pub provider: &'static str,
    pub detail: String,
}

pub fn lookup_hash(sha256: &str) -> Vec<ThreatIntelMatch> {
    let mut matches = Vec::new();

    if let Some(detail) = lookup_local_feed(sha256) {
        matches.push(ThreatIntelMatch {
            provider: "LocalFeed",
            detail,
        });
    }

    if let Some(detail) = lookup_known_bad_hashes(sha256) {
        matches.push(ThreatIntelMatch {
            provider: "KnownBadHashes",
            detail,
        });
    }

    if std::env::var("MALWAREBAZAAR_KEY").is_ok() {
        match check_malware_hash(sha256) {
            MalwareHashStatus::Match => matches.push(ThreatIntelMatch {
                provider: "MalwareBazaar",
                detail: "hash match".to_string(),
            }),
            MalwareHashStatus::NoMatch | MalwareHashStatus::Unknown => {}
        }
    }

    if let Some(detail) = lookup_virustotal(sha256) {
        matches.push(ThreatIntelMatch {
            provider: "VirusTotal",
            detail,
        });
    }

    matches
}

fn lookup_local_feed(sha256: &str) -> Option<String> {
    let path = Path::new("quarantine/threat_intel_iocs.json");
    let text = fs::read_to_string(path).ok()?;
    let map = serde_json::from_str::<HashMap<String, String>>(&text).ok()?;
    map.get(sha256).cloned()
}

fn lookup_known_bad_hashes(sha256: &str) -> Option<String> {
    let path = Path::new("quarantine/known_bad_hashes.txt");
    let text = fs::read_to_string(path).ok()?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let mut parts = line.splitn(2, char::is_whitespace);
            let hash = parts.next()?.trim();
            let note = parts
                .next()
                .unwrap_or("matched local known-bad hash list")
                .trim();
            hash.eq_ignore_ascii_case(sha256)
                .then_some(note.to_string())
        })
}

fn lookup_virustotal(sha256: &str) -> Option<String> {
    let api_key = std::env::var("VT_API_KEY").ok()?;
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("https://www.virustotal.com/api/v3/files/{sha256}"))
        .header("x-apikey", api_key)
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let value = response.json::<serde_json::Value>().ok()?;
    let stats = &value["data"]["attributes"]["last_analysis_stats"];
    let malicious = stats["malicious"].as_u64().unwrap_or(0);
    let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
    (malicious > 0 || suspicious > 0)
        .then_some(format!("malicious={} suspicious={}", malicious, suspicious))
}
