use sha2::{Digest, Sha256};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalwareHashStatus {
    Match,
    NoMatch,
    Unknown,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn md5_hex(_bytes: &[u8]) -> Option<String> {
    None
}

pub fn ssdeep(_bytes: &[u8]) -> Option<String> {
    None
}

pub fn tlsh(_bytes: &[u8]) -> Option<String> {
    None
}

pub fn check_malware_hash(hash: &str) -> MalwareHashStatus {
    let auth_key = match std::env::var("MALWAREBAZAAR_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("MALWAREBAZAAR_KEY environment variable not set");
            return MalwareHashStatus::Unknown;
        }
    };

    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    let response = match CLIENT
        .get_or_init(reqwest::blocking::Client::new)
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("User-Agent", "ProjectX")
        .header("Auth-Key", auth_key)
        .form(&[("query", "get_info"), ("hash", hash)])
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("MalwareBazaar request failed: {}", e);
            return MalwareHashStatus::Unknown;
        }
    };

    let raw_text = match response.text() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to read MalwareBazaar response: {}", e);
            return MalwareHashStatus::Unknown;
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&raw_text) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to parse MalwareBazaar JSON: {}", e);
            return MalwareHashStatus::Unknown;
        }
    };

    match json["query_status"].as_str() {
        Some("ok") => MalwareHashStatus::Match,
        Some("no_results") => MalwareHashStatus::NoMatch,
        _ => MalwareHashStatus::Unknown,
    }
}
