pub fn check_malware_hash(hash: &str) -> bool {
    let auth_key = match std::env::var("MALWAREBAZAAR_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("MALWAREBAZAAR_KEY environment variable not set");
            return false;
        }
    };

    let client = reqwest::blocking::Client::new();

    let response = match client
        .post("https://mb-api.abuse.ch/api/v1/")
        .header("User-Agent", "ProjectX")
        .header("Auth-Key", auth_key)
        .form(&[("query", "get_info"), ("hash", hash)])
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("MalwareBazaar request failed: {}", e);
            return false;
        }
    };

    let raw_text = match response.text() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to read MalwareBazaar response: {}", e);
            return false;
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&raw_text) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to parse MalwareBazaar JSON: {}", e);
            return false;
        }
    };

    match json["query_status"].as_str() {
        Some("ok") => true,
        Some("no_results") => false,
        _ => false
    }
}