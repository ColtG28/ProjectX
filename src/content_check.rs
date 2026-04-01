pub fn check_file_contents(contents: &str) -> bool {
    let keywords = fetch_yara_keywords();
    
    for keyword in &keywords {
        if contents.contains(keyword.as_str()) {
            println!("Suspicious keyword found: {}", keyword);
            return true;
        }
    }
    false
}

fn fetch_yara_keywords() -> Vec<String> {
    let urls = fetch_yara_file_urls();
    let client = reqwest::blocking::Client::new();
    let keyword_re = regex::Regex::new(r#""([^"]{4,50})""#).unwrap();
    let mut keywords = Vec::new();

    for url in urls {
        let Ok(response) = client.get(url).send() else { continue };
        let Ok(text) = response.text() else { continue };

        for cap in keyword_re.captures_iter(&text) {
            let kw = cap[1].to_string();
            if !keywords.contains(&kw) {
                keywords.push(kw);
            }
        }
    }

    println!("Loaded {} keywords from YARA rules", keywords.len());
    keywords
}

fn fetch_yara_file_urls() -> Vec<String> {
    let client = reqwest::blocking::Client::new();
    let mut urls = Vec::new();
    
    let dirs = vec![
        "malware",
        "webshells",
        "antidebug_antivm",
        "exploit_kits",
        "email"
    ];

    for dir in dirs {
        let api_url = format!(
            "https://api.github.com/repos/Yara-Rules/rules/contents/{}",
            dir
        );

        let Ok(response) = client
            .get(&api_url)
            .header("User-Agent", "ProjectX")
            .send() else { continue };

        let Ok(json) = response.json::<serde_json::Value>() else { continue };

        if let Some(files) = json.as_array() {
            for file in files {
                if let Some(name) = file["name"].as_str() {
                    if name.ends_with(".yar") || name.ends_with(".yara") {
                        if let Some(url) = file["download_url"].as_str() {
                            urls.push(url.to_string());
                        }
                    }
                }
            }
        }
    }
    urls
}