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
    let urls = vec![
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Backdoor.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Trojan.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/antidebug_antivm/antidebug_antivm.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/capabilities/capabilities.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/webshells/Webshells_index.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/exploit_kits/exploit_kits.yar",
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/maldocs/maldocs_index.yar",
];

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