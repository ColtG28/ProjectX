use std::fs;
use sha2::{Sha256, Digest};
use hex;
use std::path::Path;
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use serde::Deserialize;
/*
    This function will be used to scan a file given its path. It will collect the necessary information about the file
    and then pass it to the analyze_file function for further analysis.    
 */
pub fn scan_file(file_path: &str) -> bool {
    let metadata = fs::metadata(file_path).unwrap();
    
    // File name
    let name = Path::new(file_path).file_name().unwrap_or_default().to_string_lossy().to_string();
    
    // File size
    let size = metadata.len();
    
    // File type
    let n1 = file_path.find(".").unwrap_or(file_path.len());
    let file_type = &file_path[n1..];

    // Hash
    let mut sha256 = Sha256::new();
    sha256.update(file_path);
    let hash: String = format!("{:x}", sha256.finalize());

    // Collect file hex
    let hex = hex::encode(file_path);

    // Collect file contents
    let contents = fs::read_to_string(file_path).unwrap_or(String::from("Could not read file contents"));

    let new_file =  File {
        name: name,
        size: size,
        file_type: file_type,
        hash: &hash,
        hex: hex,
        contents: contents,
    };

    let result = analyze_file(&new_file);

    result
}

struct File<'a> {
    name: String,
    size: u64,
    file_type: &'a str,
    hash: &'a str,
    hex: String,
    contents: String, 
}


// The following will be used to run through the tests on each separate area of the file, returning a boolean of the file's safety.
fn analyze_file(file: &File) -> bool {
    println!("File name: {}", file.name);
    println!("File size: {} bytes", file.size);
    println!("File type: {:#?}", file.file_type);
    println!("File hash: {}", file.hash);
    println!("File hex: {}", file.hex);
    println!("File contents: {}", file.contents);

    let mut rating = 10; 

    if file.size < 1024 {
        rating -= 2;
    }

    if check_query(file.hash) == true {
        rating -= 5;
    } 
    
    // Perform analysis on the file contents
    // Will return false if the file isn't safe. 
    /* 
        Ensure that the file is analyzed piece by piece and allowing for a false return after each portion is analyzed to ensure the shortest
        possible lifetime of the file on each device.
    */
    true
}

fn check_query(sha256: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let url = String::from("https://bazaar.abuse.ch/browse/");
    let client = Client::builder().build()?;
    let mut form = std::collections::HashMap::new();
    form.insert("query", "get_info");
    form.insert("sha256",sha256);

    let resp = client.post(url)
        .header(USER_AGENT, "my-malware-checker/1.0")
        .form(&form)
        .send()?
        .error_for_status()?;

    let text = resp.text()?;
    let mb_resp: MBResponse = serde_json::from_str(&text)?;

    if mb_resp.query_status.to_lowercase() == "ok" && !mb_resp.data.is_empty() {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Deserialize, Debug)]
struct MBResponse {
    query_status: String,
    #[serde(default)]
    data: Vec<serde_json::Value>,
}