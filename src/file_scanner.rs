use std::fs;
use sha2::{Sha256, Digest};
use hex;
use std::path::Path;
use reqwest::blocking::Client;
use serde::Deserialize;
use crate::header_list::find_header;



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

    match check_query(file.hash, "cffbefaf6178b38f75902a99ee5463f8604a3b8bb26422e5") {
        Ok(true) => return false,
        Ok(false) => {},
        Err(e) => eprintln!("Failed to query hash: {}", e),
    }

    let is_valid = find_header(&file.hex, &file.file_type);

    /*
        THINGS TO DO:
        - Add more to file size checks
        - Fix file hash check
        - Create list for file content checks (like for scripts, macros, etc.)
        - Create algorithm to search contents for items in list
        - Create file quarentine system
     */
  
    true
}

fn check_query(sha256: &str, api_key: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let url = "https://mb-api.abuse.ch/api/v1/";
    let client = Client::builder().build()?;
    let form = [
        ("query", "sha256_hash"),
        ("hash", sha256),
    ];

    let resp = client.post(url)
        .header(api_key, "my-malware-checker/1.0",)
        .form(&form)
        .send()?
        .error_for_status()?;


    let text = resp.text()?;
    let mb_resp: MBResponse = serde_json::from_str(&text)?;

    // Helper function to check if the response status is "ok" and data is not empty, might need to be double checked
    fn is_response_ok(resp: &MBResponse) -> bool {
        resp.query_status.to_lowercase() == "ok" && !resp.data.is_empty()
    }

    Ok(is_response_ok(&mb_resp))
}

#[derive(Deserialize, Debug)]
struct MBResponse {
    query_status: String,
    #[serde(default)]
    data: Vec<serde_json::Value>,
}