use std::fs;
use sha2::{Sha256, Digest};
use hex;
use std::path::Path;
use reqwest_wasm;

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
    let hash = format!("{:x}", sha256.finalize());

    // Collect file hex
    let hex = hex::encode(file_path);

    // Collect file contents
    let contents = fs::read_to_string(file_path).unwrap_or(String::from("Could not read file contents"));

    let new_file =  File {
        name: name,
        size: size,
        file_type: file_type,
        hash: hash,
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
    hash: String,
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

    let hash_result: bool = reqwest_wasm::get("https://bazaar.abuse.ch/browse/").text();
    
    // Perform analysis on the file contents
    // Will return false if the file isn't safe. 
    /* 
        Ensure that the file is analyzed piece by piece and allowing for a false return after each portion is analyzed to ensure the shortest
        possible lifetime of the file on each device.
    */
    true
}