use std::fs;
use std::fs::FileType;

pub fn scan_file(file_path: &str) -> bool {
    // Collect the metadata.
    let metadata = fs::metadata(file_path).unwrap();
    let name = String::from(file_path);
    let size = metadata.len();
    let file_type = metadata.file_type();
    let new_file =  File {
        name: name,
        size: size,
        file_type: file_type,
        hash: String::from("abc123"), // Need to collect.
        header: String::from("header_info"), // Need to collect.
        contents: vec![0; 1024], // Placeholder for file contents
    };
    let result = analyze_file(&new_file);

    result
}

struct File {
    name: String,
    size: u64,
    file_type: FileType,
    hash: String,
    header: String,
    contents: Vec<u8>, // Might want to switch this to something else in order to store the remaining file contents.
}


// The following will be used to run through the tests on each separate area of the file, returning a boolean of the file's safety.
fn analyze_file(file: &File) -> bool {
    println!("Analyzing file: {}", file.name);
    println!("File name: {}", file.name);
    println!("File size: {}", file.size);
    println!("File type: {:#?}", file.file_type);
    
    // Perform analysis on the file contents
    // Will return false if the file isn't safe. 
    /* 
        Ensure that the file is analyzed piece by piece and allowing for a false return after each portion is analyzed to ensure the shortest
        possible lifetime of the file on each device.
    */
    true
}