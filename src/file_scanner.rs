use std::fs;

pub fn scan_file(file_name: &str) -> bool {
    // Use the below struct initialization to create the file ojbect and collect the metadata.
    let new_file =  File {
        name: String::from("example.txt"),
        size: 1024,
        file_type: String::from("txt"),
        hash: String::from("abc123"),
        header: String::from("header_info"),
        contents: vec![0; 1024], // Placeholder for file contents
    };
    let result = analyze_file(&new_file);

    result
}

struct File {
    name: String,
    size: u64,
    file_type: String,
    hash: String,
    header: String,
    contents: Vec<u8>, // Might want to switch this to something else in order to store the remaining file contents.
}

// The following will be used to run through the tests on each separate area of the file, returning a boolean of the file's safety.
fn analyze_file(file: &File) -> bool {
    println!("Analyzing file: {}", file.name);
    // Perform analysis on the file contents
    // Will return false if the file isn't safe. 
    /* 
        Ensure that the file is analyzed piece by piece and allowing for a false return after each portion is analyzed to ensure the shortest
        possible lifetime of the file on each device.
    */
    true
}