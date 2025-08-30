mod gui;

fn main() {
    println!("Hello, World!");
    println!("Ok maybe this works");
    gui::gui();
}

// The following function will run through each area of the file collecting the data to fill out the struct essentially. 
fn collect_file_info(new_file: &File) -> File{
    println!("Collecting information for file: {}", new_file.name);
    println!("File size: {} bytes", new_file.size);
    println!("File type: {}", new_file.file_type);
    println!("File hash: {}", new_file.hash);
    println!("File header: {}", new_file.header);
    println!("File contents: {:?}", new_file.contents);
    new_file.clone()
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
fn analyze_file(new_file: &File) -> bool {
    println!("Analyzing file: {}", new_file.name);
    // Perform analysis on the file contents
    // Will return false if the file isn't safe. 
    /* 
        Ensure that the file is analyzed piece by piece and allowing for a false return after each portion is analyzed to ensure the shortest
        possible lifetime of the file on each device.
    */
    true
}