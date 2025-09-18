mod gui;
mod file_scanner;
use std::env;

fn main() {
    println!("Hello, World!");
    println!("Ok maybe this works");
    let _ = gui::gui();
    file_scanner::scan_file("/Users/coltongorman/Desktop/TestFile.txt");

    // Run the info collect and the analysis here...
}