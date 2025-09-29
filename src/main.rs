mod gui;
mod file_scanner;

fn main() {
    println!("Hello, World!");
    let file_path = "C:\\Users\\762915\\Desktop\\TestFile.txt";
    file_scanner::scan_file(file_path);
    let _ = gui::gui();
    
    /*
        Windows file path: C:\\Users\\762915\\Desktop\\TestFile.txt
        Mac file path: /Users/coltongorman/Desktop/TestFile.txt
     */
    

    // Run the info collect and the analysis here...
}