mod gui;
mod file_scanner;

fn main() {
    println!("Hello, World!");
    println!("Ok maybe this works");
    let _ = gui::gui();
    let file_path = "C:\\Users\\762915\\Desktop\\TestFile.txt";
    file_scanner::scan_file(file_path);

    // Run the info collect and the analysis here...
}