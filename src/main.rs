mod gui;
mod file_scanner;
mod header_check;
mod hash_check;
mod content_check;
mod setup;

fn main() {
    dotenvy::dotenv().ok();
    setup::ensure_docker();
    setup::ensure_ubuntu_image();
    file_scanner::init_quarantine();
    println!("Hello, World!");
    let file_path = "/Users/coltongorman/Desktop/TestFile.txt";
    file_scanner::scan_file(file_path);
    // let _ = gui::gui();
    
    /*
        Windows file path: C:\\Users\\762915\\Desktop\\TestFile.txt
        Mac file path: /Users/coltongorman/Desktop/TestFile.txt
    */
    
    // Run the info collect and the analysis here...
}

fn init_quarantine() {
    let path = std::path::Path::new("quarantine");
    if !path.exists() {
        std::fs::create_dir(path).expect("Failed to create quarantine folder");
    }
}

/*
    Current Plan:
    - Work out rating logic
    - Work out and test downloading setup
    - Add GUI
    
    
    Note:
    For firewall include bit scanning, DNS testing, basically check where everything comes/goes, also make it to approve scripts to ignore captcha tests (hidden ones)
*/
