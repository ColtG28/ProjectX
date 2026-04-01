use std::fs;
use std::path::Path;
use sha2::{Sha256, Digest};
use crate::header_check::find_header;
use crate::hash_check::check_malware_hash;
use crate::content_check::check_file_contents;

pub fn init_quarantine() {
    let path = Path::new("quarantine");
    if !path.exists() {
        fs::create_dir(path).expect("Failed to create quarantine folder");
    }
}

fn quarantine_file(file_path: &str) -> Result<String, std::io::Error> {
    let source = Path::new(file_path);
    let file_name = source.file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid file path"))?;

    let quarantine_path = Path::new("quarantine").join(file_name);
    fs::copy(source, &quarantine_path)?;
    println!("File quarantined: {:?}", quarantine_path);
    Ok(quarantine_path.to_string_lossy().to_string())
}

fn release_file(quarantine_path: &str, original_path: &str) -> Result<(), std::io::Error> {
    fs::rename(quarantine_path, original_path)?;
    println!("File released from quarantine: {}", original_path);
    Ok(())
}

fn delete_quarantined_file(quarantine_path: &str) -> Result<(), std::io::Error> {
    fs::remove_file(quarantine_path)?;
    println!("Quarantined file deleted: {}", quarantine_path);
    Ok(())
}

pub fn scan_file(file_path: &str) -> bool {
    // Quarantine first, scan the quarantined copy
    let quarantine_path = match quarantine_file(file_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to quarantine file: {}", e);
            return false;
        }
    };

    let is_safe = scan_quarantined_file(&quarantine_path);

    if is_safe {
        match release_file(&quarantine_path, file_path) {
            Ok(_) => println!("File is safe, restored to original location."),
            Err(e) => eprintln!("Failed to restore file: {}", e),
        }
    } else {
        println!("File is unsafe, left in quarantine: {}", quarantine_path);
    }

    is_safe
}

fn scan_quarantined_file(file_path: &str) -> bool {
    let metadata = match fs::metadata(file_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read metadata: {}", e);
            return false;
        }
    };

    // File name
    let name = Path::new(file_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // File size
    let size = metadata.len();

    // File type
    let file_type = Path::new(file_path)
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Read raw bytes for hashing and hex
    let bytes = match fs::read(file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read file bytes: {}", e);
            return false;
        }
    };

    // Hash the actual file contents
    let mut sha256 = Sha256::new();
    sha256.update(&bytes);
    let hash = format!("{:x}", sha256.finalize());

    // Hex encode actual file bytes
    let hex = hex::encode(&bytes);

    // File contents as string
    let contents = String::from_utf8_lossy(&bytes).to_string();

    let file = File {
        name,
        size,
        file_type,
        hash,
        hex,
        contents,
    };

    analyze_file(&file)
}

struct File {
    name: String,
    size: u64,
    file_type: String,
    hash: String,
    hex: String,
    contents: String,
}

fn analyze_file(file: &File) -> bool {
    println!("File name: {}", file.name);
    println!("File size: {} bytes", file.size);
    println!("File type: {}", file.file_type);
    println!("File hash: {}", file.hash);

    let mut rating = 10;

    // File size checks
    if file.size == 0 {
        return false;
    } else if file.size < 512 {
        rating -= 2;
    } else if file.size < 1024 {
        rating -= 1;
    } else if file.size < 52_428_800 {
        rating += 0;
    } else if file.size <= 2_147_483_648 {
        rating -= 1;
    } else {
        rating -= 2;
    }

    // File hash check
    let hash_check = check_malware_hash(&file.hash);
    if hash_check {
        println!("File hash matches known malware hash.");
        return false;
    } else {
        println!("File hash does not match any known malware hashes.");
    }

    // File header check
    let header_check = find_header(&file.hex, &file.file_type);
    if !header_check {
        println!("File header does not match file type.");
        rating -= 3;
    }

    // File content check
    let content_check = check_file_contents(&file.contents);
    if content_check {
        println!("Suspicious content found in file.");
        rating -= 5;
    }

    println!("Final rating: {}", rating);
    rating >= 5
}