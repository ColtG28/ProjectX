use std::fs;
use std::path::Path;
use std::process::Command;
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

    // Remove execute permissions so it can't be accidentally run
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&quarantine_path)?.permissions();
        perms.set_mode(0o600); // owner read/write only, no execute for anyone
        fs::set_permissions(&quarantine_path, perms)?;
    }

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
    let quarantine_path = match quarantine_file(file_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to quarantine file: {}", e);
            return false;
        }
    };

    let is_safe = scan_in_sandbox(&quarantine_path);

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

fn scan_in_sandbox(file_path: &str) -> bool {
    let abs_path = match fs::canonicalize(file_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to resolve path: {}", e);
            return false;
        }
    };

    let abs_str = abs_path.to_string_lossy().to_string();

    // Mount the file as read-only into the container
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",                          // Remove container after scan
            "--network", "none",             // No network access
            "--read-only",                   // Read-only filesystem
            "--cap-drop", "ALL",             // Drop all Linux capabilities
            "--security-opt", "no-new-privileges", // Prevent privilege escalation
            "--memory", "128m",              // Cap memory
            "--cpus", "0.5",                 // Cap CPU
            "-v", &format!("{}:/sandbox/file:ro", abs_str), // Mount file read-only
            "ubuntu:22.04",
            "cat", "/sandbox/file"           // Just read the file, don't execute 
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            // Pass the file contents retrieved from the sandbox into analyzers
            scan_quarantined_file(file_path)
        },
        Ok(o) => {
            eprintln!("Sandbox error: {}", String::from_utf8_lossy(&o.stderr));
            false
        },
        Err(e) => {
            eprintln!("Failed to launch sandbox: {}", e);
            false
        }
    }
}

fn scan_quarantined_file(file_path: &str) -> bool {
    let metadata = match fs::metadata(file_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to read metadata: {}", e);
            return false;
        }
    };

    let name = Path::new(file_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let size = metadata.len();

    let file_type = Path::new(file_path)
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let bytes = match fs::read(file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read file bytes: {}", e);
            return false;
        }
    };

    let mut sha256 = Sha256::new();
    sha256.update(&bytes);
    let hash = format!("{:x}", sha256.finalize());

    let hex = hex::encode(&bytes);
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

    if file.size == 0 {
        println!("File is empty.");
        return false;
    }

    if check_malware_hash(&file.hash) {
        println!("File hash matches known malware hash.");
        return false;
    } else {
        println!("File hash does not match any known malware hashes.");
    }

    let mut weighted_risk: f64 = 0.0;
    let mut total_weight: f64 = 0.0;

    // Size check
    let size_weight = 1.0;
    let size_risk = if file.size < 512 {
        0.8
    } else if file.size < 1024 {
        0.4
    } else if file.size < 52_428_800 {
        0.0 
    } else if file.size <= 2_147_483_648 {
        0.2
    } else {
        0.6
    };
    weighted_risk += size_risk * size_weight;
    total_weight += size_weight;

    // Header check 
    let header_weight = 2.5;
    let header_risk = if !find_header(&file.hex, &file.file_type) {
        println!("File header does not match file type.");
        1.0
    } else {
        0.0
    };
    weighted_risk += header_risk * header_weight;
    total_weight += header_weight;

    // YARA/content check
    let content_weight = 3.5;
    let content_risk = if check_file_contents(&file.contents) {
        1.0
    } else {
        0.0
    };
    weighted_risk += content_risk * content_weight;
    total_weight += content_weight;

    let risk_score = (weighted_risk / total_weight) * 10.0;
    let safety_score = 10.0 - risk_score;

    println!("Risk score:   {:.2}/10.0", risk_score);
    println!("Safety score: {:.2}/10.0", safety_score);

    let content_alone_fail = content_risk == 1.0 && risk_score >= 4.5;
    let header_and_size_fail = header_risk == 1.0 && size_risk >= 0.4;

    if content_alone_fail {
        return false;
    }

    if header_and_size_fail {
        return false;
    }

    safety_score >= 5.0
}