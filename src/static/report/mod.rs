pub mod finding;
pub mod json;
pub mod summary;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::r#static::context::ScanContext;
use crate::r#static::types::Severity;

pub fn run(ctx: &ScanContext, severity: Severity) {
    let emit_stdout = std::env::var("PROJECTX_REPORT_STDOUT")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if emit_stdout {
        let summary = summary::build(ctx, severity);
        println!("{}", summary);
    }
}

pub fn persist(
    ctx: &ScanContext,
    severity: Severity,
    original_path: &Path,
    quarantine_path: &Path,
    restored_to_original_path: bool,
) -> Result<(String, PathBuf), String> {
    let report_json = json::render(
        ctx,
        severity,
        original_path,
        quarantine_path,
        restored_to_original_path,
    );
    let report_path = write_report_file(&report_json, &ctx.file_name)?;
    append_telemetry(&json::value(
        ctx,
        severity,
        original_path,
        quarantine_path,
        restored_to_original_path,
    ))?;
    Ok((report_json, report_path))
}

fn write_report_file(report_json: &str, file_name: &str) -> Result<PathBuf, String> {
    let reports_dir = Path::new("quarantine/reports");
    fs::create_dir_all(reports_dir)
        .map_err(|error| format!("Failed to create reports directory: {error}"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let sanitized_name = file_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let path = reports_dir.join(format!("{timestamp}_{sanitized_name}.json"));
    fs::write(&path, report_json)
        .map_err(|error| format!("Failed to write JSON report: {error}"))?;
    Ok(path)
}

fn append_telemetry(value: &serde_json::Value) -> Result<(), String> {
    let telemetry_path = Path::new("quarantine/scan_telemetry.jsonl");
    if let Some(parent) = telemetry_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create telemetry directory: {error}"))?;
    }

    let line = serde_json::to_string(value)
        .map_err(|error| format!("Failed to serialize telemetry entry: {error}"))?;
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(telemetry_path)
        .map_err(|error| format!("Failed to open telemetry log: {error}"))?;
    writeln!(file, "{line}").map_err(|error| format!("Failed to append telemetry log: {error}"))?;
    Ok(())
}
