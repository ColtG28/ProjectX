use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn api_scan_parallel_returns_json_report() {
    let path = unique_path("api_scan_parallel_returns_json_report.ps1");
    fs::write(
        &path,
        "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
    )
    .unwrap();

    let results = projectx::r#static::scan_inputs_parallel(&[path.clone()], None, Some(1), 8);
    assert_eq!(results.len(), 1);

    let outcome = results[0].outcome.as_ref().unwrap();
    let report = serde_json::from_str::<serde_json::Value>(&outcome.json_report).unwrap();
    assert!(report.get("verdict").is_some());
    assert!(outcome.report_path.is_file());

    cleanup_result(&path, outcome);
}

#[test]
fn cli_sandbox_plan_outputs_json() {
    let path = unique_path("cli_sandbox_plan_outputs_json.bin");
    fs::write(&path, "hello world").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ProjectX"))
        .args(["--cli", "--sandbox-plan", "--json", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("valid json output");
    assert_eq!(parsed["engine"], "docker");

    let _ = fs::remove_file(path);
}

#[test]
fn cli_pretty_json_scan_outputs_structured_report() {
    let path = unique_path("cli_pretty_json_scan_outputs_structured_report.txt");
    fs::write(&path, "IEX(New-Object Net.WebClient)").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ProjectX"))
        .args(["--cli", "--pretty-json", path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("valid json output");
    assert!(parsed.get("file").is_some());
    assert!(parsed.get("findings").is_some());

    if let Some(quarantine) = parsed["file"]["quarantine_path"].as_str() {
        let _ = fs::remove_file(quarantine);
    }
}

#[test]
fn cli_detonate_scan_includes_dynamic_analysis_section() {
    let path = unique_path("cli_detonate_scan_includes_dynamic_analysis_section.sh");
    fs::write(&path, "#!/bin/sh\necho hello\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ProjectX"))
        .args([
            "--cli",
            "--pretty-json",
            "--detonate",
            "--sandbox-timeout-ms",
            "500",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("valid json output");
    assert!(parsed.get("dynamic_analysis").is_some());

    if let Some(quarantine) = parsed["file"]["quarantine_path"].as_str() {
        let _ = fs::remove_file(quarantine);
    }
}

fn unique_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("projectx_{nanos}_{name}"))
}

fn cleanup_result(path: &PathBuf, outcome: &projectx::r#static::ScanOutcome) {
    let _ = fs::remove_file(path);
    if outcome.quarantine_path.is_file() {
        let _ = fs::remove_file(&outcome.quarantine_path);
    }
    if outcome.report_path.is_file() {
        let _ = fs::remove_file(&outcome.report_path);
    }
}
