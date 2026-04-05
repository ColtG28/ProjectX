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

#[test]
fn cli_native_ml_scan_writes_summary_report_with_evaluation() {
    let root = unique_path("cli_native_ml_scan_writes_summary_report_with_evaluation");
    fs::create_dir_all(&root).unwrap();

    let clean_path = root.join("clean_sample.txt");
    let suspicious_path = root.join("suspicious_sample.ps1");
    fs::write(&clean_path, "hello from projectx").unwrap();
    fs::write(&suspicious_path, "IEX(New-Object Net.WebClient)").unwrap();

    let manifest_path = root.join("ember_eval_manifest.csv");
    fs::write(
        &manifest_path,
        format!(
            "path,label\n{},0\n{},1\n",
            clean_path.display(),
            suspicious_path.display()
        ),
    )
    .unwrap();

    let output_prefix = root.join("native_ml_scan");
    let output = Command::new(env!("CARGO_BIN_EXE_ProjectX"))
        .args([
            "--native-ml",
            "--pretty-json",
            "--output",
            output_prefix.to_str().unwrap(),
            "--eval-manifest",
            manifest_path.to_str().unwrap(),
            clean_path.to_str().unwrap(),
            suspicious_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let parsed =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).expect("valid json output");
    assert_eq!(parsed["processed_files"], 2);
    assert_eq!(parsed["output_csv"], output_prefix.with_extension("csv").display().to_string());
    assert_eq!(
        parsed["output_jsonl"],
        output_prefix.with_extension("jsonl").display().to_string()
    );
    assert_eq!(parsed["evaluation"]["manifest_rows"], 2);
    assert_eq!(parsed["evaluation"]["matched_rows"], 2);
    assert!(parsed["evaluation"]["accuracy"].as_f64().is_some());

    let summary_path = output_prefix.with_extension("summary.json");
    let summary =
        serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&summary_path).unwrap())
            .expect("valid summary report");
    assert_eq!(summary["processed_files"], 2);
    assert_eq!(summary["evaluation"]["manifest_rows"], 2);
    assert!(output_prefix.with_extension("csv").is_file());
    assert!(output_prefix.with_extension("jsonl").is_file());
    assert!(summary_path.is_file());

    let _ = fs::remove_file(output_prefix.with_extension("csv"));
    let _ = fs::remove_file(output_prefix.with_extension("jsonl"));
    let _ = fs::remove_file(summary_path);
    let _ = fs::remove_file(manifest_path);
    let _ = fs::remove_file(clean_path);
    let _ = fs::remove_file(suspicious_path);
    let _ = fs::remove_dir(root);
}

#[test]
fn cli_score_features_jsonl_outputs_portable_predictions() {
    let root = unique_path("cli_score_features_jsonl_outputs_portable_predictions");
    fs::create_dir_all(&root).unwrap();
    let input_path = root.join("features.jsonl");
    let values = vec![0.0f32; 386];
    fs::write(
        &input_path,
        format!(
            "{{\"sample_id\":\"sample-1\",\"source_label\":0,\"feature_values\":{}}}\n",
            serde_json::to_string(&values).unwrap()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ProjectX"))
        .args(["--score-features-jsonl", input_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    let parsed = serde_json::from_str::<serde_json::Value>(line.trim()).unwrap();
    assert_eq!(parsed["sample_id"], "sample-1");
    assert_eq!(parsed["label"], "clean");
    assert!(parsed["score"].as_f64().unwrap() < 0.4);

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_dir(root);
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
