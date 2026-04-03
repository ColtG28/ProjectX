use std::path::PathBuf;

fn main() {
    // Keep startup lean: parse flags once, then jump directly into GUI, native ML, or legacy scan mode.
    let args = std::env::args().collect::<Vec<_>>();
    let cli_mode = args.iter().skip(1).any(|arg| arg == "--cli");

    #[cfg(feature = "gui")]
    if !cli_mode && !args.iter().skip(1).any(|arg| arg != "--gui") {
        if let Err(error) = projectx::gui::gui() {
            eprintln!("Failed to launch GUI: {}", error);
        }
        return;
    }

    #[cfg(not(feature = "gui"))]
    if args.iter().skip(1).any(|arg| arg == "--gui") {
        eprintln!(
            "GUI support is disabled in this build. Rebuild with: cargo run --features gui -- --gui"
        );
        return;
    }

    let mut inputs = Vec::<PathBuf>::new();
    let mut json_output = false;
    let mut pretty_json = false;
    let mut refresh_rules = false;
    let mut sandbox_plan = false;
    let mut detonate = false;
    let mut allow_network = false;
    let mut workers = None;
    let mut max_files = 50_000usize;
    let mut sandbox_timeout_ms = None;
    let mut native_ml = false;
    let mut model_path = None;
    let mut output_path = None;
    let mut batch_size = 256usize;
    let mut concurrency = None;
    let mut evaluation_manifest = None;
    let mut max_input_bytes = None;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--cli" => {}
            "--json" => json_output = true,
            "--pretty-json" => {
                json_output = true;
                pretty_json = true;
            }
            "--refresh-rules" => refresh_rules = true,
            "--sandbox-plan" => sandbox_plan = true,
            "--detonate" => detonate = true,
            "--allow-network" => allow_network = true,
            "--native-ml" => native_ml = true,
            "--model" => {
                index += 1;
                model_path = args.get(index).map(PathBuf::from);
            }
            "--output" => {
                index += 1;
                output_path = args.get(index).map(PathBuf::from);
            }
            "--batch-size" => {
                index += 1;
                batch_size = args
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(batch_size)
                    .max(1);
            }
            "--concurrency" => {
                index += 1;
                concurrency = args
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok())
                    .map(|value| value.max(1));
            }
            "--eval-manifest" => {
                index += 1;
                evaluation_manifest = args.get(index).map(PathBuf::from);
            }
            "--max-input-bytes" => {
                index += 1;
                max_input_bytes = args
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok());
            }
            "--workers" => {
                index += 1;
                workers = args
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok());
            }
            "--sandbox-timeout-ms" => {
                index += 1;
                sandbox_timeout_ms = args.get(index).and_then(|value| value.parse::<u64>().ok());
            }
            "--max-files" => {
                index += 1;
                max_files = args
                    .get(index)
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(max_files);
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            value if value.starts_with('-') => {
                eprintln!("Unknown option: {}", value);
                print_usage();
                return;
            }
            value => inputs.push(PathBuf::from(value)),
        }
        index += 1;
    }

    dotenvy::dotenv().ok();
    if let Err(error) = projectx::r#static::init_quarantine() {
        eprintln!("Quarantine initialization failed: {}", error);
        return;
    }

    if refresh_rules {
        let version = projectx::r#static::refresh_rules();
        eprintln!("Refreshed rule bundle version {}", version);
    }

    if sandbox_plan {
        let Some(path) = inputs.first() else {
            eprintln!("Provide a file path for --sandbox-plan.");
            return;
        };
        let plan = projectx::sandbox::plan_for_path(path);
        let value = serde_json::to_value(plan).unwrap_or_else(|_| serde_json::json!({}));
        print_json_value(&value, pretty_json || !json_output);
        return;
    }

    if inputs.is_empty() {
        print_usage();
        return;
    }

    let use_legacy_cli_scan = cli_mode && !native_ml && model_path.is_none();
    if !use_legacy_cli_scan {
        let output_prefix =
            output_path.unwrap_or_else(|| PathBuf::from("quarantine/native_ml_scan"));
        let resolved_concurrency = concurrency.or(workers).unwrap_or_else(default_concurrency);
        match projectx::ml::native_scanner::run(projectx::ml::native_scanner::NativeScanConfig {
            model_path,
            inputs,
            output_prefix,
            batch_size,
            concurrency: resolved_concurrency,
            max_files,
            max_input_bytes,
            evaluation_manifest,
        }) {
            Ok(output) => {
                if pretty_json || json_output {
                    let value = serde_json::to_value(&output.summary).unwrap_or_else(
                        |_| serde_json::json!({ "error": "failed_to_serialize_summary" }),
                    );
                    print_json_value(&value, pretty_json);
                } else {
                    println!(
                        "Native ML scan complete | processed={} | malicious={} | suspicious={} | clean={} | errors={} | throughput={:.2} files/sec",
                        output.summary.processed_files,
                        output.summary.malicious_files,
                        output.summary.suspicious_files,
                        output.summary.clean_files,
                        output.summary.error_files,
                        output.summary.files_per_second
                    );
                    println!("CSV results: {}", output.csv_path.display());
                    println!("JSONL results: {}", output.jsonl_path.display());
                    println!("Summary: {}", output.summary_path.display());
                }
            }
            Err(error) => {
                eprintln!("Native ML scan failed: {}", error);
            }
        }
        return;
    }

    let mut config = projectx::r#static::config::ScanConfig::default();
    config.features.enable_dynamic_sandbox = detonate;
    if let Some(timeout_ms) = sandbox_timeout_ms {
        config.limits.sandbox_timeout_ms = timeout_ms.max(250);
    }
    if allow_network {
        std::env::set_var("PROJECTX_SANDBOX_NETWORK", "1");
    }

    let results =
        projectx::r#static::scan_inputs_parallel(&inputs, Some(config), workers, max_files);
    if json_output {
        print_json_results(&results, pretty_json);
    } else {
        print_text_results(&results);
    }
}

fn print_json_results(results: &[projectx::r#static::BatchScanResult], pretty: bool) {
    let value = if results.len() == 1 {
        match &results[0].outcome {
            Ok(outcome) => serde_json::from_str::<serde_json::Value>(&outcome.json_report)
                .unwrap_or_else(|_| serde_json::json!({ "path": results[0].path, "error": "invalid_json_report" })),
            Err(error) => serde_json::json!({
                "path": results[0].path,
                "status": "error",
                "error": error,
            }),
        }
    } else {
        serde_json::Value::Array(
            results
                .iter()
                .map(|result| match &result.outcome {
                    Ok(outcome) => serde_json::from_str::<serde_json::Value>(&outcome.json_report)
                        .unwrap_or_else(|_| {
                            serde_json::json!({
                                "path": result.path,
                                "status": "error",
                                "error": "invalid_json_report",
                            })
                        }),
                    Err(error) => serde_json::json!({
                        "path": result.path,
                        "status": "error",
                        "error": error,
                    }),
                })
                .collect(),
        )
    };

    print_json_value(&value, pretty);
}

fn print_text_results(results: &[projectx::r#static::BatchScanResult]) {
    for result in results {
        match &result.outcome {
            Ok(outcome) => {
                println!(
                    "{} | severity={:?} | cache_hit={} | rules={} | report={}",
                    result.path.display(),
                    outcome.severity,
                    outcome.cache_hit,
                    outcome.rules_version,
                    outcome.report_path.display()
                );
                println!("{}", outcome.summary);
                if !outcome.is_safe() {
                    println!("Quarantine path: {}", outcome.quarantine_path.display());
                }
                if !outcome.findings.is_empty() {
                    println!(
                        "Top findings: {}",
                        outcome
                            .findings
                            .iter()
                            .take(5)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | ")
                    );
                }
            }
            Err(error) => {
                eprintln!("{} | error={}", result.path.display(), error);
            }
        }
    }
}

fn print_json_value(value: &serde_json::Value, pretty: bool) {
    if pretty {
        println!("{}", serde_json::to_string_pretty(value).unwrap_or_default());
    } else {
        println!("{}", serde_json::to_string(value).unwrap_or_default());
    }
}

fn print_usage() {
    println!(
        "\
ProjectX

Usage:
  cargo run
  cargo run -- <file-or-folder> [more paths...]
  cargo run -- [options] <path> [more paths...]

Options:
  --json | --pretty-json
  --workers <n> | --max-files <n>
  --native-ml | --model <path> | --output <prefix>
  --batch-size <n> | --concurrency <n> | --eval-manifest <path>
  --max-input-bytes <n>
  --refresh-rules | --sandbox-plan | --help

Notes:
  cargo run                launches the GUI when available
  cargo run -- <path>      runs the embedded native ML scanner
"
    );
}

fn default_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .max(1)
}
