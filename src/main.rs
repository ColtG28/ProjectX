use std::path::PathBuf;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();

    #[cfg(feature = "gui")]
    if !args.iter().any(|arg| arg == "--cli") {
        if let Err(error) = projectx::gui::gui() {
            eprintln!("Failed to launch GUI: {}", error);
        }
        return;
    }

    #[cfg(not(feature = "gui"))]
    if args.iter().any(|arg| arg == "--gui") {
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
        if pretty_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
        } else if json_output {
            println!("{}", serde_json::to_string(&value).unwrap_or_default());
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            );
        }
        return;
    }

    if inputs.is_empty() {
        print_usage();
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

    if pretty {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    } else {
        println!("{}", serde_json::to_string(&value).unwrap_or_default());
    }
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

fn print_usage() {
    println!(
        "\
ProjectX scanner

Usage:
  cargo run -- --cli [options] <file-or-folder> [more paths...]

Options:
  --json               Emit JSON reports
  --pretty-json        Emit pretty JSON reports
  --workers <n>        Scan multiple files in parallel
  --max-files <n>      Limit recursive folder expansion
  --refresh-rules      Hot-reload and version the local YARA rule bundle
  --sandbox-plan       Print the sandbox execution plan for the first input
  --detonate           Attempt opt-in dynamic detonation in the sandbox stage
  --sandbox-timeout-ms Override dynamic sandbox timeout
  --allow-network      Reserved for future sandbox networking support
  --help               Show this help
"
    );
}
