use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/parser_fixtures.rs"]
mod parser_fixtures;

use parser_fixtures::{
    build_standard_pe_with_imports, build_test_pe, build_test_pe_with_imports,
    build_test_pe_with_imports_and_entrypoint, unique_temp_path, PeImportSpec, PeSectionSpec,
};
use projectx::r#static::config::ScanConfig;
use projectx::r#static::run_pipeline;
use projectx::r#static::types::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct EmberManifestEntry {
    path: PathBuf,
    #[serde(default)]
    label: String,
    #[serde(default)]
    #[serde(rename = "source")]
    _source: Option<String>,
}

#[derive(Debug, Serialize)]
struct EmberPeBenchmarkReport {
    benchmark: String,
    external_dataset_status: String,
    manifest_path: Option<String>,
    external_sample_count: usize,
    external_benign_count: usize,
    external_suspicious_count: usize,
    external_benign_clean_rate: String,
    external_suspicious_escalation_rate: String,
    external_false_positive_rate: String,
    controlled_pe_sample_count: usize,
    controlled_pe_benign_clean_rate: String,
    controlled_pe_suspicious_escalation_rate: String,
    controlled_pe_false_positive_rate: String,
    controlled_rule_family_hits: BTreeMap<String, usize>,
    pe_scope_notes: Vec<String>,
}

#[derive(Clone)]
struct ControlledPeCase {
    name: &'static str,
    expected: ExpectedDisposition,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum ExpectedDisposition {
    Benign,
    SuspiciousSafe,
}

fn run_fixture(path: &Path) -> (projectx::r#static::context::ScanContext, Severity) {
    run_pipeline(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap()
}

fn suspicious_fixture_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("suspicious_safe")
        .join(category)
        .join(name)
}

fn write_report(report: &EmberPeBenchmarkReport) {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("quarantine")
        .join("validation_reports")
        .join("ember_pe_benchmark.json");
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    fs::write(&output, serde_json::to_string_pretty(report).unwrap()).unwrap();
    eprintln!(
        "EMBER PE benchmark report:\n{}",
        serde_json::to_string_pretty(report).unwrap()
    );
}

fn rate(ok: usize, total: usize) -> String {
    format!("{ok}/{total}")
}

fn controlled_pe_cases() -> Vec<ControlledPeCase> {
    let pe_injection_payload =
        fs::read(suspicious_fixture_path("binary", "pe_injection_chain.txt")).unwrap();
    let pe_resource_payload =
        fs::read(suspicious_fixture_path("binary", "pe_resource_stage.txt")).unwrap();

    vec![
        ControlledPeCase {
            name: "benign_standard_imports",
            expected: ExpectedDisposition::Benign,
            bytes: build_standard_pe_with_imports(
                &[PeImportSpec {
                    dll: "kernel32.dll",
                    functions: &["LoadLibraryA", "GetProcAddress"],
                }],
                b"VersionInfo support notes and signed package metadata",
            ),
        },
        ControlledPeCase {
            name: "benign_sparse_weak_layout",
            expected: ExpectedDisposition::Benign,
            bytes: build_test_pe(
                &[PeSectionSpec {
                    name: ".text",
                    virtual_size: 0x4000,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                }],
                b"VersionInfo installer notes and release metadata",
            ),
        },
        ControlledPeCase {
            name: "suspicious_injection_import_chain",
            expected: ExpectedDisposition::SuspiciousSafe,
            bytes: build_test_pe_with_imports(
                &[
                    PeSectionSpec {
                        name: ".text",
                        virtual_size: 0x800,
                        raw_size: 0x400,
                        characteristics: 0x6000_0020,
                    },
                    PeSectionSpec {
                        name: ".idata",
                        virtual_size: 0x800,
                        raw_size: 0x400,
                        characteristics: 0xC000_0040,
                    },
                    PeSectionSpec {
                        name: ".rdata",
                        virtual_size: 0x600,
                        raw_size: 0x200,
                        characteristics: 0x4000_0040,
                    },
                    PeSectionSpec {
                        name: ".rsrc",
                        virtual_size: 0x400,
                        raw_size: 0x200,
                        characteristics: 0x4000_0040,
                    },
                ],
                &[PeImportSpec {
                    dll: "kernel32.dll",
                    functions: &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
                }],
                &pe_injection_payload,
            ),
        },
        ControlledPeCase {
            name: "suspicious_packed_entrypoint_chain",
            expected: ExpectedDisposition::SuspiciousSafe,
            bytes: build_test_pe_with_imports_and_entrypoint(
                &[
                    PeSectionSpec {
                        name: "UPX0",
                        virtual_size: 0x1800,
                        raw_size: 0x200,
                        characteristics: 0xE000_0020,
                    },
                    PeSectionSpec {
                        name: ".idata",
                        virtual_size: 0x800,
                        raw_size: 0x400,
                        characteristics: 0xC000_0040,
                    },
                    PeSectionSpec {
                        name: ".rsrc",
                        virtual_size: 0x700,
                        raw_size: 0x200,
                        characteristics: 0x4000_0040,
                    },
                ],
                &[PeImportSpec {
                    dll: "kernel32.dll",
                    functions: &["VirtualAlloc", "WriteProcessMemory", "QueueUserAPC"],
                }],
                &pe_resource_payload,
                Some("UPX0"),
            ),
        },
    ]
}

fn evaluate_controlled_pe() -> (usize, usize, usize, usize, usize, BTreeMap<String, usize>) {
    let cases = controlled_pe_cases();
    let mut benign_total = 0usize;
    let mut benign_clean = 0usize;
    let mut suspicious_total = 0usize;
    let mut suspicious_escalated = 0usize;
    let mut rule_families = BTreeMap::new();

    for case in &cases {
        let path = unique_temp_path(&format!("projectx_ember_pe_{}", case.name), "exe");
        fs::write(&path, &case.bytes).unwrap();
        let (ctx, severity) = run_fixture(&path);
        let _ = fs::remove_file(path);

        match case.expected {
            ExpectedDisposition::Benign => {
                benign_total += 1;
                if matches!(severity, Severity::Clean) {
                    benign_clean += 1;
                }
            }
            ExpectedDisposition::SuspiciousSafe => {
                suspicious_total += 1;
                if !matches!(severity, Severity::Clean) {
                    suspicious_escalated += 1;
                }
            }
        }

        for finding in ctx
            .findings
            .iter()
            .filter(|finding| finding.code == "YARA_MATCH")
        {
            if let Some(family) = finding
                .message
                .split(" family ")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
            {
                *rule_families.entry(family.to_string()).or_insert(0) += 1;
            }
        }
    }

    (
        benign_total + suspicious_total,
        benign_total,
        benign_clean,
        suspicious_total,
        suspicious_escalated,
        rule_families,
    )
}

fn evaluate_external_manifest(
    path: &Path,
) -> Option<(usize, usize, usize, usize, usize, BTreeMap<String, usize>)> {
    let text = fs::read_to_string(path).ok()?;
    let mut total = 0usize;
    let mut benign_total = 0usize;
    let mut benign_clean = 0usize;
    let mut suspicious_total = 0usize;
    let mut suspicious_escalated = 0usize;
    let mut rule_families = BTreeMap::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(entry) = serde_json::from_str::<EmberManifestEntry>(line) else {
            continue;
        };
        if !entry.path.exists() {
            continue;
        }

        let (ctx, severity) = run_fixture(&entry.path);
        let label = entry.label.to_ascii_lowercase();
        total += 1;

        if matches!(label.as_str(), "benign" | "0" | "clean") {
            benign_total += 1;
            if matches!(severity, Severity::Clean) {
                benign_clean += 1;
            }
        } else if matches!(
            label.as_str(),
            "malicious" | "suspicious" | "1" | "suspicious_safe"
        ) {
            suspicious_total += 1;
            if !matches!(severity, Severity::Clean) {
                suspicious_escalated += 1;
            }
        }

        for finding in ctx
            .findings
            .iter()
            .filter(|finding| finding.code == "YARA_MATCH")
        {
            if let Some(family) = finding
                .message
                .split(" family ")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
            {
                *rule_families.entry(family.to_string()).or_insert(0) += 1;
            }
        }
    }

    Some((
        total,
        benign_total,
        benign_clean,
        suspicious_total,
        suspicious_escalated,
        rule_families,
    ))
}

#[test]
fn ember_pe_evaluation_report_is_generated() {
    let manifest = env::var("PROJECTX_EMBER_PE_MANIFEST")
        .ok()
        .map(PathBuf::from);
    let external = manifest
        .as_ref()
        .and_then(|path| evaluate_external_manifest(path));
    let (
        controlled_total,
        controlled_benign,
        controlled_benign_clean,
        controlled_suspicious,
        controlled_suspicious_escalated,
        controlled_rule_families,
    ) = evaluate_controlled_pe();

    let external_dataset_status = match (&manifest, &external) {
        (Some(path), Some((total, ..))) if *total > 0 => {
            format!("evaluated PE manifest {}", path.display())
        }
        (Some(path), _) => format!(
            "manifest {} was provided but no readable labeled PE samples were evaluated",
            path.display()
        ),
        (None, _) => "not run: PROJECTX_EMBER_PE_MANIFEST was not set; standard EMBER feature releases do not include raw PE bytes for this passive file scanner to scan directly"
            .to_string(),
    };

    let (
        external_total,
        external_benign,
        external_benign_clean,
        external_suspicious,
        external_suspicious_escalated,
        _,
    ) = external.unwrap_or_default();

    let report = EmberPeBenchmarkReport {
        benchmark: "ember_pe_evaluation".to_string(),
        external_dataset_status,
        manifest_path: manifest.map(|path| path.display().to_string()),
        external_sample_count: external_total,
        external_benign_count: external_benign,
        external_suspicious_count: external_suspicious,
        external_benign_clean_rate: rate(external_benign_clean, external_benign),
        external_suspicious_escalation_rate: rate(external_suspicious_escalated, external_suspicious),
        external_false_positive_rate: rate(external_benign.saturating_sub(external_benign_clean), external_benign),
        controlled_pe_sample_count: controlled_total,
        controlled_pe_benign_clean_rate: rate(controlled_benign_clean, controlled_benign),
        controlled_pe_suspicious_escalation_rate: rate(controlled_suspicious_escalated, controlled_suspicious),
        controlled_pe_false_positive_rate: rate(controlled_benign.saturating_sub(controlled_benign_clean), controlled_benign),
        controlled_rule_family_hits: controlled_rule_families,
        pe_scope_notes: vec![
            "This report is PE-focused and does not validate ELF, Mach-O, GUI workflow, or real-time protection by itself.".to_string(),
            "When PROJECTX_EMBER_PE_MANIFEST is unset, the report is an adapter/smoke baseline rather than an external EMBER result.".to_string(),
            "EMBER feature datasets are not equivalent to scanning raw PE files; this harness expects a JSONL manifest of raw PE paths plus labels when external evaluation data is available.".to_string(),
        ],
    };

    assert_eq!(report.controlled_pe_benign_clean_rate, "2/2");
    assert_eq!(report.controlled_pe_suspicious_escalation_rate, "2/2");
    write_report(&report);
}
