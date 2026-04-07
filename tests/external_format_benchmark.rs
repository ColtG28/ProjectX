use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/parser_fixtures.rs"]
mod parser_fixtures;

use parser_fixtures::{
    build_standard_elf_with_symbols, build_standard_macho, build_standard_pe_with_imports,
    build_test_elf_with_symbol_tables, build_test_macho, build_test_macho_with_dylib_specs,
    build_test_pe_with_imports, unique_temp_path, ElfSymbolSpec, ElfSymbolTableSpec,
    MachoDylibSpec, MachoSegmentSpec, PeImportSpec, PeSectionSpec,
};
use projectx::r#static::config::ScanConfig;
use projectx::r#static::run_pipeline;
use projectx::r#static::types::Severity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_CAP_PER_FORMAT: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
enum Format {
    Pe,
    Elf,
    MachO,
}

impl Format {
    fn label(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
        }
    }

    fn manifest_env_vars(self) -> &'static [&'static str] {
        match self {
            Self::Pe => &[
                "PROJECTX_PE_BENCHMARK_MANIFEST",
                "PROJECTX_EMBER_PE_MANIFEST",
            ],
            Self::Elf => &["PROJECTX_ELF_BENCHMARK_MANIFEST"],
            Self::MachO => &["PROJECTX_MACHO_BENCHMARK_MANIFEST"],
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ExpectedDisposition {
    Benign,
    SuspiciousSafe,
}

#[derive(Debug, Deserialize)]
struct ManifestEntry {
    path: PathBuf,
    #[serde(default)]
    label: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    provenance: Option<String>,
}

#[derive(Debug)]
struct PreparedExternalCase {
    path: PathBuf,
    label: ExpectedDisposition,
    source: String,
    category: String,
}

struct ControlledCase {
    name: &'static str,
    format: Format,
    label: ExpectedDisposition,
    bytes: Vec<u8>,
}

#[derive(Debug, Default, Serialize)]
struct FormatBenchmarkMetrics {
    format: String,
    target_cap: usize,
    manifest_path: Option<String>,
    acquisition_status: String,
    manifest_entries_seen: usize,
    acquired_count: usize,
    prepared_count: usize,
    tested_count: usize,
    skipped_missing_count: usize,
    skipped_duplicate_count: usize,
    skipped_unlabeled_count: usize,
    benign_count: usize,
    benign_clean_count: usize,
    false_positive_count: usize,
    false_positive_rate: String,
    suspicious_count: usize,
    suspicious_escalated_count: usize,
    suspicious_escalation_rate: String,
    category_counts: BTreeMap<String, usize>,
    source_counts: BTreeMap<String, usize>,
    rule_family_hits: BTreeMap<String, usize>,
    trust_hit_count: usize,
    trust_vendor_count: usize,
    trust_ecosystem_count: usize,
    controlled_sample_count: usize,
    controlled_benign_clean_rate: String,
    controlled_suspicious_escalation_rate: String,
    controlled_false_positive_rate: String,
    scope_notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CrossFormatBenchmarkReport {
    benchmark: String,
    cap_per_format: usize,
    pe: FormatBenchmarkMetrics,
    elf: FormatBenchmarkMetrics,
    macho: FormatBenchmarkMetrics,
    combined_external_tested_count: usize,
    combined_controlled_tested_count: usize,
    overall_scope_notes: Vec<String>,
}

fn run_fixture(path: &Path) -> (projectx::r#static::context::ScanContext, Severity) {
    run_pipeline(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap()
}

fn rate(ok: usize, total: usize) -> String {
    format!("{ok}/{total}")
}

fn suspicious_fixture_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("suspicious_safe")
        .join(category)
        .join(name)
}

fn manifest_for(format: Format) -> Option<PathBuf> {
    format
        .manifest_env_vars()
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        .map(PathBuf::from)
}

fn cap_per_format() -> usize {
    env::var("PROJECTX_EXTERNAL_BENCHMARK_CAP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CAP_PER_FORMAT)
}

fn disposition(label: &str) -> Option<ExpectedDisposition> {
    match label.to_ascii_lowercase().as_str() {
        "benign" | "clean" | "0" => Some(ExpectedDisposition::Benign),
        "suspicious" | "malicious" | "suspicious_safe" | "1" => {
            Some(ExpectedDisposition::SuspiciousSafe)
        }
        _ => None,
    }
}

fn prepare_external_cases(
    format: Format,
    manifest: Option<&Path>,
    cap: usize,
    metrics: &mut FormatBenchmarkMetrics,
) -> Vec<PreparedExternalCase> {
    let Some(manifest) = manifest else {
        metrics.acquisition_status = format!(
            "not run: no {} manifest environment variable was set",
            format.label()
        );
        return Vec::new();
    };

    metrics.manifest_path = Some(manifest.display().to_string());
    let Ok(text) = fs::read_to_string(manifest) else {
        metrics.acquisition_status = format!("manifest {} could not be read", manifest.display());
        return Vec::new();
    };

    let mut cases = Vec::new();
    let mut seen_hashes = BTreeSet::new();

    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        metrics.manifest_entries_seen += 1;
        if cases.len() >= cap {
            break;
        }
        let Ok(entry) = serde_json::from_str::<ManifestEntry>(line) else {
            metrics.skipped_unlabeled_count += 1;
            continue;
        };
        let Some(label) = disposition(&entry.label) else {
            metrics.skipped_unlabeled_count += 1;
            continue;
        };
        if !entry.path.exists() {
            metrics.skipped_missing_count += 1;
            continue;
        }
        let Ok(bytes) = fs::read(&entry.path) else {
            metrics.skipped_missing_count += 1;
            continue;
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = format!("{:x}", hasher.finalize());
        if !seen_hashes.insert(digest) {
            metrics.skipped_duplicate_count += 1;
            continue;
        }
        cases.push(PreparedExternalCase {
            path: entry.path,
            label,
            source: entry
                .source
                .or(entry.platform)
                .unwrap_or_else(|| "external_manifest".to_string()),
            category: entry
                .category
                .or(entry.provenance)
                .unwrap_or_else(|| "uncategorized".to_string()),
        });
    }

    metrics.acquired_count = cases.len();
    metrics.prepared_count = cases.len();
    metrics.acquisition_status = format!(
        "prepared {} deduplicated {} sample(s) from {}",
        cases.len(),
        format.label(),
        manifest.display()
    );
    cases
}

fn add_context_metrics(
    ctx: &projectx::r#static::context::ScanContext,
    metrics: &mut FormatBenchmarkMetrics,
) {
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
            *metrics
                .rule_family_hits
                .entry(family.to_string())
                .or_insert(0) += 1;
        }
    }

    if let Some(intelligence) = &ctx.intelligence {
        metrics.trust_hit_count += intelligence.trust_reasons.len();
        metrics.trust_vendor_count += intelligence.trust_vendors.len();
        metrics.trust_ecosystem_count += intelligence.trust_ecosystems.len();
    }
}

fn evaluate_external(
    format: Format,
    manifest: Option<&Path>,
    cap: usize,
) -> FormatBenchmarkMetrics {
    let mut metrics = FormatBenchmarkMetrics {
        format: format.label().to_string(),
        target_cap: cap,
        scope_notes: vec![
            "External benchmark input is manifest-driven and uses only local files listed by the operator.".to_string(),
            "No live malware repositories are downloaded or required by this harness.".to_string(),
        ],
        ..FormatBenchmarkMetrics::default()
    };
    let cases = prepare_external_cases(format, manifest, cap, &mut metrics);

    for case in &cases {
        *metrics
            .category_counts
            .entry(case.category.clone())
            .or_insert(0) += 1;
        *metrics
            .source_counts
            .entry(case.source.clone())
            .or_insert(0) += 1;
        let (ctx, severity) = run_fixture(&case.path);
        metrics.tested_count += 1;
        add_context_metrics(&ctx, &mut metrics);

        match case.label {
            ExpectedDisposition::Benign => {
                metrics.benign_count += 1;
                if matches!(severity, Severity::Clean) {
                    metrics.benign_clean_count += 1;
                }
            }
            ExpectedDisposition::SuspiciousSafe => {
                metrics.suspicious_count += 1;
                if !matches!(severity, Severity::Clean) {
                    metrics.suspicious_escalated_count += 1;
                }
            }
        }
    }

    metrics.false_positive_count = metrics
        .benign_count
        .saturating_sub(metrics.benign_clean_count);
    metrics.false_positive_rate = rate(metrics.false_positive_count, metrics.benign_count);
    metrics.suspicious_escalation_rate =
        rate(metrics.suspicious_escalated_count, metrics.suspicious_count);
    metrics
}

fn controlled_cases(format: Format) -> Vec<ControlledCase> {
    match format {
        Format::Pe => controlled_pe_cases(),
        Format::Elf => controlled_elf_cases(),
        Format::MachO => controlled_macho_cases(),
    }
}

fn controlled_pe_cases() -> Vec<ControlledCase> {
    let pe_injection_payload =
        fs::read(suspicious_fixture_path("binary", "pe_injection_chain.txt")).unwrap();
    vec![
        ControlledCase {
            name: "pe_benign_imports",
            format: Format::Pe,
            label: ExpectedDisposition::Benign,
            bytes: build_standard_pe_with_imports(
                &[PeImportSpec {
                    dll: "kernel32.dll",
                    functions: &["LoadLibraryA", "GetProcAddress"],
                }],
                b"VersionInfo support notes and signed package metadata",
            ),
        },
        ControlledCase {
            name: "pe_suspicious_injection",
            format: Format::Pe,
            label: ExpectedDisposition::SuspiciousSafe,
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
                ],
                &[PeImportSpec {
                    dll: "kernel32.dll",
                    functions: &["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"],
                }],
                &pe_injection_payload,
            ),
        },
    ]
}

fn controlled_elf_cases() -> Vec<ControlledCase> {
    vec![
        ControlledCase {
            name: "elf_benign_dynamic_symbols",
            format: Format::Elf,
            label: ExpectedDisposition::Benign,
            bytes: build_standard_elf_with_symbols(
                &[
                    ElfSymbolSpec { name: "dlopen" },
                    ElfSymbolSpec { name: "dlsym" },
                ],
                b"release metadata and distro package notes",
            ),
        },
        ControlledCase {
            name: "elf_suspicious_static_exec_network",
            format: Format::Elf,
            label: ExpectedDisposition::SuspiciousSafe,
            bytes: build_test_elf_with_symbol_tables(
                &[".text", ".strtab", ".symtab", ".interp", ".shstrtab"],
                Some("/lib64/ld-linux-x86-64.so.2"),
                ElfSymbolTableSpec {
                    dyn_symbols: &[],
                    static_symbols: &[
                        ElfSymbolSpec { name: "execve" },
                        ElfSymbolSpec { name: "system" },
                        ElfSymbolSpec { name: "socket" },
                        ElfSymbolSpec { name: "connect" },
                    ],
                },
                b"/bin/sh connect placeholder runtime notes",
            ),
        },
    ]
}

fn controlled_macho_cases() -> Vec<ControlledCase> {
    vec![
        ControlledCase {
            name: "macho_benign_app_bundle",
            format: Format::MachO,
            label: ExpectedDisposition::Benign,
            bytes: build_standard_macho(b"harmless app bundle metadata and release notes"),
        },
        ControlledCase {
            name: "macho_suspicious_loader_network",
            format: Format::MachO,
            label: ExpectedDisposition::SuspiciousSafe,
            bytes: build_test_macho(
                &[
                    MachoSegmentSpec {
                        name: "__TEXT",
                        maxprot: 5,
                        initprot: 5,
                        sections: &["__text"],
                    },
                    MachoSegmentSpec {
                        name: "__DATA",
                        maxprot: 7,
                        initprot: 7,
                        sections: &["__packed"],
                    },
                ],
                &[
                    "/usr/lib/libSystem.B.dylib",
                    "/usr/lib/libdyld.dylib",
                    "/System/Library/Frameworks/Foundation.framework/Foundation",
                ],
                b"dlopen dlsym vm_protect posix_spawn NSURLSession local placeholder",
            ),
        },
        ControlledCase {
            name: "macho_relative_loader_path",
            format: Format::MachO,
            label: ExpectedDisposition::SuspiciousSafe,
            bytes: build_test_macho_with_dylib_specs(
                &[MachoSegmentSpec {
                    name: "__TEXT",
                    maxprot: 5,
                    initprot: 5,
                    sections: &["__text"],
                }],
                &[
                    MachoDylibSpec {
                        path: "@loader_path/Frameworks/Helper.framework/Helper",
                        command: 0x8000_0018,
                    },
                    MachoDylibSpec {
                        path: "/usr/lib/libSystem.B.dylib",
                        command: 0x0000_000c,
                    },
                ],
                b"dlopen dlsym vm_protect placeholder notes",
            ),
        },
    ]
}

fn evaluate_controlled(format: Format, metrics: &mut FormatBenchmarkMetrics) {
    let cases = controlled_cases(format);
    let mut benign_total = 0usize;
    let mut benign_clean = 0usize;
    let mut suspicious_total = 0usize;
    let mut suspicious_escalated = 0usize;

    for case in &cases {
        let path = unique_temp_path(
            &format!("projectx_controlled_{}", case.name),
            extension(case.format),
        );
        fs::write(&path, &case.bytes).unwrap();
        let (ctx, severity) = run_fixture(&path);
        let _ = fs::remove_file(path);
        metrics.controlled_sample_count += 1;
        add_context_metrics(&ctx, metrics);

        match case.label {
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
    }

    metrics.controlled_benign_clean_rate = rate(benign_clean, benign_total);
    metrics.controlled_suspicious_escalation_rate = rate(suspicious_escalated, suspicious_total);
    metrics.controlled_false_positive_rate =
        rate(benign_total.saturating_sub(benign_clean), benign_total);
}

fn extension(format: Format) -> &'static str {
    match format {
        Format::Pe => "exe",
        Format::Elf => "elf",
        Format::MachO => "dylib",
    }
}

fn evaluate_format(format: Format, cap: usize) -> FormatBenchmarkMetrics {
    let manifest = manifest_for(format);
    let mut metrics = evaluate_external(format, manifest.as_deref(), cap);
    evaluate_controlled(format, &mut metrics);
    metrics
}

fn write_report(report: &CrossFormatBenchmarkReport) {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("quarantine")
        .join("validation_reports")
        .join("external_format_benchmark_summary.json");
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    fs::write(&output, serde_json::to_string_pretty(report).unwrap()).unwrap();
    eprintln!(
        "external format benchmark summary:\n{}",
        serde_json::to_string_pretty(report).unwrap()
    );
}

#[test]
fn external_format_benchmark_summary_is_generated() {
    let cap = cap_per_format();
    let pe = evaluate_format(Format::Pe, cap);
    let elf = evaluate_format(Format::Elf, cap);
    let macho = evaluate_format(Format::MachO, cap);
    let combined_external_tested_count = pe.tested_count + elf.tested_count + macho.tested_count;
    let combined_controlled_tested_count =
        pe.controlled_sample_count + elf.controlled_sample_count + macho.controlled_sample_count;

    let report = CrossFormatBenchmarkReport {
        benchmark: "external_format_benchmark_summary".to_string(),
        cap_per_format: cap,
        pe,
        elf,
        macho,
        combined_external_tested_count,
        combined_controlled_tested_count,
        overall_scope_notes: vec![
            "External acquisition is manifest-based so operators can supply safe local PE, ELF, and Mach-O corpora without the test harness downloading from live malware or opaque sources.".to_string(),
            "When manifests are absent, only controlled safe baselines are run and external counts remain zero by design.".to_string(),
            "Set PROJECTX_PE_BENCHMARK_MANIFEST or PROJECTX_EMBER_PE_MANIFEST, PROJECTX_ELF_BENCHMARK_MANIFEST, and PROJECTX_MACHO_BENCHMARK_MANIFEST to JSONL manifests to evaluate larger corpora.".to_string(),
        ],
    };

    assert_eq!(report.pe.controlled_benign_clean_rate, "1/1");
    assert_eq!(report.elf.controlled_benign_clean_rate, "1/1");
    assert_eq!(report.macho.controlled_benign_clean_rate, "1/1");
    assert_eq!(report.combined_controlled_tested_count, 7);
    write_report(&report);
}
