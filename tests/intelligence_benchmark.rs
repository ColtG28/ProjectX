use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/parser_fixtures.rs"]
mod parser_fixtures;

use parser_fixtures::{
    build_standard_elf_with_symbols, build_standard_macho, build_standard_pe_with_imports,
    unique_temp_path, ElfSymbolSpec, PeImportSpec,
};
use projectx::r#static::config::ScanConfig;
use projectx::r#static::run_pipeline;
use projectx::r#static::types::Severity;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct RegressionReport {
    benign_clean_rate: String,
    false_positive_rate: String,
    suspicious_escalation_rate: String,
    false_positive_rate_realworld: String,
    escalation_rate_realworld: String,
    stability_score: String,
    benign_fixture_count: usize,
    suspicious_fixture_count: usize,
    benign_category_counts: BTreeMap<String, usize>,
    benign_clean_by_category: BTreeMap<String, String>,
    suspicious_category_counts: BTreeMap<String, usize>,
    suspicious_escalated_by_category: BTreeMap<String, String>,
    pe_verdict: String,
    elf_verdict: String,
    macho_verdict: String,
    rule_quality: Vec<String>,
    rule_families: BTreeMap<String, usize>,
    trust_hit_count: usize,
    known_bad_hit_count: usize,
    trust_vendor_count: usize,
    trust_ecosystem_count: usize,
    trust_reputation_notes: Vec<String>,
    intelligence_status: Vec<String>,
}

fn category_name(path: &Path) -> String {
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn benign_fixture_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("benign")
        .join(category)
        .join(name)
}

fn suspicious_fixture_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("suspicious_safe")
        .join(category)
        .join(name)
}

fn run_fixture(path: &Path) -> (projectx::r#static::context::ScanContext, Severity) {
    run_pipeline(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap()
}

#[test]
fn benchmark_harness_tracks_benign_and_suspicious_rates() {
    let benign_paths = vec![
        benign_fixture_path("developer", "framework_chunk.js"),
        benign_fixture_path("developer", "minified_bundle.js"),
        benign_fixture_path("developer", "obfuscated_feature_flags.js"),
        benign_fixture_path("developer", "eval_config_loader.js"),
        benign_fixture_path("developer", "transpiled_runtime_chunk.js"),
        benign_fixture_path("admin", "deployment_helper.ps1"),
        benign_fixture_path("admin", "backup_cleanup.ps1"),
        benign_fixture_path("admin", "ci_release_sync.ps1"),
        benign_fixture_path("installers", "update_checker.ps1"),
        benign_fixture_path("installers", "environment_probe.ps1"),
        benign_fixture_path("installers", "package_restore.ps1"),
        benign_fixture_path("archives", "update_manifest.txt"),
        benign_fixture_path("archives", "mixed_bundle_inventory.txt"),
        benign_fixture_path("encoded", "config_blob.txt"),
        benign_fixture_path("encoded", "theme_asset_map.txt"),
        benign_fixture_path("office", "macro_notes.txt"),
        benign_fixture_path("office", "template_macro_outline.txt"),
    ];

    let suspicious_paths = vec![
        suspicious_fixture_path("scripts", "powershell_downloader_chain.ps1"),
        suspicious_fixture_path("scripts", "javascript_launcher_chain.js"),
        suspicious_fixture_path("scripts", "powershell_archive_extract_chain.ps1"),
        suspicious_fixture_path("scripts", "javascript_fetch_decode_stage.js"),
        suspicious_fixture_path("encoded", "decoded_follow_on_chain.txt"),
        suspicious_fixture_path("encoded", "archive_run_config.txt"),
        suspicious_fixture_path("office", "macro_download_chain.txt"),
        suspicious_fixture_path("office", "template_download_stage.txt"),
        suspicious_fixture_path("binary", "pe_injection_chain.txt"),
        suspicious_fixture_path("binary", "macho_loader_spawn_network.txt"),
    ];

    let mut benign_clean = 0usize;
    let mut suspicious_escalated = 0usize;
    let mut benign_category_counts = BTreeMap::new();
    let mut benign_clean_counts = BTreeMap::new();
    let mut suspicious_category_counts = BTreeMap::new();
    let mut suspicious_escalated_counts = BTreeMap::new();

    for path in &benign_paths {
        let category = category_name(path);
        *benign_category_counts.entry(category.clone()).or_insert(0) += 1;
        if matches!(run_fixture(path).1, Severity::Clean) {
            benign_clean += 1;
            *benign_clean_counts.entry(category).or_insert(0) += 1;
        }
    }
    for path in &suspicious_paths {
        let category = category_name(path);
        *suspicious_category_counts
            .entry(category.clone())
            .or_insert(0) += 1;
        if !matches!(run_fixture(path).1, Severity::Clean) {
            suspicious_escalated += 1;
            *suspicious_escalated_counts.entry(category).or_insert(0) += 1;
        }
    }
    let benign_fp = benign_paths.len().saturating_sub(benign_clean);
    let benign_clean_by_category = benign_category_counts
        .iter()
        .map(|(category, total)| {
            let clean = benign_clean_counts
                .get(category)
                .copied()
                .unwrap_or_default();
            (category.clone(), format!("{clean}/{total}"))
        })
        .collect::<BTreeMap<_, _>>();
    let suspicious_escalated_by_category = suspicious_category_counts
        .iter()
        .map(|(category, total)| {
            let escalated = suspicious_escalated_counts
                .get(category)
                .copied()
                .unwrap_or_default();
            (category.clone(), format!("{escalated}/{total}"))
        })
        .collect::<BTreeMap<_, _>>();

    let mut rule_quality = Vec::new();
    let mut rule_families = BTreeMap::new();
    let mut trust_reputation_notes = Vec::new();
    let mut trust_hit_count = 0;
    let mut known_bad_hit_count = 0;
    let mut trust_vendor_count = 0;
    let mut trust_ecosystem_count = 0;
    let mut intelligence_status = Vec::new();
    for path in &suspicious_paths {
        let (ctx, _) = run_fixture(path);
        for rule_hit in ctx
            .findings
            .iter()
            .filter(|finding| finding.code == "YARA_MATCH")
        {
            rule_quality.push(rule_hit.message.clone());
            if let Some(family) = rule_hit
                .message
                .split(" family ")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
            {
                *rule_families.entry(family.to_string()).or_insert(0) += 1;
            }
        }
        if let Some(intelligence) = &ctx.intelligence {
            trust_reputation_notes.extend(intelligence.policy_effects.clone());
            trust_hit_count += intelligence.trust_reasons.len();
            known_bad_hit_count += intelligence.reputation_hits.len();
            trust_vendor_count += intelligence.trust_vendors.len();
            trust_ecosystem_count += intelligence.trust_ecosystems.len();
            intelligence_status.push(intelligence.external_intelligence_status.clone());
        }
    }

    let report = RegressionReport {
        benign_clean_rate: format!("{}/{}", benign_clean, benign_paths.len()),
        false_positive_rate: format!("{}/{}", benign_fp, benign_paths.len()),
        suspicious_escalation_rate: format!("{}/{}", suspicious_escalated, suspicious_paths.len()),
        false_positive_rate_realworld: "reported by tests/staged_validation.rs stage_realworld"
            .to_string(),
        escalation_rate_realworld: "reported by tests/staged_validation.rs stage_realworld"
            .to_string(),
        stability_score: if benign_fp == 0 && suspicious_escalated == suspicious_paths.len() {
            "1.0".to_string()
        } else {
            "review".to_string()
        },
        benign_fixture_count: benign_paths.len(),
        suspicious_fixture_count: suspicious_paths.len(),
        benign_category_counts,
        benign_clean_by_category,
        suspicious_category_counts,
        suspicious_escalated_by_category,
        pe_verdict: "n/a".to_string(),
        elf_verdict: "n/a".to_string(),
        macho_verdict: "n/a".to_string(),
        rule_quality,
        rule_families,
        trust_hit_count,
        known_bad_hit_count,
        trust_vendor_count,
        trust_ecosystem_count,
        trust_reputation_notes,
        intelligence_status,
    };
    let json = serde_json::to_string_pretty(&report).unwrap();
    eprintln!("intelligence harness report:\n{json}");

    assert_eq!(benign_clean, benign_paths.len());
    assert_eq!(suspicious_escalated, suspicious_paths.len());
    assert!(json.contains("benign_clean_rate"));
    assert!(json.contains("false_positive_rate"));
    assert!(json.contains("false_positive_rate_realworld"));
    assert!(json.contains("stability_score"));
    assert!(json.contains("suspicious_escalation_rate"));
    assert!(json.contains("benign_clean_by_category"));
    assert!(json.contains("suspicious_escalated_by_category"));
    assert!(json.contains("rule_families"));
    assert!(json.contains("trust_hit_count"));
    assert!(json.contains("trust_vendor_count"));
}

#[test]
fn benchmark_harness_tracks_binary_behavior_per_format() {
    let pe_path = unique_temp_path("projectx_intel_benchmark", "exe");
    let elf_path = unique_temp_path("projectx_intel_benchmark", "elf");
    let macho_path = unique_temp_path("projectx_intel_benchmark", "dylib");

    fs::write(
        &pe_path,
        build_standard_pe_with_imports(
            &[PeImportSpec {
                dll: "kernel32.dll",
                functions: &["LoadLibraryA", "GetProcAddress"],
            }],
            b"release notes and packaging metadata",
        ),
    )
    .unwrap();
    fs::write(
        &elf_path,
        build_standard_elf_with_symbols(
            &[
                ElfSymbolSpec { name: "dlopen" },
                ElfSymbolSpec { name: "dlsym" },
            ],
            b"release metadata and startup notes",
        ),
    )
    .unwrap();
    fs::write(
        &macho_path,
        build_standard_macho(b"release metadata and startup notes"),
    )
    .unwrap();

    let pe = run_fixture(&pe_path).1;
    let elf = run_fixture(&elf_path).1;
    let macho = run_fixture(&macho_path).1;
    let report = RegressionReport {
        benign_clean_rate: "n/a".to_string(),
        false_positive_rate: "n/a".to_string(),
        suspicious_escalation_rate: "n/a".to_string(),
        false_positive_rate_realworld: "reported by tests/staged_validation.rs stage_realworld"
            .to_string(),
        escalation_rate_realworld: "reported by tests/staged_validation.rs stage_realworld"
            .to_string(),
        stability_score: "n/a".to_string(),
        benign_fixture_count: 0,
        suspicious_fixture_count: 0,
        benign_category_counts: BTreeMap::new(),
        benign_clean_by_category: BTreeMap::new(),
        suspicious_category_counts: BTreeMap::new(),
        suspicious_escalated_by_category: BTreeMap::new(),
        pe_verdict: format!("{pe:?}"),
        elf_verdict: format!("{elf:?}"),
        macho_verdict: format!("{macho:?}"),
        rule_quality: Vec::new(),
        rule_families: BTreeMap::new(),
        trust_hit_count: 0,
        known_bad_hit_count: 0,
        trust_vendor_count: 0,
        trust_ecosystem_count: 0,
        trust_reputation_notes: Vec::new(),
        intelligence_status: Vec::new(),
    };
    let json = serde_json::to_string_pretty(&report).unwrap();
    eprintln!("intelligence harness formats report:\n{json}");

    assert_eq!(pe, Severity::Clean);
    assert_eq!(elf, Severity::Clean);
    assert_eq!(macho, Severity::Clean);
    assert!(json.contains("\"pe_verdict\""));
    assert!(json.contains("\"elf_verdict\""));
    assert!(json.contains("\"macho_verdict\""));

    let _ = fs::remove_file(pe_path);
    let _ = fs::remove_file(elf_path);
    let _ = fs::remove_file(macho_path);
}
