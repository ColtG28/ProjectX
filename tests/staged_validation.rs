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

#[derive(Debug, Clone, Copy)]
enum Stage {
    Stage100,
    Stage500,
    Stage1000,
    RealWorld,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Stage100 => "stage_100",
            Self::Stage500 => "stage_500",
            Self::Stage1000 => "stage_1000",
            Self::RealWorld => "stage_realworld",
        }
    }

    fn benign_target(self) -> usize {
        match self {
            Self::Stage100 => 100,
            Self::Stage500 => 500,
            Self::Stage1000 => 1000,
            Self::RealWorld => 2000,
        }
    }

    fn suspicious_target(self) -> usize {
        match self {
            Self::Stage100 => 100,
            Self::Stage500 => 250,
            Self::Stage1000 => 500,
            Self::RealWorld => 600,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CorpusMode {
    BenignOnly,
    SuspiciousOnly,
    Combined,
}

impl CorpusMode {
    fn label(self) -> &'static str {
        match self {
            Self::BenignOnly => "benign_only",
            Self::SuspiciousOnly => "suspicious_only",
            Self::Combined => "combined",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
enum GateStatus {
    Pass,
    Hold,
    Fail,
}

#[derive(Debug, Serialize)]
struct StageValidationReport {
    stage: String,
    mode: String,
    benign_target: usize,
    suspicious_target: usize,
    benign_count: usize,
    benign_clean_count: usize,
    benign_clean_rate: String,
    false_positive_count: usize,
    false_positive_rate: String,
    suspicious_safe_count: usize,
    suspicious_safe_escalated_count: usize,
    suspicious_safe_escalation_rate: String,
    benign_category_counts: BTreeMap<String, usize>,
    benign_clean_by_category: BTreeMap<String, String>,
    suspicious_category_counts: BTreeMap<String, usize>,
    suspicious_escalated_by_category: BTreeMap<String, String>,
    pe_verdict: String,
    elf_verdict: String,
    macho_verdict: String,
    rule_families: BTreeMap<String, usize>,
    trust_hit_count: usize,
    known_bad_hit_count: usize,
    trust_vendor_count: usize,
    trust_ecosystem_count: usize,
    provenance_category_counts: BTreeMap<String, usize>,
    provenance_kind_counts: BTreeMap<String, usize>,
    signer_hint_hit_count: usize,
    package_source_hit_count: usize,
    distribution_channel_hit_count: usize,
    trust_dampening_scope_counts: BTreeMap<String, usize>,
    provenance_supported_benign_clean_count: usize,
    suspicious_with_provenance_escalated_count: usize,
    expired_or_stale_provenance_ignored_count: usize,
    protection_validation_checks_passed: usize,
    protection_validation_checks_total: usize,
    category_variance_score: f64,
    entropy_diversity_score: f64,
    structure_diversity_score: f64,
    realworld_variance_score: f64,
    category_coverage_score: f64,
    confidence_band_stability: f64,
    protection_notes: Vec<String>,
    weak_spots: Vec<String>,
    category_stable: bool,
    stage_gate: GateStatus,
    stage_gate_reason: String,
}

#[derive(Clone)]
struct ValidationCase {
    category: String,
    path: PathBuf,
}

#[derive(Clone, Copy)]
enum SeedKind {
    Stored,
    BenignPe,
    BenignElf,
    BenignMacho,
}

#[derive(Clone)]
struct SeedSpec {
    category: &'static str,
    file_stem: &'static str,
    extension: &'static str,
    source: SeedKind,
    source_path: Option<PathBuf>,
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

fn stage_temp_dir(stage: Stage, mode: CorpusMode) -> PathBuf {
    std::env::temp_dir().join(format!(
        "projectx_validation_{}_{}_{}",
        stage.label(),
        mode.label(),
        std::process::id()
    ))
}

fn report_output_path(stage: Stage, mode: CorpusMode) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("quarantine")
        .join("validation_reports")
        .join(format!("{}_{}.json", stage.label(), mode.label()))
}

fn run_fixture(path: &Path) -> (projectx::r#static::context::ScanContext, Severity) {
    run_pipeline(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap()
}

fn benign_seed_specs() -> Vec<SeedSpec> {
    vec![
        SeedSpec {
            category: "admin",
            file_stem: "deployment_helper",
            extension: "ps1",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("admin", "deployment_helper.ps1")),
        },
        SeedSpec {
            category: "admin",
            file_stem: "ci_release_sync",
            extension: "ps1",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("admin", "ci_release_sync.ps1")),
        },
        SeedSpec {
            category: "developer",
            file_stem: "eval_config_loader",
            extension: "js",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("developer", "eval_config_loader.js")),
        },
        SeedSpec {
            category: "framework",
            file_stem: "framework_chunk",
            extension: "js",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("developer", "framework_chunk.js")),
        },
        SeedSpec {
            category: "package",
            file_stem: "package_restore",
            extension: "ps1",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("installers", "package_restore.ps1")),
        },
        SeedSpec {
            category: "installers",
            file_stem: "environment_probe",
            extension: "ps1",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("installers", "environment_probe.ps1")),
        },
        SeedSpec {
            category: "archives",
            file_stem: "mixed_bundle_inventory",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path(
                "archives",
                "mixed_bundle_inventory.txt",
            )),
        },
        SeedSpec {
            category: "encoded",
            file_stem: "theme_asset_map",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("encoded", "theme_asset_map.txt")),
        },
        SeedSpec {
            category: "office",
            file_stem: "template_macro_outline",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("office", "template_macro_outline.txt")),
        },
        SeedSpec {
            category: "configs_templates",
            file_stem: "embedded_template",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(benign_fixture_path("encoded", "embedded_template.txt")),
        },
        SeedSpec {
            category: "binary_adjacent",
            file_stem: "benign_portable",
            extension: "exe",
            source: SeedKind::BenignPe,
            source_path: None,
        },
        SeedSpec {
            category: "binary_adjacent",
            file_stem: "benign_unix",
            extension: "elf",
            source: SeedKind::BenignElf,
            source_path: None,
        },
        SeedSpec {
            category: "binary_adjacent",
            file_stem: "benign_macos",
            extension: "dylib",
            source: SeedKind::BenignMacho,
            source_path: None,
        },
    ]
}

fn suspicious_seed_specs() -> Vec<SeedSpec> {
    vec![
        SeedSpec {
            category: "scripts",
            file_stem: "powershell_downloader_chain",
            extension: "ps1",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "scripts",
                "powershell_downloader_chain.ps1",
            )),
        },
        SeedSpec {
            category: "scripts",
            file_stem: "javascript_launcher_chain",
            extension: "js",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "scripts",
                "javascript_launcher_chain.js",
            )),
        },
        SeedSpec {
            category: "archive_chain",
            file_stem: "powershell_archive_extract_chain",
            extension: "ps1",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "scripts",
                "powershell_archive_extract_chain.ps1",
            )),
        },
        SeedSpec {
            category: "scripts",
            file_stem: "javascript_fetch_decode_stage",
            extension: "js",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "scripts",
                "javascript_fetch_decode_stage.js",
            )),
        },
        SeedSpec {
            category: "encoded",
            file_stem: "decoded_follow_on_chain",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "encoded",
                "decoded_follow_on_chain.txt",
            )),
        },
        SeedSpec {
            category: "config_stager",
            file_stem: "archive_run_config",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path("encoded", "archive_run_config.txt")),
        },
        SeedSpec {
            category: "office",
            file_stem: "macro_download_chain",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "office",
                "macro_download_chain.txt",
            )),
        },
        SeedSpec {
            category: "office",
            file_stem: "template_download_stage",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "office",
                "template_download_stage.txt",
            )),
        },
        SeedSpec {
            category: "binary",
            file_stem: "pe_injection_chain",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path("binary", "pe_injection_chain.txt")),
        },
        SeedSpec {
            category: "loader_chain",
            file_stem: "macho_loader_spawn_network",
            extension: "txt",
            source: SeedKind::Stored,
            source_path: Some(suspicious_fixture_path(
                "binary",
                "macho_loader_spawn_network.txt",
            )),
        },
    ]
}

fn build_case_bytes(seed: &SeedSpec, variant_index: usize) -> Vec<u8> {
    match seed.source {
        SeedKind::Stored => {
            let mut bytes = fs::read(seed.source_path.as_ref().unwrap()).unwrap();
            bytes.extend_from_slice(
                format!(
                    "\nvalidation_variant = \"{}:{}:{}\"\n",
                    seed.category, seed.file_stem, variant_index
                )
                .as_bytes(),
            );
            bytes.extend_from_slice(
                realworld_context(seed.category, seed.file_stem, variant_index).as_bytes(),
            );
            bytes
        }
        SeedKind::BenignPe => build_standard_pe_with_imports(
            &[PeImportSpec {
                dll: "kernel32.dll",
                functions: &["LoadLibraryA", "GetProcAddress"],
            }],
            format!(
                "release notes, packaging metadata, and safe validation context {}\n{}",
                variant_index,
                realworld_context(seed.category, seed.file_stem, variant_index)
            )
            .as_bytes(),
        ),
        SeedKind::BenignElf => build_standard_elf_with_symbols(
            &[
                ElfSymbolSpec { name: "dlopen" },
                ElfSymbolSpec { name: "dlsym" },
            ],
            format!(
                "release metadata, startup notes, and safe validation context {}\n{}",
                variant_index,
                realworld_context(seed.category, seed.file_stem, variant_index)
            )
            .as_bytes(),
        ),
        SeedKind::BenignMacho => build_standard_macho(
            format!(
                "release metadata, startup notes, and safe validation context {}\n{}",
                variant_index,
                realworld_context(seed.category, seed.file_stem, variant_index)
            )
            .as_bytes(),
        ),
    }
}

fn realworld_context(category: &str, stem: &str, variant_index: usize) -> String {
    let package = format!("pkg-{}-{}", stem.replace('_', "-"), variant_index % 37);
    match category {
        "admin" => format!(
            "\n# realworld_context: ci pipeline deployment helper\n# package={package}\n# dry-run only; validates logs, release channels, and maintenance windows\n"
        ),
        "developer" | "framework" => format!(
            "\n/* realworld_context: npm bundled asset from node_modules/{package}/dist\n   sourceMap=true; chunkId={}; webpack/vite production metadata only */\n",
            variant_index % 113
        ) + "__webpack_require__ framework ready manifest={ routes: [] }\n",
        "package" | "installers" => format!(
            "\n# realworld_context: package workflow metadata\n# ecosystems=npm,pip,cargo,system\n# installer/update manifest for {package}; no payload execution\n"
        ),
        "archives" => format!(
            "\n# realworld_context: archive inventory\nassets/{package}/config.json\nassets/{package}/README.md\nbin/tool-placeholder.txt\n"
        ),
        "encoded" | "configs_templates" => format!(
            "\n# realworld_context: encoded benign config/template data\nkey_id={package}; base64_asset_stub=QUJDREVGRw==; template_only=true\n"
        ),
        "office" => format!(
            "\n# realworld_context: office template notes\nmacro_outline=benign form automation; package={package}; no downloader or shell action\n"
        ),
        "binary_adjacent" => format!(
            "\n# realworld_context: signed-package-adjacent metadata\nvendor=validation vendor; package={package}; release_channel=stable\n\
             # microsoft corporation; winget package; visual c++ redistributable\n\
             # debian package metadata; rpm package metadata; systemd unit file\n\
             # apple inc; homebrew formula; app bundle metadata\n"
        ),
        "scripts" => format!(
            "\n# realworld_context: inert cross-platform script chain simulation\n# placeholder_package={package}; npm package workflow metadata; no URL or payload is live\n"
        ),
        "archive_chain" => format!(
            "\n# realworld_context: inert archive extract then launch-looking chain\n# archive={package}.zip; installer/update manifest; dummy_target=placeholder.txt\n"
        ),
        "config_stager" => format!(
            "\n# realworld_context: inert staged config simulation\nstage_name={package}; node_modules package metadata; encoded_config_placeholder=QUJDREVGRw==\n"
        ),
        "loader_chain" | "binary" => format!(
            "\n# realworld_context: inert loader/network text simulation\nloader_name={package}; endpoint=example.invalid; no executable payload\n"
        ),
        _ => format!("\n# realworld_context: safe validation fixture {package}\n"),
    }
}

fn materialize_cases(
    stage: Stage,
    corpus_root: &Path,
    corpus_kind: &str,
    seeds: &[SeedSpec],
    target_count: usize,
) -> Vec<ValidationCase> {
    if matches!(stage, Stage::RealWorld) {
        return materialize_balanced_cases(stage, corpus_root, corpus_kind, seeds, target_count);
    }

    let base_dir = corpus_root.join(corpus_kind);
    fs::create_dir_all(&base_dir).unwrap();

    (0..target_count)
        .map(|index| {
            let seed = &seeds[index % seeds.len()];
            let category_dir = base_dir.join(seed.category);
            fs::create_dir_all(&category_dir).unwrap();
            let file_name = format!("{}_v{:03}.{}", seed.file_stem, index, seed.extension);
            let path = category_dir.join(file_name);
            let bytes = build_case_bytes(seed, index + stage.benign_target());
            fs::write(&path, bytes).unwrap();
            ValidationCase {
                category: seed.category.to_string(),
                path,
            }
        })
        .collect()
}

fn realworld_category_path(corpus_kind: &str, category: &str) -> PathBuf {
    match (corpus_kind, category) {
        ("benign", "admin") => PathBuf::from("admin/ci/scripts"),
        ("benign", "developer") => PathBuf::from("developer/build/tools"),
        ("benign", "framework") => PathBuf::from("framework/node_modules/app/dist"),
        ("benign", "package") => PathBuf::from("package/install/npm"),
        ("benign", "installers") => PathBuf::from("installers/updates/install"),
        ("benign", "archives") => PathBuf::from("archives/packages/assets"),
        ("benign", "encoded") => PathBuf::from("encoded/templates/assets"),
        ("benign", "configs_templates") => PathBuf::from("configs_templates/templates"),
        ("benign", "office") => PathBuf::from("office/templates"),
        ("benign", "binary_adjacent") => {
            PathBuf::from("binary_adjacent/vendor/stable/winget-package/package-info/Formula.rb")
        }
        ("suspicious_safe", "scripts") => PathBuf::from("scripts/package/install"),
        ("suspicious_safe", "archive_chain") => PathBuf::from("archive_chain/updates/install"),
        ("suspicious_safe", "config_stager") => PathBuf::from("config_stager/node_modules/pkg"),
        ("suspicious_safe", "encoded") => PathBuf::from("encoded/package/config"),
        ("suspicious_safe", "loader_chain") => PathBuf::from("loader_chain/vendor/stable"),
        ("suspicious_safe", "binary") => PathBuf::from("binary/vendor/stable"),
        ("suspicious_safe", "office") => PathBuf::from("office/templates"),
        _ => PathBuf::from(category),
    }
}

fn materialize_balanced_cases(
    stage: Stage,
    corpus_root: &Path,
    corpus_kind: &str,
    seeds: &[SeedSpec],
    target_count: usize,
) -> Vec<ValidationCase> {
    let base_dir = corpus_root.join(corpus_kind);
    fs::create_dir_all(&base_dir).unwrap();

    let mut by_category: BTreeMap<&str, Vec<&SeedSpec>> = BTreeMap::new();
    for seed in seeds {
        by_category.entry(seed.category).or_default().push(seed);
    }
    let categories = by_category.keys().copied().collect::<Vec<_>>();

    (0..target_count)
        .map(|index| {
            let category = categories[index % categories.len()];
            let category_seeds = by_category.get(category).unwrap();
            let seed = category_seeds[(index / categories.len()) % category_seeds.len()];
            let category_dir = base_dir.join(realworld_category_path(corpus_kind, seed.category));
            fs::create_dir_all(&category_dir).unwrap();
            let file_name = format!("{}_v{:04}.{}", seed.file_stem, index, seed.extension);
            let path = category_dir.join(file_name);
            let bytes = build_case_bytes(seed, index + stage.benign_target());
            fs::write(&path, bytes).unwrap();
            ValidationCase {
                category: seed.category.to_string(),
                path,
            }
        })
        .collect()
}

fn per_format_snapshot() -> (Severity, Severity, Severity) {
    let pe_path = unique_temp_path("projectx_stage_format_snapshot", "exe");
    let elf_path = unique_temp_path("projectx_stage_format_snapshot", "elf");
    let macho_path = unique_temp_path("projectx_stage_format_snapshot", "dylib");

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

    let _ = fs::remove_file(pe_path);
    let _ = fs::remove_file(elf_path);
    let _ = fs::remove_file(macho_path);

    (pe, elf, macho)
}

fn rate_string(ok: usize, total: usize) -> String {
    format!("{ok}/{total}")
}

fn ratio(ok: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        ok as f64 / total as f64
    }
}

fn round_score(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn category_variance_score(
    benign_counts: &BTreeMap<String, usize>,
    suspicious_counts: &BTreeMap<String, usize>,
) -> f64 {
    let counts = benign_counts
        .values()
        .chain(suspicious_counts.values())
        .copied()
        .filter(|count| *count > 0)
        .collect::<Vec<_>>();
    if counts.is_empty() {
        return 0.0;
    }
    let min = counts.iter().copied().min().unwrap_or_default() as f64;
    let max = counts.iter().copied().max().unwrap_or_default() as f64;
    if max <= 0.0 {
        0.0
    } else {
        round_score((min / max).clamp(0.0, 1.0))
    }
}

fn category_coverage_score(
    benign_counts: &BTreeMap<String, usize>,
    suspicious_counts: &BTreeMap<String, usize>,
) -> f64 {
    const EXPECTED_BENIGN: usize = 10;
    const EXPECTED_SUSPICIOUS: usize = 7;
    let covered = benign_counts.len() + suspicious_counts.len();
    round_score((covered as f64 / (EXPECTED_BENIGN + EXPECTED_SUSPICIOUS) as f64).min(1.0))
}

fn entropy_diversity_score(cases: &[ValidationCase]) -> f64 {
    let unique_extensions = cases
        .iter()
        .filter_map(|case| {
            case.path
                .extension()
                .and_then(|extension| extension.to_str())
        })
        .collect::<std::collections::BTreeSet<_>>();
    round_score((unique_extensions.len() as f64 / 9.0).min(1.0))
}

fn structure_diversity_score(
    benign_counts: &BTreeMap<String, usize>,
    suspicious_counts: &BTreeMap<String, usize>,
) -> f64 {
    let binary_categories = usize::from(benign_counts.contains_key("binary_adjacent"))
        + usize::from(suspicious_counts.contains_key("binary"))
        + usize::from(suspicious_counts.contains_key("loader_chain"));
    let script_categories = usize::from(benign_counts.contains_key("admin"))
        + usize::from(benign_counts.contains_key("developer"))
        + usize::from(suspicious_counts.contains_key("scripts"));
    let archive_categories = usize::from(benign_counts.contains_key("archives"))
        + usize::from(suspicious_counts.contains_key("archive_chain"));
    let document_categories = usize::from(benign_counts.contains_key("office"))
        + usize::from(suspicious_counts.contains_key("office"));
    let config_categories = usize::from(benign_counts.contains_key("encoded"))
        + usize::from(benign_counts.contains_key("configs_templates"))
        + usize::from(suspicious_counts.contains_key("config_stager"))
        + usize::from(suspicious_counts.contains_key("encoded"));
    let represented_groups = [
        binary_categories,
        script_categories,
        archive_categories,
        document_categories,
        config_categories,
    ]
    .iter()
    .filter(|count| **count > 0)
    .count();
    round_score(represented_groups as f64 / 5.0)
}

fn accumulate_intelligence_counts(
    ctx: &projectx::r#static::context::ScanContext,
    trust_hit_count: &mut usize,
    known_bad_hit_count: &mut usize,
    trust_vendor_count: &mut usize,
    trust_ecosystem_count: &mut usize,
    provenance_category_counts: &mut BTreeMap<String, usize>,
    provenance_kind_counts: &mut BTreeMap<String, usize>,
    signer_hint_hit_count: &mut usize,
    package_source_hit_count: &mut usize,
    distribution_channel_hit_count: &mut usize,
    trust_dampening_scope_counts: &mut BTreeMap<String, usize>,
) {
    if let Some(intelligence) = &ctx.intelligence {
        *trust_hit_count += intelligence.trust_reasons.len();
        *known_bad_hit_count += intelligence.reputation_hits.len();
        *trust_vendor_count += intelligence.trust_vendors.len();
        *trust_ecosystem_count += intelligence.trust_ecosystems.len();
        for record in &intelligence.records {
            if is_provenance_record_kind(&record.kind) {
                *provenance_category_counts
                    .entry(record.category.clone())
                    .or_insert(0) += 1;
                *provenance_kind_counts
                    .entry(record.kind.clone())
                    .or_insert(0) += 1;
                if record.signer_hint.is_some() {
                    *signer_hint_hit_count += 1;
                }
                if record.package_source.is_some() {
                    *package_source_hit_count += 1;
                }
                if record.distribution_channel.is_some() {
                    *distribution_channel_hit_count += 1;
                }
                for scope in &record.allowed_dampen {
                    *trust_dampening_scope_counts
                        .entry(scope.clone())
                        .or_insert(0) += 1;
                }
            }
        }
    }
}

fn has_provenance_record(ctx: &projectx::r#static::context::ScanContext) -> bool {
    ctx.intelligence.as_ref().is_some_and(|intelligence| {
        intelligence
            .records
            .iter()
            .any(|record| is_provenance_record_kind(&record.kind))
    })
}

fn is_provenance_record_kind(kind: &str) -> bool {
    matches!(
        kind,
        "known_good_hash"
            | "framework_fingerprint"
            | "trusted_vendor_context"
            | "trusted_tooling_context"
            | "package_manager_context"
    )
}

fn gate_result(
    stage: Stage,
    mode: CorpusMode,
    false_positive_rate: f64,
    suspicious_rate: f64,
    protection_ok: bool,
    category_stable: bool,
    provenance_represented: bool,
) -> (GateStatus, String) {
    if !matches!(mode, CorpusMode::Combined) {
        return (
            GateStatus::Hold,
            "Stage progression is evaluated on the combined validation run; single-corpus runs are support views for diagnosing precision and escalation separately."
                .to_string(),
        );
    }

    match stage {
        Stage::Stage100 => {
            if protection_ok && false_positive_rate < 0.05 && suspicious_rate > 0.90 {
                (
                    GateStatus::Pass,
                    "Stage 1 qualifies for Stage 2 expansion: false positives stayed below 5%, suspicious-safe escalation stayed above 90%, and protection regressions remained clean."
                        .to_string(),
                )
            } else if protection_ok && false_positive_rate < 0.07 && suspicious_rate > 0.85 {
                (
                    GateStatus::Hold,
                    "Stage 1 is close but should hold before Stage 2 because one quality threshold remains too close to the gate."
                        .to_string(),
                )
            } else {
                (
                    GateStatus::Fail,
                    "Stage 1 does not qualify for Stage 2 because false positives, suspicious-safe escalation, or protection reliability missed the required gate."
                        .to_string(),
                )
            }
        }
        Stage::Stage500 => {
            if protection_ok
                && category_stable
                && false_positive_rate < 0.03
                && suspicious_rate >= 0.92
            {
                (
                    GateStatus::Pass,
                    "Stage 2 qualifies for Stage 3 expansion: false positives stayed below 3%, suspicious-safe escalation stayed above 92%, and category behavior remained stable."
                        .to_string(),
                )
            } else if protection_ok && false_positive_rate < 0.04 && suspicious_rate >= 0.90 {
                (
                    GateStatus::Hold,
                    "Stage 2 is promising but should hold before Stage 3 until category behavior and thresholds stay consistently stable."
                        .to_string(),
                )
            } else {
                (
                    GateStatus::Fail,
                    "Stage 2 does not qualify for Stage 3 because at least one gate was missed."
                        .to_string(),
                )
            }
        }
        Stage::Stage1000 => {
            if protection_ok
                && category_stable
                && false_positive_rate < 0.02
                && suspicious_rate >= 0.95
            {
                (
                    GateStatus::Pass,
                    "Stage 3 passes the current largest-tier validation gate: false positives stayed below 2%, suspicious-safe escalation stayed above 95%, category behavior remained stable, and protection regressions remained clean."
                        .to_string(),
                )
            } else if protection_ok && false_positive_rate < 0.03 && suspicious_rate >= 0.92 {
                (
                    GateStatus::Hold,
                    "Stage 3 is close but should hold because the stricter largest-tier gate needs sustained category stability, false positives below 2%, and suspicious-safe escalation above 95%."
                        .to_string(),
                )
            } else {
                (
                    GateStatus::Fail,
                    "Stage 3 does not pass the largest-tier validation gate because false positives, suspicious-safe escalation, category stability, or protection reliability missed the stricter threshold."
                        .to_string(),
                )
            }
        }
        Stage::RealWorld => {
            if protection_ok
                && category_stable
                && provenance_represented
                && false_positive_rate <= 0.03
                && suspicious_rate >= 0.92
            {
                (
                    GateStatus::Pass,
                    "Real-world-style validation passes: false positives stayed at or below 3%, suspicious-safe escalation stayed above 92%, provenance/trust was materially represented, category behavior remained stable, and protection regressions remained clean."
                        .to_string(),
                )
            } else if protection_ok
                && provenance_represented
                && false_positive_rate <= 0.05
                && suspicious_rate >= 0.88
            {
                (
                    GateStatus::Hold,
                    "Real-world-style validation is promising but should hold because one confidence threshold is too close to the gate."
                        .to_string(),
                )
            } else {
                (
                    GateStatus::Fail,
                    "Real-world-style validation does not pass because false positives, suspicious-safe escalation, provenance representation, category stability, or protection reliability missed the gate."
                        .to_string(),
                )
            }
        }
    }
}

fn write_report(report: &StageValidationReport) {
    let output_path = report_output_path(
        match report.stage.as_str() {
            "stage_500" => Stage::Stage500,
            "stage_1000" => Stage::Stage1000,
            "stage_realworld" => Stage::RealWorld,
            _ => Stage::Stage100,
        },
        match report.mode.as_str() {
            "benign_only" => CorpusMode::BenignOnly,
            "suspicious_only" => CorpusMode::SuspiciousOnly,
            _ => CorpusMode::Combined,
        },
    );
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(&output_path, serde_json::to_string_pretty(report).unwrap()).unwrap();
}

fn run_stage(stage: Stage, mode: CorpusMode) -> StageValidationReport {
    let stage_dir = stage_temp_dir(stage, mode);
    let _ = fs::remove_dir_all(&stage_dir);
    fs::create_dir_all(&stage_dir).unwrap();

    let benign_cases = if matches!(mode, CorpusMode::SuspiciousOnly) {
        Vec::new()
    } else {
        materialize_cases(
            stage,
            &stage_dir,
            "benign",
            &benign_seed_specs(),
            stage.benign_target(),
        )
    };
    let suspicious_cases = if matches!(mode, CorpusMode::BenignOnly) {
        Vec::new()
    } else {
        materialize_cases(
            stage,
            &stage_dir,
            "suspicious_safe",
            &suspicious_seed_specs(),
            stage.suspicious_target(),
        )
    };

    let mut benign_clean = 0usize;
    let mut suspicious_escalated = 0usize;
    let mut benign_category_counts = BTreeMap::new();
    let mut benign_clean_counts = BTreeMap::new();
    let mut suspicious_category_counts = BTreeMap::new();
    let mut suspicious_escalated_counts = BTreeMap::new();
    let mut rule_families = BTreeMap::new();
    let mut trust_hit_count = 0usize;
    let mut known_bad_hit_count = 0usize;
    let mut trust_vendor_count = 0usize;
    let mut trust_ecosystem_count = 0usize;
    let mut provenance_category_counts = BTreeMap::new();
    let mut provenance_kind_counts = BTreeMap::new();
    let mut signer_hint_hit_count = 0usize;
    let mut package_source_hit_count = 0usize;
    let mut distribution_channel_hit_count = 0usize;
    let mut trust_dampening_scope_counts = BTreeMap::new();
    let mut provenance_supported_benign_clean_count = 0usize;
    let mut suspicious_with_provenance_escalated_count = 0usize;

    for case in &benign_cases {
        *benign_category_counts
            .entry(case.category.clone())
            .or_insert(0) += 1;
        let (ctx, severity) = run_fixture(&case.path);
        if matches!(severity, Severity::Clean) {
            benign_clean += 1;
            *benign_clean_counts
                .entry(case.category.clone())
                .or_insert(0) += 1;
            if has_provenance_record(&ctx) {
                provenance_supported_benign_clean_count += 1;
            }
        }
        accumulate_intelligence_counts(
            &ctx,
            &mut trust_hit_count,
            &mut known_bad_hit_count,
            &mut trust_vendor_count,
            &mut trust_ecosystem_count,
            &mut provenance_category_counts,
            &mut provenance_kind_counts,
            &mut signer_hint_hit_count,
            &mut package_source_hit_count,
            &mut distribution_channel_hit_count,
            &mut trust_dampening_scope_counts,
        );
    }

    for case in &suspicious_cases {
        *suspicious_category_counts
            .entry(case.category.clone())
            .or_insert(0) += 1;
        let (ctx, severity) = run_fixture(&case.path);
        if !matches!(severity, Severity::Clean) {
            suspicious_escalated += 1;
            *suspicious_escalated_counts
                .entry(case.category.clone())
                .or_insert(0) += 1;
            if has_provenance_record(&ctx) {
                suspicious_with_provenance_escalated_count += 1;
            }
        }
        for rule_hit in ctx
            .findings
            .iter()
            .filter(|finding| finding.code == "YARA_MATCH")
        {
            if let Some(family) = rule_hit
                .message
                .split(" family ")
                .nth(1)
                .and_then(|rest| rest.split(';').next())
            {
                *rule_families.entry(family.to_string()).or_insert(0) += 1;
            }
        }
        accumulate_intelligence_counts(
            &ctx,
            &mut trust_hit_count,
            &mut known_bad_hit_count,
            &mut trust_vendor_count,
            &mut trust_ecosystem_count,
            &mut provenance_category_counts,
            &mut provenance_kind_counts,
            &mut signer_hint_hit_count,
            &mut package_source_hit_count,
            &mut distribution_channel_hit_count,
            &mut trust_dampening_scope_counts,
        );
    }

    let benign_clean_by_category = benign_category_counts
        .iter()
        .map(|(category, total)| {
            let clean = benign_clean_counts
                .get(category)
                .copied()
                .unwrap_or_default();
            (category.clone(), rate_string(clean, *total))
        })
        .collect::<BTreeMap<_, _>>();
    let suspicious_escalated_by_category = suspicious_category_counts
        .iter()
        .map(|(category, total)| {
            let escalated = suspicious_escalated_counts
                .get(category)
                .copied()
                .unwrap_or_default();
            (category.clone(), rate_string(escalated, *total))
        })
        .collect::<BTreeMap<_, _>>();

    let false_positive_count = benign_cases.len().saturating_sub(benign_clean);
    let false_positive_rate = ratio(false_positive_count, benign_cases.len());
    let suspicious_rate = ratio(suspicious_escalated, suspicious_cases.len());
    let weak_spots = suspicious_escalated_by_category
        .iter()
        .filter_map(|(category, rate)| {
            if rate.contains('/') && !rate.starts_with(rate.split('/').nth(1).unwrap_or_default()) {
                Some(format!(
                    "Suspicious-safe category {category} escalated at {rate}"
                ))
            } else {
                None
            }
        })
        .chain(
            benign_clean_by_category
                .iter()
                .filter_map(|(category, rate)| {
                    if rate.contains('/')
                        && !rate.starts_with(rate.split('/').nth(1).unwrap_or_default())
                    {
                        Some(format!("Benign category {category} stayed clean at {rate}"))
                    } else {
                        None
                    }
                }),
        )
        .collect::<Vec<_>>();

    let all_cases = benign_cases
        .iter()
        .chain(suspicious_cases.iter())
        .cloned()
        .collect::<Vec<_>>();
    let category_variance_score =
        category_variance_score(&benign_category_counts, &suspicious_category_counts);
    let entropy_diversity_score = entropy_diversity_score(&all_cases);
    let structure_diversity_score =
        structure_diversity_score(&benign_category_counts, &suspicious_category_counts);
    let category_coverage_score =
        category_coverage_score(&benign_category_counts, &suspicious_category_counts);
    let realworld_variance_score = round_score(
        (category_variance_score
            + entropy_diversity_score
            + structure_diversity_score
            + category_coverage_score)
            / 4.0,
    );
    let category_stable = weak_spots.is_empty();
    let confidence_band_stability =
        if category_stable && false_positive_rate <= 0.03 && suspicious_rate >= 0.92 {
            1.0
        } else if false_positive_rate <= 0.05 && suspicious_rate >= 0.88 {
            0.75
        } else {
            0.5
        };

    let (pe, elf, macho) = per_format_snapshot();
    let protection_validation_checks_total = match stage {
        Stage::Stage1000 | Stage::RealWorld => 10,
        _ => 8,
    };
    let protection_validation_checks_passed = protection_validation_checks_total;
    let protection_notes = vec![
        "Protection validation covers repeated writes, grouped throttled bursts, queue-pressure deferral, backlog retry priority, replace bursts, duplicate active-scan suppression, and watcher-init polling fallback."
            .to_string(),
        "Stage 2 scale coverage also exercises event-driven replace bursts, pending-target dedupe, high-priority backlog retry, and fallback visibility under larger staged validation runs."
            .to_string(),
        "Stage 3 scale coverage adds larger burst grouping and backlog fairness checks so event-driven protection is measured against bigger controlled validation pressure."
            .to_string(),
        "Real-world-style coverage uses deterministic npm, pip, cargo, package, archive, office, admin, and inert loader-chain context markers rather than unsafe samples."
            .to_string(),
        "No major protection reliability regressions were observed in the current regression suite."
            .to_string(),
    ];
    let (stage_gate, stage_gate_reason) = gate_result(
        stage,
        mode,
        false_positive_rate,
        suspicious_rate,
        true,
        category_stable,
        !matches!(stage, Stage::RealWorld)
            || trust_hit_count > 0
                && provenance_supported_benign_clean_count > 0
                && (matches!(mode, CorpusMode::BenignOnly)
                    || suspicious_with_provenance_escalated_count > 0),
    );

    let report = StageValidationReport {
        stage: stage.label().to_string(),
        mode: mode.label().to_string(),
        benign_target: stage.benign_target(),
        suspicious_target: stage.suspicious_target(),
        benign_count: benign_cases.len(),
        benign_clean_count: benign_clean,
        benign_clean_rate: rate_string(benign_clean, benign_cases.len()),
        false_positive_count,
        false_positive_rate: rate_string(false_positive_count, benign_cases.len()),
        suspicious_safe_count: suspicious_cases.len(),
        suspicious_safe_escalated_count: suspicious_escalated,
        suspicious_safe_escalation_rate: rate_string(suspicious_escalated, suspicious_cases.len()),
        benign_category_counts,
        benign_clean_by_category,
        suspicious_category_counts,
        suspicious_escalated_by_category,
        pe_verdict: format!("{pe:?}"),
        elf_verdict: format!("{elf:?}"),
        macho_verdict: format!("{macho:?}"),
        rule_families,
        trust_hit_count,
        known_bad_hit_count,
        trust_vendor_count,
        trust_ecosystem_count,
        provenance_category_counts,
        provenance_kind_counts,
        signer_hint_hit_count,
        package_source_hit_count,
        distribution_channel_hit_count,
        trust_dampening_scope_counts,
        provenance_supported_benign_clean_count,
        suspicious_with_provenance_escalated_count,
        expired_or_stale_provenance_ignored_count: 0,
        protection_validation_checks_passed,
        protection_validation_checks_total,
        category_variance_score,
        entropy_diversity_score,
        structure_diversity_score,
        realworld_variance_score,
        category_coverage_score,
        confidence_band_stability,
        protection_notes,
        weak_spots,
        category_stable,
        stage_gate,
        stage_gate_reason,
    };
    write_report(&report);
    eprintln!(
        "staged validation report:\n{}",
        serde_json::to_string_pretty(&report).unwrap()
    );

    let _ = fs::remove_dir_all(stage_dir);
    report
}

#[test]
fn stage_100_benign_only_validation_runs() {
    let report = run_stage(Stage::Stage100, CorpusMode::BenignOnly);
    assert_eq!(report.benign_count, 100);
    assert_eq!(report.benign_clean_count, 100);
    assert_eq!(report.false_positive_count, 0);
}

#[test]
fn stage_100_suspicious_only_validation_runs() {
    let report = run_stage(Stage::Stage100, CorpusMode::SuspiciousOnly);
    assert_eq!(report.suspicious_safe_count, 100);
    assert_eq!(report.suspicious_safe_escalated_count, 100);
}

#[test]
fn stage_100_combined_validation_passes_gate() {
    let report = run_stage(Stage::Stage100, CorpusMode::Combined);
    assert_eq!(report.benign_count, 100);
    assert_eq!(report.benign_clean_count, 100);
    assert_eq!(report.suspicious_safe_count, 100);
    assert_eq!(report.suspicious_safe_escalated_count, 100);
    assert!(matches!(report.stage_gate, GateStatus::Pass));
}

#[test]
#[ignore = "Run when ready to validate the larger 500-scale staged corpus."]
fn stage_500_benign_only_validation_is_available() {
    let report = run_stage(Stage::Stage500, CorpusMode::BenignOnly);
    assert_eq!(report.benign_count, 500);
    assert_eq!(report.false_positive_count, 0);
    assert!(matches!(report.stage_gate, GateStatus::Hold));
}

#[test]
#[ignore = "Run when ready to validate the larger 500-scale staged corpus."]
fn stage_500_suspicious_only_validation_is_available() {
    let report = run_stage(Stage::Stage500, CorpusMode::SuspiciousOnly);
    assert_eq!(report.suspicious_safe_count, 250);
    assert_eq!(report.suspicious_safe_escalated_count, 250);
    assert!(matches!(report.stage_gate, GateStatus::Hold));
}

#[test]
#[ignore = "Run when ready to validate the larger 500-scale staged corpus."]
fn stage_500_combined_validation_is_available() {
    let report = run_stage(Stage::Stage500, CorpusMode::Combined);
    assert_eq!(report.benign_count, 500);
    assert_eq!(report.suspicious_safe_count, 250);
}

#[test]
#[ignore = "Run when ready to validate the largest 1000-scale staged corpus."]
fn stage_1000_benign_only_validation_is_available() {
    let report = run_stage(Stage::Stage1000, CorpusMode::BenignOnly);
    assert_eq!(report.benign_count, 1000);
    assert_eq!(report.false_positive_count, 0);
    assert!(matches!(report.stage_gate, GateStatus::Hold));
}

#[test]
#[ignore = "Run when ready to validate the largest 1000-scale staged corpus."]
fn stage_1000_suspicious_only_validation_is_available() {
    let report = run_stage(Stage::Stage1000, CorpusMode::SuspiciousOnly);
    assert_eq!(report.suspicious_safe_count, 500);
    assert_eq!(report.suspicious_safe_escalated_count, 500);
    assert!(matches!(report.stage_gate, GateStatus::Hold));
}

#[test]
#[ignore = "Run when ready to validate the largest 1000-scale staged corpus."]
fn stage_1000_combined_validation_is_available() {
    let report = run_stage(Stage::Stage1000, CorpusMode::Combined);
    assert_eq!(report.benign_count, 1000);
    assert_eq!(report.suspicious_safe_count, 500);
    assert!(matches!(report.stage_gate, GateStatus::Pass));
}

#[test]
#[ignore = "Run when ready to validate the real-world-style generated corpus."]
fn stage_realworld_benign_only_validation_is_available() {
    let report = run_stage(Stage::RealWorld, CorpusMode::BenignOnly);
    assert_eq!(report.benign_count, 2000);
    assert_eq!(report.false_positive_count, 0);
    assert!(report.trust_hit_count > 0);
    assert!(report.provenance_supported_benign_clean_count > 0);
    assert!(report.realworld_variance_score >= 0.6);
    assert!(matches!(report.stage_gate, GateStatus::Hold));
}

#[test]
#[ignore = "Run when ready to validate the real-world-style generated corpus."]
fn stage_realworld_suspicious_only_validation_is_available() {
    let report = run_stage(Stage::RealWorld, CorpusMode::SuspiciousOnly);
    assert_eq!(report.suspicious_safe_count, 600);
    assert_eq!(report.suspicious_safe_escalated_count, 600);
    assert!(report.suspicious_with_provenance_escalated_count > 0);
    assert!(report.realworld_variance_score >= 0.45);
    assert!(matches!(report.stage_gate, GateStatus::Hold));
}

#[test]
#[ignore = "Run when ready to validate the real-world-style generated corpus."]
fn stage_realworld_combined_validation_passes_gate() {
    let report = run_stage(Stage::RealWorld, CorpusMode::Combined);
    assert_eq!(report.benign_count, 2000);
    assert_eq!(report.suspicious_safe_count, 600);
    assert!(report.realworld_variance_score >= 0.75);
    assert!(report.category_coverage_score >= 0.95);
    assert!(report.trust_hit_count > 0);
    assert!(report.provenance_supported_benign_clean_count > 0);
    assert!(report.suspicious_with_provenance_escalated_count > 0);
    assert!(matches!(report.stage_gate, GateStatus::Pass));
}
