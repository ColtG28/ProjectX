use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/parser_fixtures.rs"]
mod parser_fixtures;

use parser_fixtures::{
    build_standard_elf, build_standard_elf_with_symbols, build_standard_pe_with_imports,
    build_test_elf, build_test_elf_with_symbol_tables, build_test_elf_with_symbols,
    build_test_fat_macho, build_test_macho, build_test_macho_with_dylib_specs, build_test_pe,
    build_test_pe_with_imports, build_test_pe_with_imports_and_entrypoint,
    malformed_elf_bad_bounds, malformed_elf_bad_static_symbol_table,
    malformed_elf_bad_symbol_table, malformed_macho_bad_load_command, malformed_pe_bad_lfanew,
    unique_temp_path, ElfSymbolSpec, ElfSymbolTableSpec, MachoDylibSpec, MachoSegmentSpec,
    PeImportSpec, PeSectionSpec,
};
use projectx::r#static::config::ScanConfig;
use projectx::r#static::report::normalize_reason_source;
use projectx::r#static::run_pipeline;
use projectx::r#static::types::Severity;

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

fn build_legacy_office_fixture(text_body: &str) -> Vec<u8> {
    let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    bytes.extend_from_slice(text_body.as_bytes());
    bytes
}

fn write_from_fixture(category: &str, name: &str, extension: &str) -> PathBuf {
    let path = unique_temp_path("projectx_suspicious_fixture", extension);
    fs::write(
        &path,
        fs::read(suspicious_fixture_path(category, name)).unwrap(),
    )
    .unwrap();
    path
}

#[test]
fn single_decoded_follow_on_signal_escalates_out_of_clean() {
    let path = suspicious_fixture_path("encoded", "decoded_follow_on_chain.txt");
    let (ctx, severity) = run_fixture(&path);

    assert_ne!(severity, Severity::Clean);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "DECODED_FOLLOW_ON_BEHAVIOR"));
}

#[test]
fn correlated_powershell_rule_and_script_signals_escalate_clearly() {
    let path = write_from_fixture("scripts", "powershell_downloader_chain.ps1", "ps1");
    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PSH_DOWNLOADER_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "YARA_MATCH"));
    assert!(ctx.findings.iter().any(|finding| {
        finding.code == "YARA_MATCH" && finding.message.contains("[high confidence]")
    }));
    assert!(ctx
        .findings
        .iter()
        .map(|finding| normalize_reason_source(&finding.code))
        .any(|source| source == "rule"));
    assert!(ctx
        .findings
        .iter()
        .map(|finding| normalize_reason_source(&finding.code))
        .any(|source| source == "heuristic"));

    let _ = fs::remove_file(path);
}

#[test]
fn javascript_launcher_chain_gets_rule_and_heuristic_corroboration() {
    let path = write_from_fixture("scripts", "javascript_launcher_chain.js", "js");
    let (ctx, severity) = run_fixture(&path);

    assert_ne!(severity, Severity::Clean);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "JS_DOWNLOADER_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "YARA_MATCH"));

    let _ = fs::remove_file(path);
}

#[test]
fn risky_macro_combination_escalates_with_passive_corroboration() {
    let source = suspicious_fixture_path("office", "macro_download_chain.txt");
    let path = unique_temp_path("projectx_suspicious_fixture", "docm");
    let body = fs::read_to_string(&source).unwrap();
    fs::write(&path, build_legacy_office_fixture(&body)).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "OFFICE_MACRO"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "VBA_AUTORUN_DOWNLOAD_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn pe_injection_combo_escalates_with_structural_and_string_signals() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let payload = fs::read(suspicious_fixture_path("binary", "pe_injection_chain.txt")).unwrap();
    let bytes = build_test_pe_with_imports(
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
        &payload,
    );
    fs::write(&path, bytes).unwrap();
    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_INJECTION_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_SCRIPTED_DOWNLOADER_STRINGS"));

    let _ = fs::remove_file(path);
}

#[test]
fn pe_packed_layout_and_script_stage_escalate_clearly() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let payload = fs::read(suspicious_fixture_path(
        "binary",
        "pe_packed_section_loader.txt",
    ))
    .unwrap();
    let bytes = build_test_pe_with_imports(
        &[
            PeSectionSpec {
                name: "UPX0",
                virtual_size: 0x2000,
                raw_size: 0x200,
                characteristics: 0xE000_0020,
            },
            PeSectionSpec {
                name: "UPX1",
                virtual_size: 0x1000,
                raw_size: 0x200,
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".idata",
                virtual_size: 0x800,
                raw_size: 0x400,
                characteristics: 0xC000_0040,
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
            functions: &["VirtualAlloc", "WriteProcessMemory", "QueueUserAPC"],
        }],
        &payload,
    );
    fs::write(&path, bytes).unwrap();
    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_PACKED_SECTION_LAYOUT"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_EXECUTABLE_WRITABLE_SECTION"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_RESOURCE_SCRIPT_STAGE"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_INJECTION_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "YARA_MATCH"));

    let _ = fs::remove_file(path);
}

#[test]
fn pe_entrypoint_in_packed_section_improves_structural_confidence() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let bytes = build_test_pe_with_imports_and_entrypoint(
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
        ],
        &[PeImportSpec {
            dll: "kernel32.dll",
            functions: &["VirtualAlloc", "WriteProcessMemory", "QueueUserAPC"],
        }],
        b"downloadstring powershell http placeholder",
        Some("UPX0"),
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_ENTRYPOINT_IN_PACKED_SECTION"));

    let _ = fs::remove_file(path);
}

#[test]
fn pe_resource_stage_escalates_without_needing_many_strings() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let payload = fs::read(suspicious_fixture_path("binary", "pe_resource_stage.txt")).unwrap();
    let bytes = build_test_pe(
        &[
            PeSectionSpec {
                name: ".text",
                virtual_size: 0x900,
                raw_size: 0x400,
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".rsrc",
                virtual_size: 0x700,
                raw_size: 0x200,
                characteristics: 0x4000_0040,
            },
        ],
        &payload,
    );
    fs::write(&path, bytes).unwrap();
    let (ctx, severity) = run_fixture(&path);

    assert_ne!(severity, Severity::Clean);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_RESOURCE_SCRIPT_STAGE"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_LAUNCHER_NETWORK_STRINGS"
            || finding.code == "PE_SCRIPTED_DOWNLOADER_STRINGS"));

    let _ = fs::remove_file(path);
}

#[test]
fn elf_shell_network_combo_escalates_out_of_clean() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let payload = fs::read(suspicious_fixture_path(
        "binary",
        "elf_shell_network_chain.txt",
    ))
    .unwrap();
    let bytes = build_test_elf(
        &[".text", ".dynamic", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &payload,
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_SHELL_DOWNLOADER"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_SHELL_NETWORK_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn elf_structural_loader_chain_escalates_with_content_corroboration() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let payload = fs::read(suspicious_fixture_path(
        "binary",
        "elf_dynamic_loader_chain.txt",
    ))
    .unwrap();
    let bytes = build_test_elf(
        &[".text", ".dynamic", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &payload,
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_DYNAMIC_LOADER_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_SELF_RELAUNCH_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_SHELL_NETWORK_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn elf_symbol_loader_chain_escalates_with_parsed_symbol_corroboration() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let payload = fs::read(suspicious_fixture_path(
        "binary",
        "elf_dynamic_loader_chain.txt",
    ))
    .unwrap();
    let bytes = build_test_elf_with_symbols(
        &[
            ".text",
            ".dynamic",
            ".dynstr",
            ".dynsym",
            ".interp",
            ".shstrtab",
        ],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
            ElfSymbolSpec { name: "mprotect" },
        ],
        &payload,
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_DYNAMIC_SYMBOL_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_DYNAMIC_LOADER_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn elf_exec_network_symbol_chain_escalates_with_content_corroboration() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let payload = fs::read(suspicious_fixture_path(
        "binary",
        "elf_symbol_exec_network.txt",
    ))
    .unwrap();
    let bytes = build_test_elf_with_symbols(
        &[
            ".text",
            ".dynamic",
            ".dynstr",
            ".dynsym",
            ".interp",
            ".shstrtab",
        ],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "execve" },
            ElfSymbolSpec { name: "system" },
            ElfSymbolSpec { name: "socket" },
            ElfSymbolSpec { name: "connect" },
            ElfSymbolSpec {
                name: "getaddrinfo",
            },
        ],
        &payload,
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_EXEC_NETWORK_SYMBOL_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_SHELL_NETWORK_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn elf_static_symbol_chain_escalates_with_content_corroboration() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let bytes = build_test_elf_with_symbol_tables(
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
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn elf_self_relaunch_symbol_chain_escalates_with_interp_and_content() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let payload = fs::read(suspicious_fixture_path(
        "binary",
        "elf_self_relaunch_symbols.txt",
    ))
    .unwrap();
    let bytes = build_test_elf_with_symbols(
        &[
            ".text",
            ".dynamic",
            ".dynstr",
            ".dynsym",
            ".interp",
            ".shstrtab",
        ],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "execve" },
            ElfSymbolSpec { name: "readlink" },
            ElfSymbolSpec { name: "realpath" },
        ],
        &payload,
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(
        matches!(severity, Severity::Suspicious | Severity::Malicious),
        "risk={} findings={:?}",
        ctx.score.risk,
        ctx.findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        ctx.findings
            .iter()
            .any(|finding| finding.code == "ELF_SELF_RELAUNCH_SYMBOL_CHAIN"),
        "risk={} findings={:?}",
        ctx.score.risk,
        ctx.findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
    );
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_SELF_RELAUNCH_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_pe_sparse_layout_without_corroboration_stays_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let bytes = build_test_pe(
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 0x4000,
            raw_size: 0x200,
            characteristics: 0x6000_0020,
        }],
        b"VersionInfo installer notes",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_SPARSE_SECTION_LAYOUT"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_elf_loader_cue_without_corroboration_stays_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let bytes = build_standard_elf(b"printf puts libc startup");
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "ELF_DYNAMIC_LOADER_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_elf_symbol_loader_cue_without_corroboration_stays_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let bytes = build_test_elf_with_symbols(
        &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
        ],
        b"printf puts libc startup",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "ELF_DYNAMIC_SYMBOL_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn malformed_pe_like_input_fails_safely_in_pipeline() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let mut bytes = malformed_pe_bad_lfanew();
    bytes.extend_from_slice(b"release notes and installer compatibility text");
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.findings.iter().all(|finding| {
        !matches!(
            finding.code.as_str(),
            "PE_PACKED_SECTION_LAYOUT"
                | "PE_EXECUTABLE_WRITABLE_SECTION"
                | "PE_SPARSE_SECTION_LAYOUT"
                | "PE_RESOURCE_SCRIPT_STAGE"
                | "PE_RESOURCE_LOADER_CHAIN"
        )
    }));

    let _ = fs::remove_file(path);
}

#[test]
fn malformed_elf_like_input_fails_safely_in_pipeline() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let mut bytes = malformed_elf_bad_bounds();
    bytes.extend_from_slice(b"runtime notes and package metadata");
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.findings.iter().all(|finding| {
        !matches!(
            finding.code.as_str(),
            "ELF_PACKED_SECTION_LAYOUT" | "ELF_DYNAMIC_LOADER_CHAIN" | "ELF_SELF_RELAUNCH_CHAIN"
        )
    }));

    let _ = fs::remove_file(path);
}

#[test]
fn malformed_elf_symbol_table_fails_safely_in_pipeline() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let mut bytes = malformed_elf_bad_symbol_table();
    bytes.extend_from_slice(b"release notes and support metadata");
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.findings.iter().all(|finding| {
        !matches!(
            finding.code.as_str(),
            "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "ELF_EXEC_NETWORK_SYMBOL_CHAIN"
                | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN"
        )
    }));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_dynamic_loader_imports_without_corroboration_stay_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let bytes = build_standard_pe_with_imports(
        &[PeImportSpec {
            dll: "kernel32.dll",
            functions: &["LoadLibraryA", "GetProcAddress"],
        }],
        b"VersionInfo support notes",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_DYNAMIC_LOADER_IMPORTS"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_pe_packed_layout_with_weak_content_stays_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "exe");
    let bytes = build_test_pe_with_imports_and_entrypoint(
        &[
            PeSectionSpec {
                name: "UPX0",
                virtual_size: 0x1400,
                raw_size: 0x200,
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".text",
                virtual_size: 0x600,
                raw_size: 0x400,
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".rsrc",
                virtual_size: 0x300,
                raw_size: 0x200,
                characteristics: 0x4000_0040,
            },
        ],
        &[],
        b"release notes mention package staging and runtime support",
        Some(".text"),
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "PE_PACKED_SECTION_LAYOUT"));
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "PE_RESOURCE_SCRIPT_STAGE"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_elf_packed_layout_with_weak_content_stays_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let bytes = build_test_elf(
        &[".upx0", ".text", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        b"release notes mention runtime startup support",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_PACKED_SECTION_LAYOUT"));
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "ELF_DYNAMIC_LOADER_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_elf_symbol_and_shell_words_without_exec_network_corroboration_stay_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let bytes = build_standard_elf_with_symbols(
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
        ],
        b"documentation mentions /bin/sh and network support examples",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "ELF_DYNAMIC_SYMBOL_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "ELF_EXEC_NETWORK_SYMBOL_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn parsed_elf_symbol_and_shell_words_become_suspicious_with_exec_network_corroboration() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    let bytes = build_standard_elf_with_symbols(
        &[
            ElfSymbolSpec { name: "system" },
            ElfSymbolSpec { name: "execve" },
            ElfSymbolSpec { name: "socket" },
            ElfSymbolSpec { name: "connect" },
            ElfSymbolSpec {
                name: "getaddrinfo",
            },
        ],
        b"/bin/sh connect getaddrinfo placeholder runtime notes",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "ELF_EXEC_NETWORK_SYMBOL_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn benign_macho_layout_does_not_receive_magic_mismatch_penalty() {
    let path = unique_temp_path("projectx_suspicious_fixture", "dylib");
    let bytes = build_test_macho(
        &[
            MachoSegmentSpec {
                name: "__TEXT",
                maxprot: 5,
                initprot: 5,
                sections: &["__text"],
            },
            MachoSegmentSpec {
                name: "__DATA",
                maxprot: 3,
                initprot: 3,
                sections: &["__data"],
            },
        ],
        &["/usr/lib/libSystem.B.dylib"],
        b"harmless runtime notes",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "MAGIC_MISMATCH"));

    let _ = fs::remove_file(path);
}

#[test]
fn weak_macho_structural_cue_stays_below_suspicious() {
    let path = unique_temp_path("projectx_suspicious_fixture", "dylib");
    let bytes = build_test_macho(
        &[
            MachoSegmentSpec {
                name: "__UPX",
                maxprot: 5,
                initprot: 5,
                sections: &["__text"],
            },
            MachoSegmentSpec {
                name: "__DATA",
                maxprot: 3,
                initprot: 3,
                sections: &["__data"],
            },
        ],
        &["/usr/lib/libSystem.B.dylib"],
        b"release notes for macOS tooling",
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx.score.risk < 3.5);
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "MACHO_PACKED_SECTION_LAYOUT"));
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "MACHO_DYNAMIC_LOADER_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn correlated_macho_loader_case_escalates_appropriately() {
    let path = unique_temp_path("projectx_suspicious_fixture", "dylib");
    let bytes = build_test_macho(
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
    );
    fs::write(&path, build_test_fat_macho(&bytes)).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "MACHO_DYNAMIC_LOADER_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "MACHO_EXEC_NETWORK_CHAIN"));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "MACHO_EXECUTABLE_WRITABLE_SEGMENT"));

    let _ = fs::remove_file(path);
}

#[test]
fn macho_relative_loader_path_chain_escalates_with_corroboration() {
    let path = unique_temp_path("projectx_suspicious_fixture", "dylib");
    let bytes = build_test_macho_with_dylib_specs(
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
    );
    fs::write(&path, bytes).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert!(matches!(
        severity,
        Severity::Suspicious | Severity::Malicious
    ));
    assert!(ctx
        .findings
        .iter()
        .any(|finding| finding.code == "MACHO_RELATIVE_LOADER_PATH_CHAIN"));

    let _ = fs::remove_file(path);
}

#[test]
fn malformed_macho_input_fails_safely_in_pipeline() {
    let path = unique_temp_path("projectx_suspicious_fixture", "dylib");
    fs::write(&path, malformed_macho_bad_load_command()).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx
        .findings
        .iter()
        .all(|finding| !finding.code.starts_with("MACHO_")));

    let _ = fs::remove_file(path);
}

#[test]
fn malformed_static_elf_symbol_table_fails_safely_in_pipeline() {
    let path = unique_temp_path("projectx_suspicious_fixture", "elf");
    fs::write(&path, malformed_elf_bad_static_symbol_table()).unwrap();

    let (ctx, severity) = run_fixture(&path);

    assert_eq!(severity, Severity::Clean);
    assert!(ctx
        .findings
        .iter()
        .all(|finding| finding.code != "ELF_STATIC_SYMBOL_LOADER_CHAIN"
            && finding.code != "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN"));

    let _ = fs::remove_file(path);
}
