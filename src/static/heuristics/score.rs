use std::cmp::Ordering;
use std::collections::HashMap;

use crate::r#static::context::ScanContext;
use crate::r#static::report::normalize_reason_source;
use crate::r#static::types::Finding;

pub fn calculate(ctx: &ScanContext) -> f64 {
    if ctx.findings.is_empty() {
        return 0.0;
    }

    let path_text = ctx.input_path.to_string_lossy().to_ascii_lowercase();
    let file_name = ctx.file_name.to_ascii_lowercase();
    let extension = ctx.extension.to_ascii_lowercase();
    let has_rule_match = ctx
        .findings
        .iter()
        .any(|finding| finding.code.contains("YARA"));
    let has_decode_or_emulation = ctx.findings.iter().any(|finding| {
        matches!(normalize_reason_source(&finding.code), "emulation")
            || finding.code.starts_with("DECODED_")
    });
    let has_strong_structural_signal = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "THREAT_INTEL_HASH_MATCH"
                | "PE_INJECTION_IMPORTS"
                | "PE_INJECTION_CHAIN"
                | "PE_MEMORY_PERMISSION_CHAIN"
                | "PE_PACKED_SECTION_LAYOUT"
                | "PE_EXECUTABLE_WRITABLE_SECTION"
                | "PE_SPARSE_SECTION_LAYOUT"
                | "PE_RESOURCE_SCRIPT_STAGE"
                | "PE_RESOURCE_LOADER_CHAIN"
                | "ZIP_EMBEDDED_EXECUTABLE"
                | "ELF_SHELL_DOWNLOADER"
                | "ELF_PACKED_SECTION_LAYOUT"
                | "ELF_DYNAMIC_LOADER_CHAIN"
                | "ELF_SELF_RELAUNCH_CHAIN"
                | "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "ELF_EXEC_NETWORK_SYMBOL_CHAIN"
                | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN"
        )
    });

    let benign_script_context = path_matches(
        &path_text,
        &[
            "/scripts/",
            "/script/",
            "/tools/",
            "/tooling/",
            "/build/",
            "/deploy/",
            "/ci/",
            "/ops/",
            "/automation/",
        ],
    ) || file_name.contains("deploy")
        || file_name.contains("build")
        || file_name.contains("backup")
        || file_name.contains("migrate")
        || file_name.contains("maintenance")
        || file_name.contains("admin");
    let installer_context = file_name.contains("setup")
        || file_name.contains("install")
        || file_name.contains("updat")
        || file_name.contains("bootstrap")
        || path_matches(&path_text, &["/install/", "/installer/", "/updates/"]);
    let office_document_context = matches!(
        extension.as_str(),
        "docm" | "dotm" | "xlsm" | "xltm" | "pptm" | "doc" | "xls" | "ppt"
    );
    let archive_context = matches!(extension.as_str(), "zip" | "jar" | "docx" | "xlsx" | "pptx");

    let adjusted = ctx
        .findings
        .iter()
        .map(|finding| {
            let adjusted = adjusted_weight(
                finding,
                benign_script_context,
                installer_context,
                office_document_context,
                archive_context,
                has_rule_match,
                has_decode_or_emulation,
                has_strong_structural_signal,
            );
            (normalize_reason_source(&finding.code).to_string(), adjusted)
        })
        .collect::<Vec<_>>();

    let strongest_signal = adjusted
        .iter()
        .map(|(_, weight)| *weight)
        .fold(0.0, f64::max);

    let mut per_source: HashMap<String, Vec<f64>> = HashMap::new();
    for (source, weight) in adjusted {
        if weight <= 0.0 {
            continue;
        }
        per_source.entry(source).or_default().push(weight);
    }

    let mut source_totals = per_source
        .values_mut()
        .map(|weights| {
            weights.sort_by(|left, right| right.partial_cmp(left).unwrap_or(Ordering::Equal));
            weights
                .iter()
                .enumerate()
                .map(|(idx, weight)| {
                    let decay = match idx {
                        0 => 1.0,
                        1 => 0.65,
                        2 => 0.4,
                        _ => 0.2,
                    };
                    weight * decay
                })
                .sum::<f64>()
        })
        .collect::<Vec<_>>();

    source_totals.sort_by(|left, right| right.partial_cmp(left).unwrap_or(Ordering::Equal));
    let base_score = source_totals
        .iter()
        .enumerate()
        .map(|(idx, total)| {
            let source_decay = match idx {
                0 => 1.0,
                1 => 0.85,
                2 => 0.7,
                _ => 0.5,
            };
            total * source_decay
        })
        .sum::<f64>();

    let corroborating_sources = source_totals.iter().filter(|total| **total >= 1.4).count();
    let diversity_bonus = ((corroborating_sources.saturating_sub(1)) as f64 * 0.45).min(1.35);
    let correlated_bonus = if strongest_signal >= 2.2 && corroborating_sources >= 2 {
        0.75
    } else if corroborating_sources >= 3 {
        0.55
    } else {
        0.0
    };
    let weak_signal_penalty = if strongest_signal < 1.5 { 0.65 } else { 0.0 };
    let single_source_noise_penalty =
        if source_totals.len() == 1 && ctx.findings.len() >= 3 && strongest_signal < 2.0 {
            0.55
        } else {
            0.0
        };
    let structural_content_bonus = if has_structural_content_corroboration(ctx) {
        0.55
    } else {
        0.0
    };

    (base_score + diversity_bonus + correlated_bonus + structural_content_bonus
        - weak_signal_penalty
        - single_source_noise_penalty)
        .clamp(0.0, 10.0)
}

fn adjusted_weight(
    finding: &Finding,
    benign_script_context: bool,
    installer_context: bool,
    office_document_context: bool,
    archive_context: bool,
    has_rule_match: bool,
    has_decode_or_emulation: bool,
    has_strong_structural_signal: bool,
) -> f64 {
    let mut weight = finding.weight.max(0.0);

    match finding.code.as_str() {
        "THREAT_INTEL_HASH_MATCH" => weight *= 1.1,
        "YARA_MATCH" => weight *= 1.2,
        "DECODED_ACTIVE_CONTENT" => weight *= 2.4,
        "DECODED_FOLLOW_ON_BEHAVIOR" => weight *= 1.3,
        "PE_INJECTION_IMPORTS" | "ZIP_EMBEDDED_EXECUTABLE" => weight *= 1.05,
        "PE_INJECTION_CHAIN" => weight *= 1.2,
        "PE_DYNAMIC_LOADER_IMPORTS" => weight *= 0.9,
        "PE_MEMORY_PERMISSION_CHAIN" => weight *= 1.05,
        "PE_PACKED_SECTION_LAYOUT" | "PE_EXECUTABLE_WRITABLE_SECTION" => weight *= 1.1,
        "PE_SPARSE_SECTION_LAYOUT" => weight *= 0.95,
        "PE_RESOURCE_SCRIPT_STAGE" | "PE_RESOURCE_LOADER_CHAIN" => weight *= 1.15,
        "PE_SCRIPTED_DOWNLOADER_STRINGS" | "PE_LAUNCHER_NETWORK_STRINGS" => weight *= 1.1,
        "ELF_PACKED_SECTION_LAYOUT" => weight *= 0.95,
        "ELF_DYNAMIC_LOADER_CHAIN" | "ELF_SELF_RELAUNCH_CHAIN" => weight *= 1.15,
        "ELF_DYNAMIC_SYMBOL_CHAIN" => weight *= 1.1,
        "ELF_EXEC_NETWORK_SYMBOL_CHAIN" | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN" => weight *= 1.05,
        "ELF_SHELL_DOWNLOADER" | "ELF_SHELL_NETWORK_CHAIN" => weight *= 1.15,
        "PSH_DOWNLOADER_CHAIN" | "JS_DOWNLOADER_CHAIN" | "VBA_AUTORUN_DOWNLOAD_CHAIN" => {
            weight *= 1.15
        }
        "ZIP_EMBEDDED_SCRIPT" => weight *= 0.75,
        "OFFICE_MACRO" => weight *= if office_document_context { 0.8 } else { 0.95 },
        "OFFICE_MACRO_CONTAINER" => weight *= 0.55,
        "ZIP_DENSE" | "ZIP_NESTED_ARCHIVES" => weight *= 0.55,
        "RESOURCE_ARCHIVE_ENTRY_LIMIT" | "RESOURCE_DECOMPRESS_LIMIT" => weight *= 0.5,
        "ZIP_SUSPICIOUS_ENTRIES" => weight *= 0.8,
        "FILE_SMALL" => weight *= 0.6,
        "HIGH_ENTROPY" => weight *= 0.8,
        "PE_EMBEDDED_POWERSHELL" => weight *= 0.6,
        "ELF_SHELL" => weight *= 0.55,
        "ML_HIGH_RISK"
            if !has_rule_match && !has_decode_or_emulation && !has_strong_structural_signal =>
        {
            weight *= 0.7;
        }
        _ => {}
    }

    if benign_script_context
        && matches!(
            finding.code.as_str(),
            "PSH_SUSPICIOUS"
                | "JS_SUSPICIOUS"
                | "VBA_SUSPICIOUS"
                | "BAT_SUSPICIOUS"
                | "SCRIPT_CHARCODE_OBFUSCATION"
                | "SCRIPT_CONCAT_EVAL"
        )
        && !has_rule_match
        && !has_decode_or_emulation
    {
        weight *= 0.65;
    }

    if installer_context
        && matches!(
            finding.code.as_str(),
            "FILE_SMALL" | "HIGH_ENTROPY" | "PE_EMBEDDED_POWERSHELL"
        )
        && !has_strong_structural_signal
    {
        weight *= 0.7;
    }

    if archive_context
        && matches!(
            finding.code.as_str(),
            "ZIP_DENSE"
                | "ZIP_NESTED_ARCHIVES"
                | "ZIP_EMBEDDED_SCRIPT"
                | "RESOURCE_ARCHIVE_ENTRY_LIMIT"
                | "RESOURCE_DECOMPRESS_LIMIT"
                | "ZIP_SUSPICIOUS_ENTRIES"
                | "EMBEDDED_SCRIPT_MARKERS"
        )
        && !has_rule_match
        && !has_decode_or_emulation
        && !has_strong_structural_signal
    {
        weight *= 0.75;
    }

    weight
}

fn path_matches(path: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| path.contains(needle))
}

fn has_structural_content_corroboration(ctx: &ScanContext) -> bool {
    let has_pe_structure = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "PE_INJECTION_CHAIN"
                | "PE_DYNAMIC_LOADER_IMPORTS"
                | "PE_MEMORY_PERMISSION_CHAIN"
                | "PE_PACKED_SECTION_LAYOUT"
                | "PE_EXECUTABLE_WRITABLE_SECTION"
                | "PE_SPARSE_SECTION_LAYOUT"
                | "PE_RESOURCE_SCRIPT_STAGE"
                | "PE_RESOURCE_LOADER_CHAIN"
        )
    });
    let has_pe_content = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "PE_SCRIPTED_DOWNLOADER_STRINGS" | "PE_LAUNCHER_NETWORK_STRINGS" | "YARA_MATCH"
        )
    });
    let has_elf_structure = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "ELF_DYNAMIC_LOADER_CHAIN"
                | "ELF_SELF_RELAUNCH_CHAIN"
                | "ELF_PACKED_SECTION_LAYOUT"
                | "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "ELF_EXEC_NETWORK_SYMBOL_CHAIN"
                | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN"
        )
    });
    let has_elf_content = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "ELF_SHELL_DOWNLOADER" | "ELF_SHELL_NETWORK_CHAIN" | "YARA_MATCH"
        )
    });

    (has_pe_structure && has_pe_content) || (has_elf_structure && has_elf_content)
}

#[cfg(test)]
mod tests {
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;
    use crate::r#static::types::Finding;

    use super::calculate;

    fn context_for(path_name: &str) -> ScanContext {
        let root = std::env::temp_dir().join(format!("projectx_score_{}", std::process::id()));
        let path = root.join(path_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, b"placeholder").unwrap();
        ScanContext::from_path(&path, ScanConfig::default()).unwrap()
    }

    #[test]
    fn archive_noise_does_not_cross_suspicious_threshold_on_its_own() {
        let mut ctx = context_for("benign/archive/sample.zip");
        ctx.push_finding(Finding::new("ZIP_DENSE", "Archive is unusually dense", 1.5));
        ctx.push_finding(Finding::new(
            "ZIP_NESTED_ARCHIVES",
            "Archive appears to contain multiple nested archive layers",
            1.0,
        ));
        ctx.push_finding(Finding::new(
            "RESOURCE_ARCHIVE_ENTRY_LIMIT",
            "Archive inspection stopped after many entries",
            1.0,
        ));

        assert!(calculate(&ctx) < 3.5);
    }

    #[test]
    fn benign_admin_script_context_dampens_script_only_signals() {
        let mut ctx = context_for("ops/deploy/admin_maintenance.ps1");
        ctx.push_finding(Finding::new("PSH_SUSPICIOUS", "PowerShell suspicious", 2.0));
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "Script builds code from string fragments before evaluating it",
            1.5,
        ));
        ctx.push_finding(Finding::new(
            "SCRIPT_CHARCODE_OBFUSCATION",
            "Script reconstructs text from character codes, which often hides intent",
            1.0,
        ));

        assert!(calculate(&ctx) < 3.5);
    }

    #[test]
    fn mixed_source_signals_gain_corroboration_bonus() {
        let mut ctx = context_for("downloads/sample.bin");
        ctx.push_finding(Finding::new(
            "PE_INJECTION_IMPORTS",
            "imports injection APIs",
            2.5,
        ));
        ctx.push_finding(Finding::new(
            "YARA_MATCH",
            "Local rule matched: suspicious.pe_injection_combo in strings",
            2.0,
        ));
        ctx.push_finding(Finding::new(
            "EMULATION_PS_DECODED",
            "Decoded script content looks suspicious",
            1.5,
        ));

        assert!(calculate(&ctx) >= 6.0);
    }
}
