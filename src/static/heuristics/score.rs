use std::cmp::Ordering;
use std::collections::HashMap;

use crate::r#static::context::ScanContext;
use crate::r#static::report::normalize_reason_source;
use crate::r#static::types::{Finding, IntelligenceRecord};

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
    let has_bad_reputation = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "REPUTATION_KNOWN_BAD_HASH" | "THREAT_INTEL_HASH_MATCH"
        )
    });
    let trust_signal_strength = applicable_trust_strength(ctx);
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
                | "PE_ENTRYPOINT_IN_PACKED_SECTION"
                | "PE_ENTRYPOINT_IN_WRITABLE_EXECUTABLE_SECTION"
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
                | "ELF_STATIC_SYMBOL_LOADER_CHAIN"
                | "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN"
                | "ELF_EXEC_NETWORK_SYMBOL_CHAIN"
                | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN"
                | "MACHO_PACKED_SECTION_LAYOUT"
                | "MACHO_EXECUTABLE_WRITABLE_SEGMENT"
                | "MACHO_DYNAMIC_LOADER_CHAIN"
                | "MACHO_EXEC_NETWORK_CHAIN"
                | "MACHO_RELATIVE_LOADER_PATH_CHAIN"
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
    let framework_bundle_context = matches!(extension.as_str(), "js" | "mjs" | "cjs")
        && (file_name.contains("bundle")
            || file_name.contains("chunk")
            || file_name.contains(".min.")
            || path_matches(
                &path_text,
                &[
                    "/dist/",
                    "/build/",
                    "/assets/",
                    "/node_modules/",
                    "/vendor/",
                ],
            ));
    let package_workflow_context = path_matches(
        &path_text,
        &[
            "/node_modules/",
            "/site-packages/",
            "/cellar/",
            "/winget/",
            "/packages/",
            "/.cargo/",
            "/.npm/",
            "/pnpm-store/",
        ],
    ) || file_name.contains("package")
        || file_name.contains("manifest")
        || file_name.contains("lock");
    let automation_context = path_matches(
        &path_text,
        &[
            "/.github/workflows/",
            "/pipelines/",
            "/automation/",
            "/ci/",
            "/ops/",
        ],
    ) || file_name.contains("workflow")
        || file_name.contains("pipeline")
        || file_name.contains("runner");
    let benign_encoded_context = path_matches(
        &path_text,
        &[
            "/encoded/",
            "/config/",
            "/templates/",
            "/assets/",
            "/fixtures/",
        ],
    ) || matches!(
        extension.as_str(),
        "json" | "yaml" | "yml" | "toml" | "xml" | "txt" | "map"
    ) && (file_name.contains("config")
        || file_name.contains("template")
        || file_name.contains("flags")
        || file_name.contains("manifest")
        || file_name.contains("blob"));
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
                framework_bundle_context,
                package_workflow_context,
                automation_context,
                benign_encoded_context,
                office_document_context,
                archive_context,
                has_rule_match,
                has_decode_or_emulation,
                has_strong_structural_signal,
                has_bad_reputation,
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
    let near_threshold_noise_penalty =
        if strongest_signal < 2.2 && corroborating_sources <= 1 && ctx.findings.len() >= 2 {
            0.35
        } else {
            0.0
        };
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
    let reputation_bonus = if has_bad_reputation { 0.95 } else { 0.0 };
    let trust_penalty = if trust_signal_strength <= 0.0 || has_bad_reputation {
        0.0
    } else if has_rule_match || has_decode_or_emulation {
        (trust_signal_strength * 0.18).min(0.55)
    } else if has_strong_structural_signal {
        (trust_signal_strength * 0.22).min(0.7)
    } else {
        (trust_signal_strength * 0.45).min(1.35)
    };

    (base_score + diversity_bonus + correlated_bonus + structural_content_bonus + reputation_bonus
        - weak_signal_penalty
        - near_threshold_noise_penalty
        - single_source_noise_penalty
        - trust_penalty)
        .clamp(0.0, 10.0)
}

#[allow(clippy::too_many_arguments)]
fn adjusted_weight(
    finding: &Finding,
    benign_script_context: bool,
    installer_context: bool,
    framework_bundle_context: bool,
    package_workflow_context: bool,
    automation_context: bool,
    benign_encoded_context: bool,
    office_document_context: bool,
    archive_context: bool,
    has_rule_match: bool,
    has_decode_or_emulation: bool,
    has_strong_structural_signal: bool,
    has_bad_reputation: bool,
) -> f64 {
    let mut weight = finding.weight.max(0.0);

    match finding.code.as_str() {
        "THREAT_INTEL_HASH_MATCH" | "REPUTATION_KNOWN_BAD_HASH" => {
            weight *= confidence_factor_from_message(&finding.message, 1.15)
        }
        "YARA_MATCH" if finding.message.contains("[high confidence]") => weight *= 1.35,
        "YARA_MATCH" if finding.message.contains("[low confidence]") => weight *= 0.85,
        "YARA_MATCH" => weight *= 1.2,
        "DECODED_ACTIVE_CONTENT" => weight *= 2.4,
        "DECODED_FOLLOW_ON_BEHAVIOR" => weight *= 1.3,
        "PE_INJECTION_IMPORTS" | "ZIP_EMBEDDED_EXECUTABLE" => weight *= 1.05,
        "PE_INJECTION_CHAIN" => weight *= 1.2,
        "PE_DYNAMIC_LOADER_IMPORTS" => weight *= 0.9,
        "PE_MEMORY_PERMISSION_CHAIN" => weight *= 1.05,
        "PE_ENTRYPOINT_IN_PACKED_SECTION" | "PE_ENTRYPOINT_IN_WRITABLE_EXECUTABLE_SECTION" => {
            weight *= 1.12
        }
        "PE_PACKED_SECTION_LAYOUT" | "PE_EXECUTABLE_WRITABLE_SECTION" => weight *= 1.1,
        "PE_SPARSE_SECTION_LAYOUT" => weight *= 0.95,
        "PE_RESOURCE_SCRIPT_STAGE" | "PE_RESOURCE_LOADER_CHAIN" => weight *= 1.15,
        "PE_SCRIPTED_DOWNLOADER_STRINGS" | "PE_LAUNCHER_NETWORK_STRINGS" => weight *= 1.1,
        "ELF_PACKED_SECTION_LAYOUT" => weight *= 0.95,
        "ELF_DYNAMIC_LOADER_CHAIN" | "ELF_SELF_RELAUNCH_CHAIN" => weight *= 1.15,
        "ELF_DYNAMIC_SYMBOL_CHAIN" => weight *= 1.1,
        "ELF_STATIC_SYMBOL_LOADER_CHAIN" | "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN" => weight *= 1.08,
        "ELF_EXEC_NETWORK_SYMBOL_CHAIN" | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN" => weight *= 1.05,
        "ELF_SHELL_DOWNLOADER" | "ELF_SHELL_NETWORK_CHAIN" => weight *= 1.15,
        "MACHO_PACKED_SECTION_LAYOUT" => weight *= 0.95,
        "MACHO_EXECUTABLE_WRITABLE_SEGMENT" => weight *= 1.1,
        "MACHO_DYNAMIC_LOADER_CHAIN"
        | "MACHO_EXEC_NETWORK_CHAIN"
        | "MACHO_RELATIVE_LOADER_PATH_CHAIN" => weight *= 1.15,
        "PSH_DOWNLOADER_CHAIN" | "JS_DOWNLOADER_CHAIN" | "VBA_AUTORUN_DOWNLOAD_CHAIN" => {
            weight *= 1.15
        }
        "ZIP_EMBEDDED_SCRIPT" => weight *= 0.75,
        "OFFICE_MACRO" => weight *= if office_document_context { 0.8 } else { 0.95 },
        "OFFICE_MACRO_CONTAINER" => weight *= 0.55,
        "ZIP_DENSE" | "ZIP_NESTED_ARCHIVES" => weight *= 0.55,
        "RESOURCE_ARCHIVE_ENTRY_LIMIT" | "RESOURCE_DECOMPRESS_LIMIT" => weight *= 0.5,
        "ZIP_SUSPICIOUS_ENTRIES" => weight *= 0.8,
        "TRUST_ALLOWLIST_HASH"
        | "TRUST_FRAMEWORK_FINGERPRINT"
        | "TRUST_BENIGN_TOOLING_CONTEXT"
        | "TRUST_PACKAGE_MANAGER_CONTEXT" => weight = 0.0,
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

    if framework_bundle_context
        && matches!(
            finding.code.as_str(),
            "JS_SUSPICIOUS" | "SCRIPT_CONCAT_EVAL" | "SCRIPT_CHARCODE_OBFUSCATION" | "HIGH_ENTROPY"
        )
        && !has_rule_match
        && !has_decode_or_emulation
    {
        weight *= 0.6;
    }

    if package_workflow_context
        && matches!(
            finding.code.as_str(),
            "PE_DYNAMIC_LOADER_IMPORTS"
                | "PE_SPARSE_SECTION_LAYOUT"
                | "ELF_DYNAMIC_LOADER_CHAIN"
                | "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "MACHO_DYNAMIC_LOADER_CHAIN"
                | "FILE_SMALL"
                | "HIGH_ENTROPY"
                | "ZIP_DENSE"
        )
        && !has_rule_match
        && !has_decode_or_emulation
        && !has_bad_reputation
    {
        weight *= 0.65;
    }

    if automation_context
        && matches!(
            finding.code.as_str(),
            "PSH_SUSPICIOUS"
                | "BAT_SUSPICIOUS"
                | "SCRIPT_CONCAT_EVAL"
                | "SCRIPT_CHARCODE_OBFUSCATION"
                | "HIGH_ENTROPY"
        )
        && !has_rule_match
        && !has_decode_or_emulation
        && !has_strong_structural_signal
    {
        weight *= 0.6;
    }

    if benign_encoded_context
        && matches!(
            finding.code.as_str(),
            "HIGH_ENTROPY"
                | "FILE_SMALL"
                | "SCRIPT_CHARCODE_OBFUSCATION"
                | "EMBEDDED_SCRIPT_MARKERS"
                | "ZIP_SUSPICIOUS_ENTRIES"
        )
        && !has_rule_match
        && !has_decode_or_emulation
        && !has_strong_structural_signal
    {
        weight *= 0.55;
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

    if has_bad_reputation
        && matches!(
            finding.code.as_str(),
            "PE_INJECTION_CHAIN"
                | "PE_RESOURCE_SCRIPT_STAGE"
                | "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN"
                | "MACHO_DYNAMIC_LOADER_CHAIN"
                | "MACHO_RELATIVE_LOADER_PATH_CHAIN"
                | "DECODED_FOLLOW_ON_BEHAVIOR"
                | "YARA_MATCH"
        )
    {
        weight *= 1.08;
    }

    weight
}

fn confidence_factor_from_message(message: &str, default: f64) -> f64 {
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("[high confidence]") || lowered.contains("[high trust]") {
        1.2
    } else if lowered.contains("[low confidence]") || lowered.contains("[low trust]") {
        0.75
    } else {
        default
    }
}

fn applicable_trust_strength(ctx: &ScanContext) -> f64 {
    let Some(summary) = &ctx.intelligence else {
        return 0.0;
    };

    summary
        .records
        .iter()
        .filter(|record| is_trust_record(record))
        .filter(|record| {
            ctx.findings.iter().any(|finding| {
                !is_intelligence_finding(finding)
                    && finding.weight > 0.0
                    && trust_record_matches_finding(record, finding)
            })
        })
        .map(trust_record_strength)
        .sum()
}

fn is_trust_record(record: &IntelligenceRecord) -> bool {
    matches!(
        record.kind.as_str(),
        "known_good_hash"
            | "framework_fingerprint"
            | "trusted_vendor_context"
            | "trusted_tooling_context"
            | "package_manager_context"
    )
}

fn is_intelligence_finding(finding: &Finding) -> bool {
    matches!(
        finding.code.as_str(),
        "TRUST_ALLOWLIST_HASH"
            | "TRUST_FRAMEWORK_FINGERPRINT"
            | "TRUST_BENIGN_TOOLING_CONTEXT"
            | "TRUST_PACKAGE_MANAGER_CONTEXT"
            | "REPUTATION_KNOWN_BAD_HASH"
            | "THREAT_INTEL_HASH_MATCH"
    )
}

fn trust_record_strength(record: &IntelligenceRecord) -> f64 {
    let tier = match record
        .trust_level
        .as_deref()
        .unwrap_or(record.confidence.as_str())
    {
        "high" => 1.2,
        "low" => 0.7,
        _ => 1.0,
    };
    let weight = record.confidence_weight.unwrap_or(1.0).clamp(0.5, 1.4);
    let score = record.confidence_score.unwrap_or(1.0).clamp(0.5, 1.3);
    let quality = record.source_quality.unwrap_or(1.0).clamp(0.5, 1.3);
    let decay = record.decay_factor.unwrap_or(1.0).clamp(0.3, 1.0);
    (tier * weight * score * quality * decay).clamp(0.3, 1.8)
}

fn trust_record_matches_finding(record: &IntelligenceRecord, finding: &Finding) -> bool {
    if record.allowed_dampen.is_empty() {
        return matches!(
            normalize_reason_source(&finding.code),
            "script" | "file" | "format"
        );
    }

    let source = normalize_reason_source(&finding.code);
    record
        .allowed_dampen
        .iter()
        .any(|scope| trust_scope_matches(scope, source, finding))
}

fn trust_scope_matches(scope: &str, source: &str, finding: &Finding) -> bool {
    match scope {
        "weak_noise" => finding.weight <= 1.5,
        "framework_bundle_noise" => {
            source == "script"
                && matches!(
                    finding.code.as_str(),
                    "JS_SUSPICIOUS" | "SCRIPT_CONCAT_EVAL" | "SCRIPT_CHARCODE_OBFUSCATION"
                )
        }
        "script_noise" => {
            source == "script"
                && matches!(
                    finding.code.as_str(),
                    "PSH_SUSPICIOUS"
                        | "JS_SUSPICIOUS"
                        | "VBA_SUSPICIOUS"
                        | "BAT_SUSPICIOUS"
                        | "SCRIPT_CONCAT_EVAL"
                        | "SCRIPT_CHARCODE_OBFUSCATION"
                )
        }
        "entropy_noise" => matches!(finding.code.as_str(), "HIGH_ENTROPY" | "FILE_SMALL"),
        "archive_noise" => matches!(
            finding.code.as_str(),
            "ZIP_DENSE"
                | "ZIP_NESTED_ARCHIVES"
                | "ZIP_EMBEDDED_SCRIPT"
                | "RESOURCE_ARCHIVE_ENTRY_LIMIT"
                | "RESOURCE_DECOMPRESS_LIMIT"
                | "ZIP_SUSPICIOUS_ENTRIES"
        ),
        "file_profile_noise" => matches!(
            finding.code.as_str(),
            "FILE_SMALL" | "HIGH_ENTROPY" | "MAGIC_MISMATCH"
        ),
        "binary_loader_noise" => matches!(
            finding.code.as_str(),
            "PE_DYNAMIC_LOADER_IMPORTS"
                | "PE_SPARSE_SECTION_LAYOUT"
                | "ELF_DYNAMIC_LOADER_CHAIN"
                | "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "MACHO_DYNAMIC_LOADER_CHAIN"
        ),
        _ => false,
    }
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
                | "PE_ENTRYPOINT_IN_PACKED_SECTION"
                | "PE_ENTRYPOINT_IN_WRITABLE_EXECUTABLE_SECTION"
                | "PE_EXECUTABLE_WRITABLE_SECTION"
                | "PE_SPARSE_SECTION_LAYOUT"
                | "PE_RESOURCE_SCRIPT_STAGE"
                | "PE_RESOURCE_LOADER_CHAIN"
        )
    });
    let has_pe_content = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "PE_SCRIPTED_DOWNLOADER_STRINGS"
                | "PE_LAUNCHER_NETWORK_STRINGS"
                | "YARA_MATCH"
                | "DECODED_ACTIVE_CONTENT"
                | "DECODED_FOLLOW_ON_BEHAVIOR"
        )
    });
    let has_elf_structure = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "ELF_DYNAMIC_LOADER_CHAIN"
                | "ELF_SELF_RELAUNCH_CHAIN"
                | "ELF_PACKED_SECTION_LAYOUT"
                | "ELF_DYNAMIC_SYMBOL_CHAIN"
                | "ELF_STATIC_SYMBOL_LOADER_CHAIN"
                | "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN"
                | "ELF_EXEC_NETWORK_SYMBOL_CHAIN"
                | "ELF_SELF_RELAUNCH_SYMBOL_CHAIN"
        )
    });
    let has_elf_content = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "ELF_SHELL_DOWNLOADER"
                | "ELF_SHELL_NETWORK_CHAIN"
                | "YARA_MATCH"
                | "DECODED_ACTIVE_CONTENT"
                | "DECODED_FOLLOW_ON_BEHAVIOR"
        )
    });
    let has_macho_structure = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "MACHO_PACKED_SECTION_LAYOUT"
                | "MACHO_EXECUTABLE_WRITABLE_SEGMENT"
                | "MACHO_DYNAMIC_LOADER_CHAIN"
                | "MACHO_EXEC_NETWORK_CHAIN"
                | "MACHO_RELATIVE_LOADER_PATH_CHAIN"
        )
    });
    let has_macho_content = ctx.findings.iter().any(|finding| {
        matches!(
            finding.code.as_str(),
            "YARA_MATCH" | "DECODED_ACTIVE_CONTENT" | "DECODED_FOLLOW_ON_BEHAVIOR"
        )
    });

    (has_pe_structure && has_pe_content)
        || (has_elf_structure && has_elf_content)
        || (has_macho_structure && has_macho_content)
}

#[cfg(test)]
mod tests {
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;
    use crate::r#static::types::{Finding, IntelligenceRecord, IntelligenceSummary};

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

    #[test]
    fn decoded_follow_on_behavior_supports_cross_format_structural_corroboration() {
        let mut ctx = context_for("downloads/sample.dylib");
        ctx.push_finding(Finding::new(
            "MACHO_DYNAMIC_LOADER_CHAIN",
            "Linked libraries and loader cues",
            2.4,
        ));
        ctx.push_finding(Finding::new(
            "DECODED_FOLLOW_ON_BEHAVIOR",
            "Decoded follow-on behavior",
            2.0,
        ));

        assert!(calculate(&ctx) >= 3.25);
    }

    #[test]
    fn trust_allowlist_dampens_weak_binary_noise() {
        let mut ctx = context_for("build/framework_chunk.js");
        ctx.intelligence = Some(IntelligenceSummary {
            records: vec![IntelligenceRecord {
                kind: "framework_fingerprint".to_string(),
                category: "frontend_framework".to_string(),
                source: "unit_test".to_string(),
                confidence: "high".to_string(),
                trust_level: Some("high".to_string()),
                note: "Trusted framework".to_string(),
                platform: None,
                version: None,
                expires: None,
                allowed_dampen: vec![
                    "framework_bundle_noise".to_string(),
                    "script_noise".to_string(),
                ],
                matched_markers: vec!["framework".to_string()],
                vendor: None,
                ecosystem: Some("npm".to_string()),
                rationale: None,
                version_range: None,
                typical_files: Vec::new(),
                signer_hint: None,
                package_source: None,
                distribution_channel: None,
                confidence_weight: Some(1.2),
                trust_scope: Vec::new(),
                confidence_score: Some(1.0),
                source_quality: Some(1.0),
                last_verified: Some("2026-04-01".to_string()),
                decay_factor: Some(1.0),
            }],
            ..IntelligenceSummary::default()
        });
        ctx.push_finding(Finding::new(
            "TRUST_FRAMEWORK_FINGERPRINT",
            "Trusted framework fingerprint",
            0.0,
        ));
        ctx.push_finding(Finding::new(
            "JS_SUSPICIOUS",
            "Suspicious JavaScript pattern",
            1.9,
        ));
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "Script builds code from string fragments before evaluating it",
            1.5,
        ));

        assert!(calculate(&ctx) < 3.5);
    }

    #[test]
    fn trust_does_not_flatten_strong_rule_and_structure_corroboration() {
        let mut ctx = context_for("build/updater_loader.exe");
        ctx.intelligence = Some(IntelligenceSummary {
            records: vec![IntelligenceRecord {
                kind: "trusted_vendor_context".to_string(),
                category: "package_vendor".to_string(),
                source: "unit_test".to_string(),
                confidence: "medium".to_string(),
                trust_level: Some("medium".to_string()),
                note: "Trusted package metadata".to_string(),
                platform: Some("windows".to_string()),
                version: None,
                expires: None,
                allowed_dampen: vec!["binary_loader_noise".to_string()],
                matched_markers: vec!["winget package".to_string()],
                vendor: Some("Microsoft".to_string()),
                ecosystem: Some("windows_package".to_string()),
                rationale: None,
                version_range: None,
                typical_files: Vec::new(),
                signer_hint: Some("Microsoft Corporation".to_string()),
                package_source: Some("winget".to_string()),
                distribution_channel: Some("stable".to_string()),
                confidence_weight: Some(1.0),
                trust_scope: vec!["binary_loader_noise".to_string()],
                confidence_score: Some(0.9),
                source_quality: Some(0.9),
                last_verified: Some("2026-04-01".to_string()),
                decay_factor: Some(1.0),
            }],
            ..IntelligenceSummary::default()
        });
        ctx.push_finding(Finding::new(
            "TRUST_BENIGN_TOOLING_CONTEXT",
            "Trusted package metadata [medium trust] [package_vendor via unit_test] (winget package)",
            0.0,
        ));
        ctx.push_finding(Finding::new(
            "PE_INJECTION_CHAIN",
            "Parsed imports indicate a memory injection chain",
            2.8,
        ));
        ctx.push_finding(Finding::new(
            "YARA_MATCH",
            "Local rule matched [high confidence]: suspicious_pe_injection_combo family pe_injection; literals VirtualAlloc, CreateRemoteThread in strings",
            2.5,
        ));

        assert!(calculate(&ctx) >= 5.5);
    }

    #[test]
    fn known_bad_reputation_increases_confidence() {
        let mut ctx = context_for("samples/loader.exe");
        ctx.push_finding(Finding::new(
            "REPUTATION_KNOWN_BAD_HASH",
            "Known-bad hash",
            3.1,
        ));
        ctx.push_finding(Finding::new(
            "PE_DYNAMIC_LOADER_IMPORTS",
            "Parsed imports dynamically load libraries",
            1.7,
        ));

        assert!(calculate(&ctx) > 4.0);
    }

    #[test]
    fn framework_bundle_context_dampens_generic_script_noise() {
        let mut ctx = context_for("frontend/dist/app.bundle.min.js");
        ctx.push_finding(Finding::new("JS_SUSPICIOUS", "Suspicious JavaScript", 1.9));
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "Script builds code from string fragments before evaluating it",
            1.5,
        ));
        ctx.push_finding(Finding::new("HIGH_ENTROPY", "Entropy elevated", 1.1));

        assert!(calculate(&ctx) < 3.25);
    }

    #[test]
    fn package_workflow_context_dampens_weak_loader_noise() {
        let mut ctx = context_for("packages/winget/package_manifest.exe");
        ctx.push_finding(Finding::new(
            "PE_DYNAMIC_LOADER_IMPORTS",
            "Dynamic loader imports",
            1.8,
        ));
        ctx.push_finding(Finding::new(
            "PE_SPARSE_SECTION_LAYOUT",
            "Sparse layout",
            1.4,
        ));
        ctx.push_finding(Finding::new("HIGH_ENTROPY", "Entropy elevated", 1.0));

        assert!(calculate(&ctx) < 3.5);
    }

    #[test]
    fn automation_pipeline_context_dampens_weak_script_noise() {
        let mut ctx = context_for(".github/workflows/build_pipeline.ps1");
        ctx.push_finding(Finding::new("PSH_SUSPICIOUS", "PowerShell suspicious", 1.9));
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "Script builds code from string fragments before evaluating it",
            1.4,
        ));
        ctx.push_finding(Finding::new("HIGH_ENTROPY", "Entropy elevated", 1.1));

        assert!(calculate(&ctx) < 3.25);
    }

    #[test]
    fn benign_encoded_config_context_dampens_entropy_style_noise() {
        let mut ctx = context_for("fixtures/encoded/config_blob.txt");
        ctx.push_finding(Finding::new("HIGH_ENTROPY", "Entropy elevated", 1.3));
        ctx.push_finding(Finding::new(
            "EMBEDDED_SCRIPT_MARKERS",
            "Archive entry contains script-like markers",
            1.2,
        ));
        ctx.push_finding(Finding::new("FILE_SMALL", "Very small file", 0.9));

        assert!(calculate(&ctx) < 3.0);
    }
}
