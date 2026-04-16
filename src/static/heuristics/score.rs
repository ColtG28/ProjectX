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
    let json_data_context = matches!(extension.as_str(), "json" | "json5" | "map" | "har")
        || ctx.sniffed_mime.contains("json")
        || file_name.ends_with(".json")
        || file_name.contains("manifest")
        || file_name.contains("package-lock")
        || file_name.contains("tsconfig")
        || file_name.contains("composer.lock")
        || file_name.contains("pnpm-lock")
        || file_name.contains("yarn.lock");
    let archive_context = matches!(extension.as_str(), "zip" | "jar" | "docx" | "xlsx" | "pptx");
    let media_container_context = matches!(
        extension.as_str(),
        "mp4" | "m4v" | "mov" | "avi" | "mkv" | "webm" | "mp3" | "m4a"
    ) || ctx.sniffed_mime.starts_with("video/")
        || ctx.sniffed_mime.starts_with("audio/")
        || matches!(ctx.detected_format.as_deref(), Some("MediaContainer"));

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
                json_data_context,
                archive_context,
                media_container_context,
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
    json_data_context: bool,
    archive_context: bool,
    media_container_context: bool,
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

    if json_data_context
        && matches!(finding.code.as_str(), "DECODED_ACTIVE_CONTENT")
        && !has_rule_match
        && !has_strong_structural_signal
        && !has_bad_reputation
    {
        weight *= 0.14;
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

    if media_container_context
        && matches!(
            finding.code.as_str(),
            "DECODED_ACTIVE_CONTENT" | "DECODED_FOLLOW_ON_BEHAVIOR" | "HIGH_ENTROPY" | "FILE_SMALL"
        )
        && !has_rule_match
        && !has_strong_structural_signal
        && !has_bad_reputation
    {
        weight *= match finding.code.as_str() {
            "DECODED_ACTIVE_CONTENT" => 0.12,
            "DECODED_FOLLOW_ON_BEHAVIOR" => 0.4,
            "HIGH_ENTROPY" => 0.35,
            "FILE_SMALL" => 0.5,
            _ => 1.0,
        };
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
    use super::*;
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;
    use crate::r#static::heuristics::decision;
    use crate::r#static::types::{Finding, Score, Severity, StringPool};
    use std::path::PathBuf;

    fn test_ctx(path: &str, extension: &str, mime: &str, format: Option<&str>) -> ScanContext {
        ScanContext {
            input_path: PathBuf::from(path),
            file_name: PathBuf::from(path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            extension: extension.to_string(),
            original_size_bytes: 1024,
            input_truncated: false,
            bytes: Vec::new(),
            sha256: "0".repeat(64),
            sniffed_mime: mime.to_string(),
            detected_format: format.map(str::to_string),
            normalized_strings: Vec::new(),
            decoded_strings: Vec::new(),
            score: Score::default(),
            findings: Vec::new(),
            views: Vec::new(),
            strings: StringPool::default(),
            stage_timings: Vec::new(),
            artifacts: Vec::new(),
            telemetry: Vec::new(),
            cache: None,
            rules_version: String::new(),
            emulation: None,
            intelligence: None,
            ml_assessment: None,
            threat_severity: None,
            config: ScanConfig::default(),
        }
    }

    #[test]
    fn weak_decoded_noise_is_dampened_for_media_containers() {
        let mut media = test_ctx(
            "/Users/test/Videos/obs-clip.mp4",
            "mp4",
            "video/mp4",
            Some("MediaContainer"),
        );
        media.findings.push(Finding::new(
            "DECODED_ACTIVE_CONTENT",
            "accidental decoded string noise",
            1.8,
        ));
        media.findings.push(Finding::new(
            "DECODED_FOLLOW_ON_BEHAVIOR",
            "single weak follow-on marker",
            1.6,
        ));

        let risk = calculate(&media);
        let verdict = decision::classify(&media, risk, &media.config.thresholds);

        assert!(risk < media.config.thresholds.suspicious_min);
        assert_eq!(verdict, Severity::Clean);
    }

    #[test]
    fn corroborated_non_media_signals_still_escalate() {
        let mut script = test_ctx("/tmp/dropper.ps1", "ps1", "text/plain", None);
        script.findings.push(Finding::new(
            "DECODED_ACTIVE_CONTENT",
            "decoded powershell command",
            2.0,
        ));
        script
            .findings
            .push(Finding::new("YARA_MATCH", "rule match", 2.2));
        script.findings.push(Finding::new(
            "PE_SCRIPTED_DOWNLOADER_STRINGS",
            "network downloader strings",
            1.8,
        ));

        let risk = calculate(&script);
        let verdict = decision::classify(&script, risk, &script.config.thresholds);

        assert!(risk >= script.config.thresholds.suspicious_min);
        assert_ne!(verdict, Severity::Clean);
    }

    #[test]
    fn weak_decoded_noise_is_dampened_for_json_data_files() {
        let mut json = test_ctx(
            "/Users/test/AppData/package-lock.json",
            "json",
            "application/json",
            None,
        );
        json.findings.push(Finding::new(
            "DECODED_ACTIVE_CONTENT",
            "accidental decoded marker in dependency metadata",
            1.8,
        ));

        let risk = calculate(&json);
        let verdict = decision::classify(&json, risk, &json.config.thresholds);

        assert!(risk < json.config.thresholds.suspicious_min);
        assert_eq!(verdict, Severity::Clean);
    }

    #[test]
    fn corroborated_json_findings_can_still_escalate() {
        let mut json = test_ctx(
            "/tmp/suspicious/package-lock.json",
            "json",
            "application/json",
            None,
        );
        json.findings.push(Finding::new(
            "DECODED_ACTIVE_CONTENT",
            "decoded network marker",
            1.8,
        ));
        json.findings
            .push(Finding::new("YARA_MATCH", "suspicious rule hit", 2.4));

        let risk = calculate(&json);
        let verdict = decision::classify(&json, risk, &json.config.thresholds);

        assert!(risk >= json.config.thresholds.suspicious_min);
        assert_ne!(verdict, Severity::Clean);
    }

    #[test]
    fn trust_context_does_not_override_strong_corroborated_signals() {
        let mut script = test_ctx(
            "/opt/homebrew/Cellar/example/bin/suspicious.sh",
            "sh",
            "text/plain",
            None,
        );
        script.findings.push(Finding::new(
            "TRUST_PACKAGE_MANAGER_CONTEXT",
            "homebrew layout",
            0.0,
        ));
        script
            .findings
            .push(Finding::new("YARA_MATCH", "matched suspicious rule", 2.5));
        script.findings.push(Finding::new(
            "DECODED_FOLLOW_ON_BEHAVIOR",
            "follow-on shell behavior",
            2.0,
        ));
        script.findings.push(Finding::new(
            "ELF_EXEC_NETWORK_SYMBOL_CHAIN",
            "network exec chain",
            2.4,
        ));

        let risk = calculate(&script);
        let verdict = decision::classify(&script, risk, &script.config.thresholds);

        assert!(risk >= script.config.thresholds.suspicious_min);
        assert_ne!(verdict, Severity::Clean);
    }
}
