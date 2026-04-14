use std::collections::HashSet;

use crate::r#static::config::Thresholds;
use crate::r#static::context::ScanContext;
use crate::r#static::report::normalize_reason_source;
use crate::r#static::types::Severity;

pub fn classify(ctx: &ScanContext, risk: f64, thresholds: &Thresholds) -> Severity {
    let profile = DecisionProfile::from_ctx(ctx);

    let suspicious_review_case = profile.supports_review_band(risk, thresholds);

    if risk >= thresholds.malicious_min && profile.supports_malicious_band() {
        Severity::Malicious
    } else if suspicious_review_case {
        Severity::Suspicious
    } else {
        Severity::Clean
    }
}

#[derive(Debug, Clone, Default)]
struct DecisionProfile {
    corroborating_sources: usize,
    strong_signal_count: usize,
    medium_signal_count: usize,
    weak_signal_count: usize,
    has_rule_match: bool,
    has_bad_reputation: bool,
    has_trust_allowlist: bool,
    has_decode_or_emulation: bool,
    has_strong_structural_signal: bool,
    has_platform_content_signal: bool,
    has_structural_corroboration: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalBand {
    Weak,
    Medium,
    Strong,
}

fn signal_band(weight: f64) -> Option<SignalBand> {
    if weight >= 2.2 {
        Some(SignalBand::Strong)
    } else if weight >= 1.5 {
        Some(SignalBand::Medium)
    } else if weight > 0.0 {
        Some(SignalBand::Weak)
    } else {
        None
    }
}

impl DecisionProfile {
    fn from_ctx(ctx: &ScanContext) -> Self {
        let mut sources = HashSet::new();
        let mut strong_signal_count = 0usize;
        let mut medium_signal_count = 0usize;
        let mut weak_signal_count = 0usize;
        let mut has_rule_match = false;
        let mut has_bad_reputation = false;
        let mut has_trust_allowlist = false;
        let mut has_decode_or_emulation = false;
        let mut has_strong_structural_signal = false;
        let mut has_platform_content_signal = false;

        for finding in &ctx.findings {
            let source = normalize_reason_source(&finding.code);
            if finding.weight > 0.0 {
                sources.insert(decision_channel(&finding.code, source));
            }
            match signal_band(finding.weight) {
                Some(SignalBand::Strong) => strong_signal_count += 1,
                Some(SignalBand::Medium) => medium_signal_count += 1,
                Some(SignalBand::Weak) => weak_signal_count += 1,
                None => {}
            }
            has_rule_match |= source == "rule";
            has_bad_reputation |= matches!(
                finding.code.as_str(),
                "REPUTATION_KNOWN_BAD_HASH" | "THREAT_INTEL_HASH_MATCH"
            );
            has_trust_allowlist |= matches!(
                finding.code.as_str(),
                "TRUST_ALLOWLIST_HASH"
                    | "TRUST_FRAMEWORK_FINGERPRINT"
                    | "TRUST_BENIGN_TOOLING_CONTEXT"
                    | "TRUST_PACKAGE_MANAGER_CONTEXT"
            );
            has_decode_or_emulation |=
                source == "emulation" || finding.code.starts_with("DECODED_");
            has_strong_structural_signal |= is_strong_structural_signal(&finding.code);
            has_platform_content_signal |= is_platform_content_signal(&finding.code);
        }

        let corroborating_sources = sources.len();
        let has_structural_corroboration = has_strong_structural_signal
            && (has_rule_match || has_decode_or_emulation || has_platform_content_signal);

        Self {
            corroborating_sources,
            strong_signal_count,
            medium_signal_count,
            weak_signal_count,
            has_rule_match,
            has_bad_reputation,
            has_trust_allowlist,
            has_decode_or_emulation,
            has_strong_structural_signal,
            has_platform_content_signal,
            has_structural_corroboration,
        }
    }

    fn supports_review_band(&self, risk: f64, thresholds: &Thresholds) -> bool {
        let strong_corroborated_near_threshold = risk >= thresholds.suspicious_min - 0.25
            && self.corroborating_sources >= 2
            && self.has_structural_corroboration
            && self.strong_signal_count >= 1;
        let medium_corroborated_near_threshold = risk >= thresholds.suspicious_min - 0.15
            && self.corroborating_sources >= 2
            && self.medium_signal_count >= 2
            && (self.has_rule_match
                || self.has_decode_or_emulation
                || self.has_platform_content_signal);
        let weak_single_source_noise = self.corroborating_sources <= 1
            && self.strong_signal_count == 0
            && self.medium_signal_count <= 1
            && self.weak_signal_count >= 2;
        let trust_dampened_review_edge = self.has_trust_allowlist
            && !self.has_bad_reputation
            && self.strong_signal_count == 0
            && self.has_rule_match
            && !self.has_decode_or_emulation
            && !self.has_strong_structural_signal
            && risk < thresholds.suspicious_min + 0.2;

        (risk >= thresholds.suspicious_min
            && !weak_single_source_noise
            && !trust_dampened_review_edge)
            || strong_corroborated_near_threshold
            || medium_corroborated_near_threshold
    }

    fn supports_malicious_band(&self) -> bool {
        ((self.corroborating_sources >= 2
            && (self.has_structural_corroboration
                || self.strong_signal_count >= 2
                || (self.has_rule_match && self.has_decode_or_emulation)
                || self.has_bad_reputation))
            || (self.has_strong_structural_signal
                && self.has_platform_content_signal
                && self.strong_signal_count >= 2))
            && (!self.has_trust_allowlist
                || self.has_bad_reputation
                || self.corroborating_sources >= 3)
    }
}

fn decision_channel<'a>(code: &'a str, source: &'a str) -> &'static str {
    if code.starts_with("DECODED_") {
        "decode"
    } else if is_strong_structural_signal(code) {
        "structure"
    } else if is_platform_content_signal(code) {
        "content"
    } else {
        match source {
            "rule" => "rule",
            "emulation" => "emulation",
            "ml" => "ml",
            "cache" => "cache",
            _ => "heuristic",
        }
    }
}

fn is_strong_structural_signal(code: &str) -> bool {
    matches!(
        code,
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
}

fn is_platform_content_signal(code: &str) -> bool {
    matches!(
        code,
        "PE_SCRIPTED_DOWNLOADER_STRINGS"
            | "PE_LAUNCHER_NETWORK_STRINGS"
            | "ELF_SHELL_DOWNLOADER"
            | "ELF_SHELL_NETWORK_CHAIN"
            | "DECODED_ACTIVE_CONTENT"
            | "DECODED_FOLLOW_ON_BEHAVIOR"
            | "YARA_MATCH"
    )
}
