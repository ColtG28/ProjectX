use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::r#static::context::ScanContext;
use crate::r#static::types::{Finding, IntelligenceRecord, IntelligenceSummary};

const DEFAULT_STORE_PATHS: &[&str] = &[
    "quarantine/intelligence/store.json",
    "src/static/intelligence/data/store.json",
];
const DEFAULT_KNOWN_BAD_PATHS: &[&str] = &[
    "quarantine/intelligence/known_bad_hashes.txt",
    "quarantine/known_bad_hashes.txt",
    "src/static/intelligence/data/known_bad_hashes.txt",
];
const DEFAULT_KNOWN_GOOD_PATHS: &[&str] = &[
    "quarantine/intelligence/known_good_hashes.txt",
    "src/static/intelligence/data/known_good_hashes.txt",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IntelligenceStore {
    #[serde(default)]
    version: String,
    #[serde(default)]
    entries: Vec<IntelligenceEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IntelligenceEntry {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    trust_level: Option<String>,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    version_range: Option<String>,
    #[serde(default)]
    allowed_dampen: Vec<String>,
    #[serde(default)]
    typical_files: Vec<String>,
    #[serde(default)]
    signer_hint: Option<String>,
    #[serde(default)]
    package_source: Option<String>,
    #[serde(default)]
    distribution_channel: Option<String>,
    #[serde(default)]
    confidence_weight: Option<f64>,
    #[serde(default)]
    trust_scope: Vec<String>,
    #[serde(default)]
    confidence_score: Option<f64>,
    #[serde(default)]
    source_quality: Option<f64>,
    #[serde(default)]
    last_verified: Option<String>,
    #[serde(default)]
    decay_factor: Option<f64>,
    #[serde(default)]
    file_markers: Vec<String>,
    #[serde(default)]
    path_markers: Vec<String>,
    #[serde(default)]
    content_markers: Vec<String>,
    #[serde(default)]
    name_markers: Vec<String>,
    #[serde(default)]
    min_content_matches: Option<usize>,
    #[serde(default)]
    min_group_matches: Option<usize>,
}

#[derive(Debug, Clone)]
struct LoadedStore {
    version: Option<String>,
    entries: Vec<IntelligenceEntry>,
}

pub fn run(ctx: &mut ScanContext) {
    evaluate(
        ctx,
        DEFAULT_STORE_PATHS,
        DEFAULT_KNOWN_BAD_PATHS,
        DEFAULT_KNOWN_GOOD_PATHS,
    );
}

fn evaluate(
    ctx: &mut ScanContext,
    store_paths: &[&str],
    known_bad_paths: &[&str],
    known_good_paths: &[&str],
) {
    let store = load_store(store_paths);
    let mut summary = IntelligenceSummary {
        store_version: store.version.clone(),
        external_intelligence_status: if ctx.config.features.enable_external_intelligence {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        external_intelligence_enabled: ctx.config.features.enable_external_intelligence,
        ..IntelligenceSummary::default()
    };

    let path_text = ctx.input_path.to_string_lossy().to_ascii_lowercase();
    let file_name = ctx.file_name.to_ascii_lowercase();
    let text = combined_text(ctx);
    let platform = detected_platform(ctx).map(str::to_string);

    for entry in &store.entries {
        if !entry_applies_to_platform(entry, platform.as_deref()) || entry_is_expired(entry) {
            continue;
        }
        if let Some(finding) = finding_from_entry(entry, ctx, &path_text, &file_name, &text) {
            let confidence = confidence_label(&entry.confidence);
            let kind = entry.kind.clone();
            let category = intelligence_category(entry);
            let source = normalized_source(entry);
            let note = if entry.note.is_empty() {
                finding.message.clone()
            } else {
                entry.note.clone()
            };
            let platform = entry.platform.clone();
            let version = entry.version.clone();
            let expires = entry.expires.clone();
            let trust_level = trust_level(entry).map(str::to_string);
            let matched_markers = matched_markers(entry, &path_text, &file_name, &text);
            let effect = policy_effect_for_entry(entry);

            ctx.push_finding(finding);
            summary.records.push(IntelligenceRecord {
                kind: kind.clone(),
                category: category.clone(),
                source: source.clone(),
                confidence: confidence.to_string(),
                trust_level,
                note: note.clone(),
                platform,
                version,
                expires,
                allowed_dampen: entry.allowed_dampen.clone(),
                matched_markers,
                vendor: entry.vendor.clone(),
                ecosystem: entry.ecosystem.clone(),
                rationale: entry.rationale.clone(),
                version_range: entry.version_range.clone(),
                typical_files: entry.typical_files.clone(),
                signer_hint: entry.signer_hint.clone(),
                package_source: entry.package_source.clone(),
                distribution_channel: entry.distribution_channel.clone(),
                confidence_weight: entry.confidence_weight,
                trust_scope: entry.trust_scope.clone(),
                confidence_score: entry.confidence_score,
                source_quality: entry.source_quality,
                last_verified: entry.last_verified.clone(),
                decay_factor: Some(intel_decay_factor(entry)),
            });

            match kind.as_str() {
                "known_bad_hash" => summary.reputation_hits.push(format!("{source}: {note}")),
                "known_good_hash"
                | "framework_fingerprint"
                | "trusted_vendor_context"
                | "trusted_tooling_context"
                | "package_manager_context" => {
                    summary.trust_reasons.push(format!("{source}: {note}"))
                }
                _ => {}
            }
            if !category.is_empty()
                && matches!(
                    kind.as_str(),
                    "known_good_hash"
                        | "framework_fingerprint"
                        | "trusted_vendor_context"
                        | "trusted_tooling_context"
                        | "package_manager_context"
                )
                && !summary.trust_categories.contains(&category)
            {
                summary.trust_categories.push(category);
            }
            if let Some(ecosystem) = entry.ecosystem.as_ref() {
                if !summary.trust_ecosystems.contains(ecosystem) {
                    summary.trust_ecosystems.push(ecosystem.clone());
                }
            }
            if let Some(vendor) = entry.vendor.as_ref() {
                if !summary.trust_vendors.contains(vendor) {
                    summary.trust_vendors.push(vendor.clone());
                }
            }
            if !effect.is_empty() {
                summary.policy_effects.push(effect);
            }
        }
    }

    if let Some(detail) = lookup_hash_note(sha256(ctx), known_bad_paths) {
        ctx.push_finding(Finding::new(
            "REPUTATION_KNOWN_BAD_HASH",
            format!(
                "Local reputation list matched file hash {} [medium confidence] ({detail})",
                ctx.sha256
            ),
            3.1,
        ));
        summary
            .reputation_hits
            .push(format!("Legacy known-bad hash list: {detail}"));
        summary.records.push(IntelligenceRecord {
            kind: "known_bad_hash".to_string(),
            category: "legacy_hash_list".to_string(),
            source: "legacy_local_list".to_string(),
            confidence: "medium".to_string(),
            trust_level: None,
            note: detail.clone(),
            platform: None,
            version: None,
            expires: None,
            allowed_dampen: Vec::new(),
            matched_markers: Vec::new(),
            vendor: None,
            ecosystem: None,
            rationale: None,
            version_range: None,
            typical_files: Vec::new(),
            signer_hint: None,
            package_source: None,
            distribution_channel: None,
            confidence_weight: None,
            trust_scope: Vec::new(),
            confidence_score: None,
            source_quality: None,
            last_verified: None,
            decay_factor: None,
        });
        summary.policy_effects.push(
            "Known-bad reputation increased confidence because the file matched a local malicious-hash list."
                .to_string(),
        );
    }

    if let Some(detail) = lookup_hash_note(sha256(ctx), known_good_paths) {
        ctx.push_finding(Finding::new(
            "TRUST_ALLOWLIST_HASH",
            format!(
                "Local trust allowlist matched file hash {} [high trust] ({detail})",
                ctx.sha256
            ),
            0.0,
        ));
        summary
            .trust_reasons
            .push(format!("Legacy known-good hash allowlist: {detail}"));
        summary.records.push(IntelligenceRecord {
            kind: "known_good_hash".to_string(),
            category: "legacy_hash_list".to_string(),
            source: "legacy_local_list".to_string(),
            confidence: "high".to_string(),
            trust_level: Some("high".to_string()),
            note: detail.clone(),
            platform: None,
            version: None,
            expires: None,
            allowed_dampen: vec!["weak_noise".to_string()],
            matched_markers: Vec::new(),
            vendor: None,
            ecosystem: None,
            rationale: None,
            version_range: None,
            typical_files: Vec::new(),
            signer_hint: None,
            package_source: None,
            distribution_channel: None,
            confidence_weight: None,
            trust_scope: Vec::new(),
            confidence_score: None,
            source_quality: None,
            last_verified: None,
            decay_factor: None,
        });
        summary.policy_effects.push(
            "Trusted allowlist context reduced confidence in weak standalone signals.".to_string(),
        );
    }

    if !summary.reputation_hits.is_empty() {
        summary.confidence_notes.push(
            "Local reputation data increased confidence because the file matched known-bad intelligence."
                .to_string(),
        );
    }
    if !summary.trust_reasons.is_empty() {
        let trust_context = if summary.trust_ecosystems.is_empty() {
            "known-safe context".to_string()
        } else {
            format!(
                "{} in {}",
                if summary.trust_categories.is_empty() {
                    "known-safe context".to_string()
                } else {
                    summary.trust_categories.join(", ")
                },
                summary.trust_ecosystems.join(", ")
            )
        };
        summary.confidence_notes.push(
            format!(
                "Trust policy reduced confidence in weak standalone signals because the file matched {trust_context}."
            ),
        );
    }
    if ctx.config.features.enable_external_intelligence {
        summary.confidence_notes.push(
            "External intelligence was explicitly enabled for this scan and remains a separate confidence input."
                .to_string(),
        );
    } else {
        summary.confidence_notes.push(
            "External intelligence remained disabled, so confidence came from local rules, parsed structure, and local intelligence only."
                .to_string(),
        );
    }

    ctx.log_event(
        "intelligence",
        format!(
            "Recorded {} intelligence record(s), {} reputation hit(s), and {} trust reason(s)",
            summary.records.len(),
            summary.reputation_hits.len(),
            summary.trust_reasons.len()
        ),
    );
    ctx.push_view(crate::r#static::types::View::new(
        "intelligence.summary",
        serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string()),
    ));
    ctx.intelligence = Some(summary);
}

fn load_store(paths: &[&str]) -> LoadedStore {
    let mut loaded = LoadedStore {
        version: None,
        entries: Vec::new(),
    };

    for path in paths {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(store) = serde_json::from_str::<IntelligenceStore>(&text) else {
            continue;
        };
        if loaded.version.is_none() && !store.version.is_empty() {
            loaded.version = Some(store.version.clone());
        }
        loaded.entries.extend(store.entries);
    }

    loaded
}

fn finding_from_entry(
    entry: &IntelligenceEntry,
    ctx: &ScanContext,
    path_text: &str,
    file_name: &str,
    text: &str,
) -> Option<Finding> {
    let confidence = confidence_label(&entry.confidence);
    match entry.kind.as_str() {
        "known_bad_hash" if entry.value.eq_ignore_ascii_case(sha256(ctx)) => Some(Finding::new(
            "REPUTATION_KNOWN_BAD_HASH",
            format!(
                "{} [{}_confidence] ({})",
                entry_message(entry, "Local reputation store matched a known-bad file hash"),
                confidence,
                sha256(ctx)
            ),
            reputation_weight(entry),
        )),
        "known_good_hash" if entry.value.eq_ignore_ascii_case(sha256(ctx)) => Some(Finding::new(
            "TRUST_ALLOWLIST_HASH",
            format!(
                "{} [{}_trust] ({})",
                entry_message(entry, "Local intelligence store matched a known-good file hash"),
                confidence,
                sha256(ctx)
            ),
            0.0,
        )),
        "framework_fingerprint" if matches_markers(entry, path_text, file_name, text) => {
            Some(Finding::new(
                "TRUST_FRAMEWORK_FINGERPRINT",
                format!(
                    "{} [{}_trust] [{} via {}] ({})",
                    entry_message(
                        entry,
                        "Local intelligence store recognized a known-good framework or library fingerprint"
                    ),
                    trust_level(entry).unwrap_or(confidence),
                    intelligence_category(entry),
                    normalized_source(entry),
                    matched_marker_summary(entry, path_text, file_name, text)
                ),
                0.0,
            ))
        }
        "trusted_vendor_context" if matches_markers(entry, path_text, file_name, text) => {
            Some(Finding::new(
                "TRUST_BENIGN_TOOLING_CONTEXT",
                format!(
                    "{} [{}_trust] [{} via {}] ({})",
                    entry_message(
                        entry,
                        "Local intelligence store recognized trusted vendor or package ecosystem context"
                    ),
                    trust_level(entry).unwrap_or(confidence),
                    intelligence_category(entry),
                    normalized_source(entry),
                    matched_marker_summary(entry, path_text, file_name, text)
                ),
                0.0,
            ))
        }
        "trusted_tooling_context" if matches_markers(entry, path_text, file_name, text) => {
            Some(Finding::new(
                "TRUST_BENIGN_TOOLING_CONTEXT",
                format!(
                    "{} [{}_trust] [{} via {}] ({})",
                    entry_message(
                        entry,
                        "Local intelligence store recognized trusted admin or developer tooling context"
                    ),
                    trust_level(entry).unwrap_or(confidence),
                    intelligence_category(entry),
                    normalized_source(entry),
                    matched_marker_summary(entry, path_text, file_name, text)
                ),
                0.0,
            ))
        }
        "package_manager_context" if matches_markers(entry, path_text, file_name, text) => {
            Some(Finding::new(
                "TRUST_PACKAGE_MANAGER_CONTEXT",
                format!(
                    "{} [{}_trust] [{} via {}] ({})",
                    entry_message(
                        entry,
                        "Local intelligence store recognized package-manager or updater context"
                    ),
                    trust_level(entry).unwrap_or(confidence),
                    intelligence_category(entry),
                    normalized_source(entry),
                    matched_marker_summary(entry, path_text, file_name, text)
                ),
                0.0,
            ))
        }
        _ => None,
    }
}

fn matches_markers(
    entry: &IntelligenceEntry,
    path_text: &str,
    file_name: &str,
    text: &str,
) -> bool {
    let path_match = entry
        .path_markers
        .iter()
        .any(|marker| path_text.contains(&marker.to_ascii_lowercase()));
    let file_match = entry
        .file_markers
        .iter()
        .any(|marker| file_name.contains(&marker.to_ascii_lowercase()));
    let name_match = entry
        .name_markers
        .iter()
        .any(|marker| file_name.contains(&marker.to_ascii_lowercase()));
    let typical_file_match = entry
        .typical_files
        .iter()
        .any(|marker| typical_file_matches(marker, file_name, path_text));
    let min_content_matches = entry.min_content_matches.unwrap_or(0);
    let content_match_count = entry
        .content_markers
        .iter()
        .filter(|marker| text.contains(&marker.to_ascii_lowercase()))
        .count();
    let content_match = content_match_count >= min_content_matches.max(1);

    let mut matched_groups = 0usize;
    if path_match {
        matched_groups += 1;
    }
    if file_match || typical_file_match {
        matched_groups += 1;
    }
    if name_match {
        matched_groups += 1;
    }
    if content_match {
        matched_groups += 1;
    }

    let min_group_matches = entry.min_group_matches.unwrap_or_else(|| {
        if matches!(
            entry.kind.as_str(),
            "framework_fingerprint"
                | "trusted_vendor_context"
                | "trusted_tooling_context"
                | "package_manager_context"
        ) {
            2
        } else {
            1
        }
    });

    let no_markers_defined = entry.path_markers.is_empty()
        && entry.file_markers.is_empty()
        && entry.name_markers.is_empty()
        && entry.content_markers.is_empty()
        && entry.typical_files.is_empty();

    no_markers_defined || matched_groups >= min_group_matches
}

fn matched_markers(
    entry: &IntelligenceEntry,
    path_text: &str,
    file_name: &str,
    text: &str,
) -> Vec<String> {
    let mut matched = Vec::new();
    matched.extend(
        entry
            .path_markers
            .iter()
            .filter(|marker| path_text.contains(&marker.to_ascii_lowercase()))
            .cloned(),
    );
    matched.extend(
        entry
            .file_markers
            .iter()
            .filter(|marker| file_name.contains(&marker.to_ascii_lowercase()))
            .cloned(),
    );
    matched.extend(
        entry
            .name_markers
            .iter()
            .filter(|marker| file_name.contains(&marker.to_ascii_lowercase()))
            .cloned(),
    );
    matched.extend(
        entry
            .typical_files
            .iter()
            .filter(|marker| typical_file_matches(marker, file_name, path_text))
            .cloned(),
    );
    matched.extend(
        entry
            .content_markers
            .iter()
            .filter(|marker| text.contains(&marker.to_ascii_lowercase()))
            .cloned(),
    );

    matched
}

fn typical_file_matches(marker: &str, file_name: &str, path_text: &str) -> bool {
    let marker = marker.to_ascii_lowercase();
    if marker.is_empty() {
        return false;
    }
    if file_name.contains(&marker) || path_text.contains(&marker) {
        return true;
    }
    let marker_stem = marker
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(marker.as_str())
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(marker.as_str());
    !marker_stem.is_empty() && (file_name.contains(marker_stem) || path_text.contains(marker_stem))
}

fn matched_marker_summary(
    entry: &IntelligenceEntry,
    path_text: &str,
    file_name: &str,
    text: &str,
) -> String {
    let matched = matched_markers(entry, path_text, file_name, text);
    if matched.is_empty() {
        entry.value.clone()
    } else {
        matched.join(", ")
    }
}

fn entry_message(entry: &IntelligenceEntry, fallback: &str) -> String {
    let base = if entry.note.is_empty() {
        fallback.to_string()
    } else {
        entry.note.clone()
    };
    let mut context = Vec::new();
    if let Some(vendor) = entry.vendor.as_ref() {
        context.push(format!("vendor {vendor}"));
    }
    if let Some(ecosystem) = entry.ecosystem.as_ref() {
        context.push(format!("ecosystem {ecosystem}"));
    }
    if let Some(rationale) = entry.rationale.as_ref() {
        context.push(rationale.clone());
    }
    if let Some(signer) = entry.signer_hint.as_ref() {
        context.push(format!("signer hint {signer}"));
    }
    if let Some(source) = entry.package_source.as_ref() {
        context.push(format!("package source {source}"));
    }
    if let Some(channel) = entry.distribution_channel.as_ref() {
        context.push(format!("distribution channel {channel}"));
    }
    if context.is_empty() {
        base
    } else {
        format!("{base}; {}", context.join("; "))
    }
}

fn intelligence_category(entry: &IntelligenceEntry) -> String {
    if entry.category.is_empty() {
        entry.kind.clone()
    } else {
        entry.category.clone()
    }
}

fn normalized_source(entry: &IntelligenceEntry) -> String {
    if entry.source.is_empty() {
        "local_intelligence".to_string()
    } else {
        entry.source.clone()
    }
}

fn policy_effect_for_entry(entry: &IntelligenceEntry) -> String {
    match entry.kind.as_str() {
        "known_bad_hash" => format!(
            "Known-bad intelligence from {} raised confidence in this result.",
            normalized_source(entry)
        ),
        "known_good_hash"
        | "framework_fingerprint"
        | "trusted_vendor_context"
        | "trusted_tooling_context"
        | "package_manager_context" => {
            let context = entry
                .vendor
                .clone()
                .or_else(|| entry.ecosystem.clone())
                .unwrap_or_else(|| normalized_source(entry));
            format!(
                "Trust context from {context} dampened only weak unsupported {} signals{}{}{}{}.",
                dampen_scope_summary(entry),
                entry
                    .rationale
                    .as_ref()
                    .map(|rationale| format!(" because {rationale}"))
                    .unwrap_or_default(),
                entry
                    .version_range
                    .as_ref()
                    .map(|version| format!(" (version relevance: {version})"))
                    .unwrap_or_default(),
                entry
                    .package_source
                    .as_ref()
                    .map(|source| format!(" (package source: {source})"))
                    .unwrap_or_default(),
                entry
                    .distribution_channel
                    .as_ref()
                    .map(|channel| format!(" (distribution: {channel})"))
                    .unwrap_or_default()
            )
        }
        _ => String::new(),
    }
}

fn entry_is_expired(entry: &IntelligenceEntry) -> bool {
    entry.expires.as_deref().is_some_and(is_expired_ymd)
}

fn entry_applies_to_platform(entry: &IntelligenceEntry, platform: Option<&str>) -> bool {
    match (&entry.platform, platform) {
        (None, _) => true,
        (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
        (Some(_), None) => false,
    }
}

fn detected_platform(ctx: &ScanContext) -> Option<&str> {
    match ctx.detected_format.as_deref() {
        Some("PE") => Some("windows"),
        Some("ELF") => Some("unix"),
        Some("Mach-O") => Some("macos"),
        _ => None,
    }
}

fn confidence_label(value: &str) -> &'static str {
    match value.to_ascii_lowercase().as_str() {
        "high" => "high",
        "low" => "low",
        _ => "medium",
    }
}

fn trust_level(entry: &IntelligenceEntry) -> Option<&str> {
    entry
        .trust_level
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| match entry.kind.as_str() {
            "known_good_hash"
            | "framework_fingerprint"
            | "trusted_vendor_context"
            | "trusted_tooling_context"
            | "package_manager_context" => Some(confidence_label(&entry.confidence)),
            _ => None,
        })
}

fn dampen_scope_summary(entry: &IntelligenceEntry) -> String {
    if entry.allowed_dampen.is_empty() {
        "noise".to_string()
    } else {
        entry
            .allowed_dampen
            .iter()
            .map(|value| value.replace('_', " "))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn is_expired_ymd(value: &str) -> bool {
    let Some(expiry) = parse_ymd(value) else {
        return false;
    };
    expiry < current_ymd()
}

fn parse_ymd(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    Some((
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ))
}

fn current_ymd() -> (i32, u32, u32) {
    use std::time::{SystemTime, UNIX_EPOCH};

    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 86_400)
        .unwrap_or_default() as i64;
    civil_from_days(days)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe.div_euclid(1_460) + doe.div_euclid(36_524) - doe.div_euclid(146_096))
        .div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe.div_euclid(4) - yoe.div_euclid(100));
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

fn reputation_weight(entry: &IntelligenceEntry) -> f64 {
    let base = match confidence_label(&entry.confidence) {
        "high" => 3.4,
        "low" => 2.3,
        _ => 3.1,
    };
    let confidence_score = entry.confidence_score.unwrap_or(1.0).clamp(0.4, 1.4);
    let source_quality = entry.source_quality.unwrap_or(1.0).clamp(0.4, 1.3);
    let confidence_weight = entry.confidence_weight.unwrap_or(1.0).clamp(0.4, 1.4);
    (base * confidence_score * source_quality * confidence_weight * intel_decay_factor(entry))
        .clamp(1.8, 4.2)
}

fn intel_decay_factor(entry: &IntelligenceEntry) -> f64 {
    let configured = entry.decay_factor.unwrap_or(1.0).clamp(0.3, 1.0);
    let Some(last_verified) = entry.last_verified.as_deref().and_then(parse_ymd) else {
        return configured;
    };
    let current = current_ymd();
    let year_delta = current.0.saturating_sub(last_verified.0).max(0) as f64;
    let age_factor = if year_delta >= 3.0 {
        0.65
    } else if year_delta >= 2.0 {
        0.75
    } else if year_delta >= 1.0 {
        0.9
    } else {
        1.0
    };
    (configured * age_factor).clamp(0.3, 1.0)
}

fn combined_text(ctx: &ScanContext) -> String {
    let mut text = String::from_utf8_lossy(&ctx.bytes).to_ascii_lowercase();
    for value in ctx.text_values() {
        text.push('\n');
        text.push_str(&value.to_ascii_lowercase());
    }
    text
}

fn sha256(ctx: &ScanContext) -> &str {
    &ctx.sha256
}

fn lookup_hash_note(sha256: &str, paths: &[&str]) -> Option<String> {
    for path in paths {
        let Some(detail) = lookup_hash_note_in_path(sha256, Path::new(path)) else {
            continue;
        };
        return Some(detail);
    }
    None
}

fn lookup_hash_note_in_path(sha256: &str, path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let mut parts = line.splitn(2, char::is_whitespace);
            let hash = parts.next()?.trim();
            let note = parts
                .next()
                .unwrap_or("matched local reputation data")
                .trim()
                .to_string();
            hash.eq_ignore_ascii_case(sha256).then_some(note)
        })
}

#[cfg(test)]
mod tests {
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;

    use super::{
        confidence_label, evaluate, load_store, lookup_hash_note_in_path, reputation_weight,
        IntelligenceEntry, IntelligenceStore,
    };

    fn temp_store_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "projectx_intel_store_{}_{}.json",
            name,
            std::process::id()
        ))
    }

    #[test]
    fn structured_store_loads_and_preserves_version() {
        let path = temp_store_path("load");
        let store = IntelligenceStore {
            version: "test-store-v1".to_string(),
            entries: vec![super::IntelligenceEntry {
                kind: "framework_fingerprint".to_string(),
                category: "frontend_framework".to_string(),
                value: "react".to_string(),
                source: "unit_test".to_string(),
                confidence: "high".to_string(),
                note: "React production bundle".to_string(),
                platform: None,
                version: Some("1".to_string()),
                expires: Some("2099-01-01".to_string()),
                trust_level: Some("high".to_string()),
                vendor: Some("Meta / webpack ecosystem".to_string()),
                ecosystem: Some("npm".to_string()),
                rationale: Some("Matched production bundle markers".to_string()),
                version_range: Some("react>=16".to_string()),
                allowed_dampen: vec!["framework_bundle_noise".to_string()],
                typical_files: vec!["bundle.js".to_string()],
                file_markers: vec!["bundle".to_string()],
                path_markers: Vec::new(),
                content_markers: vec!["react.production.min".to_string()],
                name_markers: Vec::new(),
                min_content_matches: Some(1),
                min_group_matches: Some(1),
                ..IntelligenceEntry::default()
            }],
        };
        std::fs::write(&path, serde_json::to_string(&store).unwrap()).unwrap();

        let loaded = load_store(&[path.to_str().unwrap()]);
        assert_eq!(loaded.version.as_deref(), Some("test-store-v1"));
        assert_eq!(loaded.entries.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_hash_lists_are_read_safely() {
        let path =
            std::env::temp_dir().join(format!("projectx_reputation_{}.txt", std::process::id()));
        std::fs::write(&path, "abc123 known-safe test fixture\n# comment\n").unwrap();
        let detail = lookup_hash_note_in_path("abc123", &path);
        assert_eq!(detail.as_deref(), Some("known-safe test fixture"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn structured_framework_fingerprint_adds_trust_reason() {
        let store_path = temp_store_path("framework");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v1",
                "entries": [{
                    "kind": "framework_fingerprint",
                    "category": "frontend_framework",
                    "source": "unit_test",
                    "confidence": "high",
                    "trust_level": "high",
                    "note": "React production bundle",
                    "allowed_dampen": ["framework_bundle_noise", "script_noise"],
                    "file_markers": ["framework", "chunk"],
                    "content_markers": ["manifest={", "framework ready"],
                    "min_content_matches": 1
                }]
            })
            .to_string(),
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "projectx_framework_chunk_{}.js",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "(()=>{const manifest={routes:['/home']};console.log('framework ready');})();",
        )
        .unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "TRUST_FRAMEWORK_FINGERPRINT"));
        assert!(ctx
            .intelligence
            .as_ref()
            .is_some_and(|summary| summary.records.iter().any(|record| {
                record.kind == "framework_fingerprint"
                    && record.trust_level.as_deref() == Some("high")
                    && record
                        .allowed_dampen
                        .contains(&"framework_bundle_noise".to_string())
            })));
        assert_eq!(
            ctx.intelligence
                .as_ref()
                .and_then(|summary| summary.store_version.as_deref()),
            Some("test-v1")
        );
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn known_bad_hash_from_structured_store_adds_reputation_finding() {
        let path = std::env::temp_dir().join(format!(
            "projectx_bad_reputation_{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "test").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        let store_path = temp_store_path("bad_hash");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v1",
                "entries": [{
                    "kind": "known_bad_hash",
                    "category": "local_hash",
                    "value": ctx.sha256,
                    "source": "unit_test",
                    "confidence": "high",
                    "note": "Known-bad test hash"
                }]
            })
            .to_string(),
        )
        .unwrap();
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "REPUTATION_KNOWN_BAD_HASH"));
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn known_good_hash_from_structured_store_adds_allowlist_finding() {
        let path = std::env::temp_dir().join(format!(
            "projectx_good_reputation_{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "test").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        let store_path = temp_store_path("good_hash");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v1",
                "entries": [{
                    "kind": "known_good_hash",
                    "category": "local_hash",
                    "value": ctx.sha256,
                    "source": "unit_test",
                    "confidence": "high",
                    "note": "Known-good test hash"
                }]
            })
            .to_string(),
        )
        .unwrap();
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);
        assert!(ctx
            .findings
            .iter()
            .any(|finding| finding.code == "TRUST_ALLOWLIST_HASH"));
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn platform_scoped_trust_does_not_bleed_across_formats() {
        let store_path = temp_store_path("platform");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v1",
                "entries": [{
                    "kind": "trusted_vendor_context",
                    "category": "package_vendor",
                    "source": "unit_test",
                    "confidence": "medium",
                    "trust_level": "medium",
                    "platform": "windows",
                    "note": "Trusted Windows package metadata",
                    "content_markers": ["microsoft corporation", "winget package"],
                    "allowed_dampen": ["binary_loader_noise"]
                }]
            })
            .to_string(),
        )
        .unwrap();

        let path = std::env::temp_dir().join(format!(
            "projectx_platform_trust_{}.elf",
            std::process::id()
        ));
        std::fs::write(&path, b"microsoft corporation winget package").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        ctx.detected_format = Some("ELF".to_string());
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);

        assert!(!ctx.findings.iter().any(|finding| {
            finding.code == "TRUST_BENIGN_TOOLING_CONTEXT"
                || finding.code == "TRUST_PACKAGE_MANAGER_CONTEXT"
        }));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn expired_trust_entries_are_ignored() {
        let store_path = temp_store_path("expired");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v1",
                "entries": [{
                    "kind": "trusted_vendor_context",
                    "category": "package_vendor",
                    "source": "unit_test",
                    "confidence": "medium",
                    "trust_level": "medium",
                    "platform": "windows",
                    "vendor": "Expired Vendor",
                    "ecosystem": "windows_package",
                    "expires": "2020-01-01",
                    "note": "Expired trust context",
                    "content_markers": ["expired vendor marker"],
                    "allowed_dampen": ["binary_loader_noise"]
                }]
            })
            .to_string(),
        )
        .unwrap();

        let path =
            std::env::temp_dir().join(format!("projectx_expired_trust_{}.exe", std::process::id()));
        std::fs::write(&path, b"expired vendor marker").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        ctx.detected_format = Some("PE".to_string());
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);

        assert!(ctx
            .intelligence
            .as_ref()
            .is_none_or(|summary| summary.records.is_empty()));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn provenance_metadata_is_captured_in_intelligence_records() {
        let store_path = temp_store_path("provenance");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v2",
                "entries": [{
                    "kind": "package_manager_context",
                    "category": "package_workflow",
                    "source": "unit_test",
                    "confidence": "medium",
                    "trust_level": "medium",
                    "vendor": "Homebrew",
                    "ecosystem": "package_manager",
                    "rationale": "Matched formula packaging markers",
                    "version_range": "brew>=4",
                    "typical_files": ["Formula.rb"],
                    "note": "Recognized Homebrew package workflow",
                    "platform": "macos",
                    "min_group_matches": 1,
                    "content_markers": ["homebrew formula", "brew install"],
                    "allowed_dampen": ["binary_loader_noise"]
                }]
            })
            .to_string(),
        )
        .unwrap();

        let path = std::env::temp_dir().join(format!(
            "Formula_projectx_homebrew_context_{}.dylib",
            std::process::id()
        ));
        std::fs::write(&path, b"homebrew formula\nbrew install").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        ctx.detected_format = Some("Mach-O".to_string());
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);

        let record = &ctx.intelligence.as_ref().unwrap().records[0];
        assert_eq!(record.vendor.as_deref(), Some("Homebrew"));
        assert_eq!(record.ecosystem.as_deref(), Some("package_manager"));
        assert_eq!(record.version_range.as_deref(), Some("brew>=4"));
        assert_eq!(
            ctx.intelligence.as_ref().unwrap().trust_ecosystems,
            vec!["package_manager".to_string()]
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn vendor_trust_requires_multiple_marker_groups_when_requested() {
        let store_path = temp_store_path("vendor_groups");
        std::fs::write(
            &store_path,
            serde_json::json!({
                "version": "test-v2",
                "entries": [{
                    "kind": "trusted_vendor_context",
                    "category": "package_vendor",
                    "source": "unit_test",
                    "confidence": "medium",
                    "trust_level": "medium",
                    "platform": "windows",
                    "vendor": "Microsoft",
                    "ecosystem": "windows_package",
                    "note": "Trusted Windows package metadata",
                    "content_markers": ["microsoft corporation"],
                    "name_markers": ["winget"],
                    "min_group_matches": 2,
                    "allowed_dampen": ["binary_loader_noise"]
                }]
            })
            .to_string(),
        )
        .unwrap();

        let path =
            std::env::temp_dir().join(format!("projectx_vendor_groups_{}.exe", std::process::id()));
        std::fs::write(&path, b"microsoft corporation only").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        ctx.detected_format = Some("PE".to_string());
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);
        assert!(ctx
            .intelligence
            .as_ref()
            .is_none_or(|summary| summary.records.is_empty()));

        std::fs::write(&path, b"microsoft corporation only").unwrap();
        let renamed = path.with_file_name(format!("winget_{}.exe", std::process::id()));
        let _ = std::fs::rename(&path, &renamed);
        let mut ctx = ScanContext::from_path(&renamed, ScanConfig::default()).unwrap();
        ctx.detected_format = Some("PE".to_string());
        evaluate(&mut ctx, &[store_path.to_str().unwrap()], &[], &[]);
        assert!(ctx
            .intelligence
            .as_ref()
            .is_some_and(|summary| !summary.records.is_empty()));

        let _ = std::fs::remove_file(renamed);
        let _ = std::fs::remove_file(store_path);
    }

    #[test]
    fn confidence_helpers_are_stable() {
        assert_eq!(confidence_label("high"), "high");
        assert_eq!(
            reputation_weight(&IntelligenceEntry {
                confidence: "high".to_string(),
                ..IntelligenceEntry::default()
            }),
            3.4
        );
        assert_eq!(
            reputation_weight(&IntelligenceEntry {
                confidence: "low".to_string(),
                ..IntelligenceEntry::default()
            }),
            2.3
        );
    }

    #[test]
    fn stale_intelligence_decay_reduces_reputation_weight() {
        let fresh = IntelligenceEntry {
            kind: "known_bad_hash".to_string(),
            confidence: "high".to_string(),
            confidence_score: Some(1.0),
            source_quality: Some(1.0),
            confidence_weight: Some(1.0),
            last_verified: Some("2026-04-01".to_string()),
            decay_factor: Some(1.0),
            ..IntelligenceEntry::default()
        };
        let stale = IntelligenceEntry {
            last_verified: Some("2020-01-01".to_string()),
            ..fresh.clone()
        };

        assert!(reputation_weight(&stale) < reputation_weight(&fresh));
    }
}
