use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::r#static::context::ScanContext;
use crate::r#static::types::{Finding, IntelligenceRecord, IntelligenceSummary};

const BUNDLED_STORE_JSON: &str = include_str!("data/store.json");
const BUNDLED_KNOWN_BAD_HASHES: &str = include_str!("data/known_bad_hashes.txt");
const BUNDLED_KNOWN_GOOD_HASHES: &str = include_str!("data/known_good_hashes.txt");

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
        &[crate::app_paths::intelligence_store_override_path()],
        &[
            crate::app_paths::intelligence_known_bad_override_path(),
            crate::app_paths::known_bad_hashes_override_path(),
        ],
        &[crate::app_paths::known_good_hashes_override_path()],
    );
}

fn evaluate(
    ctx: &mut ScanContext,
    store_paths: &[std::path::PathBuf],
    known_bad_paths: &[std::path::PathBuf],
    known_good_paths: &[std::path::PathBuf],
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

    apply_runtime_provenance(ctx, &mut summary, &path_text, &file_name);

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

fn apply_runtime_provenance(
    ctx: &mut ScanContext,
    summary: &mut IntelligenceSummary,
    path_text: &str,
    file_name: &str,
) {
    for signal in runtime_provenance_signals(path_text, file_name) {
        ctx.push_finding(Finding::new(
            signal.finding_code,
            signal.message.clone(),
            0.0,
        ));
        summary
            .trust_reasons
            .push(format!("{}: {}", signal.source, signal.note));
        if !summary.trust_categories.contains(&signal.category) {
            summary.trust_categories.push(signal.category.clone());
        }
        if !summary.trust_ecosystems.contains(&signal.ecosystem) {
            summary.trust_ecosystems.push(signal.ecosystem.clone());
        }
        if !summary.trust_vendors.contains(&signal.vendor) {
            summary.trust_vendors.push(signal.vendor.clone());
        }
        summary.policy_effects.push(signal.policy_effect.clone());
        summary.records.push(IntelligenceRecord {
            kind: signal.kind,
            category: signal.category,
            source: signal.source,
            confidence: signal.confidence,
            trust_level: Some(signal.trust_level),
            note: signal.note,
            platform: signal.platform,
            version: None,
            expires: None,
            allowed_dampen: signal.allowed_dampen,
            matched_markers: signal.matched_markers,
            vendor: Some(signal.vendor),
            ecosystem: Some(signal.ecosystem),
            rationale: Some(signal.rationale),
            version_range: None,
            typical_files: Vec::new(),
            signer_hint: signal.signer_hint,
            package_source: signal.package_source,
            distribution_channel: signal.distribution_channel,
            confidence_weight: None,
            trust_scope: signal.trust_scope,
            confidence_score: None,
            source_quality: None,
            last_verified: None,
            decay_factor: Some(1.0),
        });
    }
}

#[derive(Debug, Clone)]
struct RuntimeProvenanceSignal {
    finding_code: &'static str,
    kind: String,
    category: String,
    source: String,
    confidence: String,
    trust_level: String,
    note: String,
    message: String,
    platform: Option<String>,
    vendor: String,
    ecosystem: String,
    rationale: String,
    package_source: Option<String>,
    distribution_channel: Option<String>,
    signer_hint: Option<String>,
    allowed_dampen: Vec<String>,
    trust_scope: Vec<String>,
    matched_markers: Vec<String>,
    policy_effect: String,
}

fn runtime_provenance_signals(path_text: &str, file_name: &str) -> Vec<RuntimeProvenanceSignal> {
    let mut signals = Vec::new();

    if path_text.starts_with("/system/applications/")
        || path_text.starts_with("/system/library/coreservices/")
    {
        signals.push(RuntimeProvenanceSignal {
            finding_code: "TRUST_BENIGN_TOOLING_CONTEXT",
            kind: "trusted_vendor_context".to_string(),
            category: "platform_trust".to_string(),
            source: "runtime_path_context".to_string(),
            confidence: "medium".to_string(),
            trust_level: "medium".to_string(),
            note: "Recognized protected macOS system-application path context.".to_string(),
            message: "Runtime path context recognized a protected macOS system application layout [medium_trust] (/System application path)".to_string(),
            platform: Some("macos".to_string()),
            vendor: "Apple".to_string(),
            ecosystem: "macos".to_string(),
            rationale: "Built-in macOS applications under protected system paths are commonly benign software locations.".to_string(),
            package_source: Some("system_applications".to_string()),
            distribution_channel: Some("apple_system_install".to_string()),
            signer_hint: Some("Apple system application path".to_string()),
            allowed_dampen: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            trust_scope: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            matched_markers: vec!["/System/Applications".to_string()],
            policy_effect: "Protected macOS system-app provenance dampened only weak unsupported loader/profile noise.".to_string(),
        });
    } else if path_text.starts_with("/applications/") && path_text.contains(".app/") {
        signals.push(RuntimeProvenanceSignal {
            finding_code: "TRUST_BENIGN_TOOLING_CONTEXT",
            kind: "trusted_vendor_context".to_string(),
            category: "platform_trust".to_string(),
            source: "runtime_path_context".to_string(),
            confidence: "medium".to_string(),
            trust_level: "medium".to_string(),
            note: "Recognized installed macOS app-bundle path context.".to_string(),
            message: "Runtime path context recognized an installed macOS app bundle [medium_trust] (/Applications bundle path)".to_string(),
            platform: Some("macos".to_string()),
            vendor: "macOS application bundle".to_string(),
            ecosystem: "macos".to_string(),
            rationale: "Installed app bundles under /Applications with a resolved Contents/MacOS entrypoint are a common benign software layout.".to_string(),
            package_source: Some("application_bundle".to_string()),
            distribution_channel: Some("user_installed_app".to_string()),
            signer_hint: Some("Installed app bundle path with resolved executable; no signer verification".to_string()),
            allowed_dampen: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            trust_scope: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            matched_markers: vec!["/Applications".to_string(), ".app".to_string()],
            policy_effect: "Installed app-bundle provenance treats common Mach-O loader/network runtime observations as baseline unless corroborated by stronger suspicious signals.".to_string(),
        });
    }

    if path_text.contains("/opt/homebrew/cellar/")
        || path_text.contains("/usr/local/cellar/")
        || path_text.contains("/opt/homebrew/caskroom/")
    {
        signals.push(RuntimeProvenanceSignal {
            finding_code: "TRUST_PACKAGE_MANAGER_CONTEXT",
            kind: "package_manager_context".to_string(),
            category: "package_ecosystem".to_string(),
            source: "runtime_path_context".to_string(),
            confidence: "medium".to_string(),
            trust_level: "medium".to_string(),
            note: "Recognized Homebrew package-management layout.".to_string(),
            message: "Runtime path context recognized Homebrew-managed software [medium_trust] (Homebrew Cellar/Caskroom layout)".to_string(),
            platform: Some("macos".to_string()),
            vendor: "Homebrew".to_string(),
            ecosystem: "homebrew".to_string(),
            rationale: "Homebrew cellar and cask layouts are common provenance signals for benign packaged software.".to_string(),
            package_source: Some("homebrew".to_string()),
            distribution_channel: Some("package_manager".to_string()),
            signer_hint: None,
            allowed_dampen: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            trust_scope: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            matched_markers: vec!["homebrew".to_string()],
            policy_effect: "Homebrew provenance dampened only weak unsupported loader/profile noise.".to_string(),
        });
    }

    if path_text.contains("/node_modules/") || path_text.contains("\\node_modules\\") {
        signals.push(RuntimeProvenanceSignal {
            finding_code: "TRUST_PACKAGE_MANAGER_CONTEXT",
            kind: "package_manager_context".to_string(),
            category: "package_ecosystem".to_string(),
            source: "runtime_path_context".to_string(),
            confidence: "medium".to_string(),
            trust_level: "medium".to_string(),
            note: "Recognized npm-style dependency layout.".to_string(),
            message: "Runtime path context recognized npm-style dependency packaging [medium_trust] (node_modules layout)".to_string(),
            platform: None,
            vendor: "npm ecosystem".to_string(),
            ecosystem: "npm".to_string(),
            rationale: "node_modules directories are a common benign packaging structure for JavaScript dependencies.".to_string(),
            package_source: Some("npm".to_string()),
            distribution_channel: Some("package_manager".to_string()),
            signer_hint: None,
            allowed_dampen: vec!["script_noise".to_string(), "file_profile_noise".to_string()],
            trust_scope: vec!["script_noise".to_string(), "file_profile_noise".to_string()],
            matched_markers: vec!["node_modules".to_string()],
            policy_effect: "npm packaging provenance dampened only weak unsupported script/profile noise.".to_string(),
        });
    }

    if path_text.contains("/site-packages/")
        || path_text.contains("/dist-packages/")
        || path_text.contains("\\site-packages\\")
    {
        signals.push(RuntimeProvenanceSignal {
            finding_code: "TRUST_PACKAGE_MANAGER_CONTEXT",
            kind: "package_manager_context".to_string(),
            category: "package_ecosystem".to_string(),
            source: "runtime_path_context".to_string(),
            confidence: "medium".to_string(),
            trust_level: "medium".to_string(),
            note: "Recognized Python package-installation layout.".to_string(),
            message: "Runtime path context recognized Python package-manager layout [medium_trust] (site-packages/dist-packages)".to_string(),
            platform: None,
            vendor: "Python packaging".to_string(),
            ecosystem: "pip".to_string(),
            rationale: "site-packages and dist-packages are common benign layouts for Python-installed dependencies.".to_string(),
            package_source: Some("pip".to_string()),
            distribution_channel: Some("package_manager".to_string()),
            signer_hint: None,
            allowed_dampen: vec!["script_noise".to_string(), "file_profile_noise".to_string()],
            trust_scope: vec!["script_noise".to_string(), "file_profile_noise".to_string()],
            matched_markers: vec!["site-packages".to_string()],
            policy_effect: "Python package provenance dampened only weak unsupported script/profile noise.".to_string(),
        });
    }

    if path_text.contains("/.cargo/registry/")
        || path_text.contains("/.cargo/bin/")
        || path_text.contains("/rustup/toolchains/")
        || file_name == "cargo"
        || file_name == "rustup"
    {
        signals.push(RuntimeProvenanceSignal {
            finding_code: "TRUST_PACKAGE_MANAGER_CONTEXT",
            kind: "package_manager_context".to_string(),
            category: "package_ecosystem".to_string(),
            source: "runtime_path_context".to_string(),
            confidence: "medium".to_string(),
            trust_level: "medium".to_string(),
            note: "Recognized Rust toolchain or cargo package layout.".to_string(),
            message: "Runtime path context recognized cargo/rustup-managed software [medium_trust] (cargo registry/toolchain layout)".to_string(),
            platform: None,
            vendor: "Rust toolchain".to_string(),
            ecosystem: "cargo".to_string(),
            rationale: "cargo registry and rustup toolchain paths are common benign layouts for Rust dependencies and tooling.".to_string(),
            package_source: Some("cargo".to_string()),
            distribution_channel: Some("package_manager".to_string()),
            signer_hint: None,
            allowed_dampen: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            trust_scope: vec!["binary_loader_noise".to_string(), "file_profile_noise".to_string()],
            matched_markers: vec!["cargo".to_string(), "rustup".to_string()],
            policy_effect: "Cargo/rustup provenance dampened only weak unsupported loader/profile noise.".to_string(),
        });
    }

    signals
}

fn load_store(paths: &[std::path::PathBuf]) -> LoadedStore {
    let mut loaded = LoadedStore {
        version: None,
        entries: Vec::new(),
    };

    for path in paths {
        extend_loaded_store(&mut loaded, fs::read_to_string(path).ok().as_deref());
    }

    extend_loaded_store(&mut loaded, Some(BUNDLED_STORE_JSON));
    loaded
}

fn extend_loaded_store(loaded: &mut LoadedStore, text: Option<&str>) {
    let Some(text) = text else {
        return;
    };
    let Ok(store) = serde_json::from_str::<IntelligenceStore>(text) else {
        return;
    };
    if loaded.version.is_none() && !store.version.is_empty() {
        loaded.version = Some(store.version.clone());
    }
    loaded.entries.extend(store.entries);
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

fn lookup_hash_note(sha256: &str, paths: &[std::path::PathBuf]) -> Option<String> {
    for path in paths {
        let Some(detail) = lookup_hash_note_in_path(sha256, path) else {
            continue;
        };
        return Some(detail);
    }

    let bundled = if paths
        .iter()
        .any(|path| path == &crate::app_paths::known_good_hashes_override_path())
    {
        BUNDLED_KNOWN_GOOD_HASHES
    } else {
        BUNDLED_KNOWN_BAD_HASHES
    };
    lookup_hash_note_in_text(sha256, bundled)
}

fn lookup_hash_note_in_path(sha256: &str, path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    lookup_hash_note_in_text(sha256, &text)
}

fn lookup_hash_note_in_text(sha256: &str, text: &str) -> Option<String> {
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
    use super::*;
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;
    use crate::r#static::types::{Finding, Score, StringPool};
    use std::path::PathBuf;

    fn test_ctx(path: &str) -> ScanContext {
        ScanContext {
            input_path: PathBuf::from(path),
            file_name: PathBuf::from(path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            extension: PathBuf::from(path)
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            original_size_bytes: 1024,
            input_truncated: false,
            bytes: Vec::new(),
            sha256: "0".repeat(64),
            sniffed_mime: "application/octet-stream".to_string(),
            detected_format: Some("Mach-O".to_string()),
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
    fn runtime_provenance_recognizes_system_macos_app_paths() {
        let signals = runtime_provenance_signals(
            "/system/applications/reminders.app/contents/macos/reminders",
            "reminders",
        );
        assert!(signals.iter().any(|signal| signal.ecosystem == "macos"));
        assert!(signals
            .iter()
            .any(|signal| signal.finding_code == "TRUST_BENIGN_TOOLING_CONTEXT"));
    }

    #[test]
    fn runtime_provenance_recognizes_package_manager_layouts() {
        let signals = runtime_provenance_signals(
            "/users/test/project/node_modules/react/index.js",
            "index.js",
        );
        assert!(signals.iter().any(|signal| signal.ecosystem == "npm"));
    }

    #[test]
    fn runtime_provenance_upgrades_installed_macos_app_bundle_to_medium_trust() {
        let signals = runtime_provenance_signals(
            "/applications/projectx.app/contents/macos/projectx",
            "projectx",
        );
        let app_signal = signals
            .iter()
            .find(|signal| signal.package_source.as_deref() == Some("application_bundle"))
            .expect("installed app bundle trust signal");

        assert_eq!(app_signal.trust_level, "medium");
        assert_eq!(app_signal.confidence, "medium");
        assert!(app_signal
            .allowed_dampen
            .iter()
            .any(|scope| scope == "binary_loader_noise"));
    }

    #[test]
    fn runtime_provenance_is_recorded_in_summary() {
        let mut ctx = test_ctx("/System/Applications/Dictionary.app/Contents/MacOS/Dictionary");
        ctx.findings
            .push(Finding::new("DECODED_ACTIVE_CONTENT", "noise", 1.0));

        evaluate(&mut ctx, &[], &[], &[]);

        let summary = ctx.intelligence.expect("summary");
        assert!(!summary.trust_reasons.is_empty());
        assert!(summary
            .trust_ecosystems
            .iter()
            .any(|value| value == "macos"));
    }
}
