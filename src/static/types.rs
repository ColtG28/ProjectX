use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Score {
    pub risk: f64,
    pub safety: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub message: String,
    pub weight: f64,
}

impl Finding {
    pub fn new(code: impl Into<String>, message: impl Into<String>, weight: f64) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            weight,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringPool {
    pub values: Vec<String>,
}

impl StringPool {
    pub fn insert(&mut self, value: String) {
        if !self.values.iter().any(|v| v == &value) {
            self.values.push(value);
        }
    }

    pub fn extend<I: IntoIterator<Item = String>>(&mut self, values: I) {
        for value in values {
            self.insert(value);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct View {
    pub name: String,
    pub content: String,
}

impl View {
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageTiming {
    pub name: String,
    pub duration_ms: u64,
}

impl StageTiming {
    pub fn new(name: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            name: name.into(),
            duration_ms,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractedArtifact {
    pub path: String,
    pub kind: String,
    pub depth: usize,
    pub size_bytes: usize,
}

impl ExtractedArtifact {
    pub fn new(
        path: impl Into<String>,
        kind: impl Into<String>,
        depth: usize,
        size_bytes: usize,
    ) -> Self {
        Self {
            path: path.into(),
            kind: kind.into(),
            depth,
            size_bytes,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanLogEntry {
    pub stage: String,
    pub message: String,
}

impl ScanLogEntry {
    pub fn new(stage: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub key: String,
    pub hit: bool,
    pub rules_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationSummary {
    pub executed: bool,
    pub instruction_budget: usize,
    pub steps_used: usize,
    pub timed_out: bool,
    pub runtime_yara_hits: Vec<String>,
    pub resolved_api_hashes: Vec<String>,
    pub derived_artifacts: Vec<ExtractedArtifact>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MlAssessment {
    pub static_signal_score: f64,
    pub heuristic_signal_score: f64,
    pub static_score: f64,
    #[serde(default, alias = "dynamic_score")]
    pub runtime_signal_score: f64,
    pub intel_score: f64,
    pub evasion_score: f64,
    pub ensemble_score: f64,
    pub blended_score: f64,
    pub label: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatSeveritySummary {
    pub severity_score: f64,
    pub recommended_action: String,
    pub contributing_signals: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelligenceRecord {
    pub kind: String,
    pub category: String,
    pub source: String,
    pub confidence: String,
    pub trust_level: Option<String>,
    pub note: String,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub expires: Option<String>,
    pub allowed_dampen: Vec<String>,
    pub matched_markers: Vec<String>,
    pub vendor: Option<String>,
    pub ecosystem: Option<String>,
    pub rationale: Option<String>,
    pub version_range: Option<String>,
    pub typical_files: Vec<String>,
    #[serde(default)]
    pub signer_hint: Option<String>,
    #[serde(default)]
    pub package_source: Option<String>,
    #[serde(default)]
    pub distribution_channel: Option<String>,
    #[serde(default)]
    pub confidence_weight: Option<f64>,
    #[serde(default)]
    pub trust_scope: Vec<String>,
    #[serde(default)]
    pub confidence_score: Option<f64>,
    #[serde(default)]
    pub source_quality: Option<f64>,
    #[serde(default)]
    pub last_verified: Option<String>,
    #[serde(default)]
    pub decay_factor: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelligenceSummary {
    pub store_version: Option<String>,
    pub reputation_hits: Vec<String>,
    pub trust_reasons: Vec<String>,
    pub confidence_notes: Vec<String>,
    pub records: Vec<IntelligenceRecord>,
    pub policy_effects: Vec<String>,
    pub trust_categories: Vec<String>,
    pub trust_ecosystems: Vec<String>,
    pub trust_vendors: Vec<String>,
    pub external_intelligence_status: String,
    pub external_intelligence_enabled: bool,
}

pub type Weights = HashMap<String, f64>;
