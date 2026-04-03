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
    pub dynamic_score: f64,
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
    pub auto_sandbox_triggered: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxPlanSummary {
    pub engine: String,
    pub network_enabled: bool,
    pub read_only_root: bool,
    pub snapshot_strategy: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicBehaviorEvent {
    pub kind: String,
    pub subject: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicBehaviorSummary {
    pub file_events: usize,
    pub registry_events: usize,
    pub network_events: usize,
    pub process_events: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DynamicAnalysisSummary {
    pub attempted: bool,
    pub executed: bool,
    pub timed_out: bool,
    pub engine: String,
    pub exit_code: Option<i32>,
    pub stdout_preview: String,
    pub stderr_preview: String,
    pub behavior: DynamicBehaviorSummary,
    pub events: Vec<DynamicBehaviorEvent>,
    pub runtime_yara_hits: Vec<String>,
    pub snapshot_id: Option<String>,
    pub revert_command: Option<String>,
    pub error: Option<String>,
}

pub type Weights = HashMap<String, f64>;
