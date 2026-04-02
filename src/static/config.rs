use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub suspicious_min: f64,
    pub malicious_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    pub enable_file_checks: bool,
    pub enable_string_extraction: bool,
    pub enable_normalization: bool,
    pub enable_decode: bool,
    pub enable_yara: bool,
    pub enable_script_parsing: bool,
    pub enable_format_analysis: bool,
    pub enable_emulation: bool,
    pub enable_runtime_yara: bool,
    pub enable_ml_scoring: bool,
    pub enable_dynamic_sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_input_bytes: usize,
    pub max_recursion_depth: usize,
    pub max_archive_entries: usize,
    pub max_decompressed_bytes: usize,
    pub max_extracted_entry_bytes: usize,
    pub max_string_values: usize,
    pub max_decoded_strings: usize,
    pub max_view_bytes: usize,
    pub max_view_items: usize,
    pub max_emulation_steps: usize,
    pub emulation_timeout_ms: u64,
    pub sandbox_timeout_ms: u64,
    pub sandbox_output_bytes: usize,
    pub sandbox_event_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub thresholds: Thresholds,
    pub weights: WeightConfig,
    pub features: FeatureFlags,
    pub limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightConfig {
    pub size: f64,
    pub magic: f64,
    pub content: f64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            thresholds: Thresholds {
                suspicious_min: 3.5,
                malicious_min: 6.5,
            },
            weights: WeightConfig {
                size: 1.0,
                magic: 2.5,
                content: 3.5,
            },
            features: FeatureFlags {
                enable_file_checks: true,
                enable_string_extraction: true,
                enable_normalization: true,
                enable_decode: true,
                enable_yara: true,
                enable_script_parsing: true,
                enable_format_analysis: true,
                enable_emulation: true,
                enable_runtime_yara: true,
                enable_ml_scoring: true,
                enable_dynamic_sandbox: false,
            },
            limits: ResourceLimits {
                max_input_bytes: 8 * 1024 * 1024,
                max_recursion_depth: 4,
                max_archive_entries: 128,
                max_decompressed_bytes: 8 * 1024 * 1024,
                max_extracted_entry_bytes: 2 * 1024 * 1024,
                max_string_values: 2_048,
                max_decoded_strings: 512,
                max_view_bytes: 16 * 1024,
                max_view_items: 128,
                max_emulation_steps: 10_000,
                emulation_timeout_ms: 250,
                sandbox_timeout_ms: 3_000,
                sandbox_output_bytes: 8 * 1024,
                sandbox_event_limit: 256,
            },
        }
    }
}
