use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use super::config::ScanConfig;
use super::file::{hash, mime};
use super::types::{
    CacheMetadata, EmulationSummary, ExtractedArtifact, Finding, IntelligenceSummary, MlAssessment,
    ScanLogEntry, Score, StageTiming, StringPool, ThreatSeveritySummary, View,
};

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub input_path: PathBuf,
    pub file_name: String,
    pub extension: String,
    pub original_size_bytes: usize,
    pub input_truncated: bool,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub sniffed_mime: String,
    pub detected_format: Option<String>,
    pub normalized_strings: Vec<String>,
    pub decoded_strings: Vec<String>,
    pub score: Score,
    pub findings: Vec<Finding>,
    pub views: Vec<View>,
    pub strings: StringPool,
    pub stage_timings: Vec<StageTiming>,
    pub artifacts: Vec<ExtractedArtifact>,
    pub telemetry: Vec<ScanLogEntry>,
    pub cache: Option<CacheMetadata>,
    pub rules_version: String,
    pub emulation: Option<EmulationSummary>,
    pub intelligence: Option<IntelligenceSummary>,
    pub ml_assessment: Option<MlAssessment>,
    pub threat_severity: Option<ThreatSeveritySummary>,
    pub config: ScanConfig,
}

impl ScanContext {
    pub fn from_path(path: impl AsRef<Path>, config: ScanConfig) -> std::io::Result<Self> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)?;
        let original_size_bytes = metadata.len() as usize;
        let max_input_bytes = config.limits.max_input_bytes;
        let bytes = if original_size_bytes > max_input_bytes {
            let file = File::open(path)?;
            let mut limited = Vec::with_capacity(max_input_bytes);
            file.take(max_input_bytes as u64)
                .read_to_end(&mut limited)?;
            limited
        } else {
            fs::read(path)?
        };
        let input_truncated = original_size_bytes > bytes.len();
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let extension = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let sha256 = hash::sha256_hex(&bytes);
        let sniffed_mime = mime::sniff_from_bytes(&bytes, &extension).to_string();

        Ok(Self {
            input_path: path.to_path_buf(),
            file_name,
            extension,
            original_size_bytes,
            input_truncated,
            bytes,
            sha256,
            sniffed_mime,
            detected_format: None,
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
            config,
        })
    }

    pub fn push_finding(&mut self, finding: Finding) {
        if self
            .findings
            .iter()
            .any(|existing| existing.code == finding.code && existing.message == finding.message)
        {
            return;
        }
        self.findings.push(finding);
    }

    pub fn push_view(&mut self, view: View) {
        self.views.push(view);
    }

    pub fn push_artifact(&mut self, artifact: ExtractedArtifact) {
        if self
            .artifacts
            .iter()
            .any(|existing| existing.path == artifact.path && existing.kind == artifact.kind)
        {
            return;
        }
        self.artifacts.push(artifact);
    }

    pub fn log_event(&mut self, stage: impl Into<String>, message: impl Into<String>) {
        self.telemetry.push(ScanLogEntry::new(stage, message));
    }

    pub fn record_stage_timing(&mut self, name: impl Into<String>, duration_ms: u64) {
        self.stage_timings.push(StageTiming::new(name, duration_ms));
    }

    pub fn text_values(&self) -> Vec<&str> {
        let mut values = Vec::with_capacity(
            self.strings.values.len() + self.normalized_strings.len() + self.decoded_strings.len(),
        );
        values.extend(self.strings.values.iter().map(String::as_str));
        values.extend(self.normalized_strings.iter().map(String::as_str));
        values.extend(self.decoded_strings.iter().map(String::as_str));
        values
    }
}

#[cfg(test)]
mod tests {
    use crate::r#static::config::ScanConfig;

    use super::ScanContext;

    #[test]
    fn caps_large_input_reads() {
        let path =
            std::env::temp_dir().join(format!("projectx_context_cap_{}.bin", std::process::id()));
        std::fs::write(&path, vec![b'A'; 64]).unwrap();

        let mut config = ScanConfig::default();
        config.limits.max_input_bytes = 16;
        let ctx = ScanContext::from_path(&path, config).unwrap();

        assert_eq!(ctx.original_size_bytes, 64);
        assert_eq!(ctx.bytes.len(), 16);
        assert!(ctx.input_truncated);

        let _ = std::fs::remove_file(path);
    }
}
