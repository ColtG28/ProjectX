use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};

pub use crate::r#static::report::{
    NormalizedSeverity as SeverityLevel, QuarantineMetadata,
    QuarantineStatus as RecordStorageState, ReportReason as DetectionReason,
    ReportSummary as ScanRecord, SummaryVerdict as Verdict,
};

pub const HISTORY_PATH: &str = "quarantine/gui_scan_history.json";
pub const INDEX_PATH: &str = "quarantine/gui_index.json";
pub const TIMING_SAMPLE_LIMIT: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Analytics,
    Scanner,
    Reports,
    History,
    Settings,
    About,
}

impl Page {
    pub fn label(self) -> &'static str {
        match self {
            Self::Analytics => "Overview",
            Self::Scanner => "Scan",
            Self::Reports => "Results",
            Self::History => "History",
            Self::Settings => "Settings",
            Self::About => "Scope",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Analytics => "▣",
            Self::Scanner => "◫",
            Self::Reports => "☰",
            Self::History => "🗂",
            Self::Settings => "⚙",
            Self::About => "ⓘ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimePeriod {
    Last24Hours,
    Last7Days,
    Last30Days,
    AllTime,
}

impl TimePeriod {
    pub fn label(self) -> &'static str {
        match self {
            Self::Last24Hours => "Last 24h",
            Self::Last7Days => "Last 7d",
            Self::Last30Days => "Last 30d",
            Self::AllTime => "All time",
        }
    }

    pub fn cutoff_epoch(self, now_epoch: u64) -> u64 {
        match self {
            Self::Last24Hours => now_epoch.saturating_sub(24 * 60 * 60),
            Self::Last7Days => now_epoch.saturating_sub(7 * 24 * 60 * 60),
            Self::Last30Days => now_epoch.saturating_sub(30 * 24 * 60 * 60),
            Self::AllTime => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSample {
    pub file_size_bytes: u64,
    pub duration_ms: u64,
    pub scanned_at_epoch: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedHistory {
    pub records: Vec<ScanRecord>,
    #[serde(default)]
    pub timing_samples: Vec<TimingSample>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedIndex {
    pub entries: Vec<ScanRecord>,
}

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub path: PathBuf,
    pub last_modified_epoch: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ScanJobState {
    pub running: bool,
    pub total: usize,
    pub total_bytes: u64,
    pub processed: usize,
    pub processed_bytes: u64,
    pub queued_files: usize,
    pub queued_bytes: u64,
    pub good: usize,
    pub malicious: usize,
    pub unsure: usize,
    pub errors: usize,
    pub current_path: String,
    pub current_stage: String,
    pub current_file_progress: f32,
    pub current_file_elapsed_ms: u64,
    pub current_file_size: u64,
    pub average_file_ms: u64,
    pub elapsed_ms: u64,
    pub eta_seconds: u64,
    pub finished: bool,
    pub new_records: Vec<ScanRecord>,
    pub new_timing_samples: Vec<TimingSample>,
    pub summary: String,
    pub pending_targets: VecDeque<ScanTarget>,
}

#[derive(Debug, Clone)]
pub struct SettingsState {
    pub include_entire_filesystem: bool,
    pub check_cached_scans: bool,
    pub max_files_per_bulk_scan: usize,
    pub enable_file_checks: bool,
    pub enable_string_extraction: bool,
    pub enable_normalization: bool,
    pub enable_decode: bool,
    pub enable_script_parsing: bool,
    pub enable_format_analysis: bool,
    pub enable_yara: bool,
    pub enable_emulation: bool,
    pub enable_runtime_yara: bool,
    pub enable_ml_scoring: bool,
    pub enable_download_monitoring: bool,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            include_entire_filesystem: false,
            check_cached_scans: true,
            max_files_per_bulk_scan: 100,
            enable_file_checks: true,
            enable_string_extraction: true,
            enable_normalization: true,
            enable_decode: true,
            enable_script_parsing: true,
            enable_format_analysis: true,
            enable_yara: true,
            enable_emulation: true,
            enable_runtime_yara: true,
            enable_ml_scoring: true,
            enable_download_monitoring: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAction {
    Restore,
    Delete,
    Leave,
    DeleteReport,
}

#[derive(Debug, Clone)]
pub enum PendingConfirmationTarget {
    RecordAction {
        record_id: String,
        action: RecordAction,
    },
    DeleteReports {
        record_ids: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct PendingConfirmation {
    pub title: String,
    pub message: String,
    pub confirm_label: String,
    pub target: PendingConfirmationTarget,
}

#[derive(Debug, Clone, Copy)]
pub struct UiMetrics {
    pub scale_factor: f32,
    pub menu_width: f32,
    pub compact: bool,
    pub content_max_width: f32,
}

impl Default for UiMetrics {
    fn default() -> Self {
        Self {
            scale_factor: 1.0,
            menu_width: 200.0,
            compact: false,
            content_max_width: 920.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TimingProfile {
    pub average_file_ms: u64,
    pub average_bytes_per_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportVerdictFilter {
    All,
    Clean,
    Malicious,
    Suspicious,
    Error,
}

impl ReportVerdictFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All verdicts",
            Self::Clean => "Clean",
            Self::Malicious => "Malicious",
            Self::Suspicious => "Suspicious",
            Self::Error => "Errors",
        }
    }

    pub fn matches(self, verdict: Verdict) -> bool {
        match self {
            Self::All => true,
            Self::Clean => verdict == Verdict::Clean,
            Self::Malicious => verdict == Verdict::Malicious,
            Self::Suspicious => verdict == Verdict::Suspicious,
            Self::Error => verdict == Verdict::Error,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportStorageFilter {
    All,
    InQuarantine,
    Restored,
    Deleted,
    Unknown,
}

impl ReportStorageFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All storage",
            Self::InQuarantine => "In quarantine",
            Self::Restored => "Restored",
            Self::Deleted => "Deleted",
            Self::Unknown => "Unknown",
        }
    }

    pub fn matches(self, state: RecordStorageState) -> bool {
        match self {
            Self::All => true,
            Self::InQuarantine => state == RecordStorageState::InQuarantine,
            Self::Restored => state == RecordStorageState::Restored,
            Self::Deleted => state == RecordStorageState::Deleted,
            Self::Unknown => state == RecordStorageState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSortOrder {
    NewestFirst,
    OldestFirst,
    SeverityFirst,
    Name,
}

impl ReportSortOrder {
    pub fn label(self) -> &'static str {
        match self {
            Self::NewestFirst => "Newest first",
            Self::OldestFirst => "Oldest first",
            Self::SeverityFirst => "Severity first",
            Self::Name => "Name",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DownloadWatchEntry {
    pub last_size: u64,
    pub last_seen_epoch: u64,
    pub last_scanned_size: u64,
}

impl TimingProfile {
    pub fn from_samples(samples: &[TimingSample]) -> Self {
        let recent = samples.iter().rev().take(512).collect::<Vec<_>>();
        if recent.is_empty() {
            return Self {
                average_file_ms: 1_500,
                average_bytes_per_ms: 0.0,
            };
        }

        let duration_total = recent.iter().map(|sample| sample.duration_ms).sum::<u64>();
        let size_total = recent
            .iter()
            .map(|sample| sample.file_size_bytes)
            .sum::<u64>();
        let average_file_ms = (duration_total / recent.len() as u64).max(300);
        let average_bytes_per_ms = if duration_total > 0 && size_total > 0 {
            size_total as f64 / duration_total as f64
        } else {
            0.0
        };

        Self {
            average_file_ms,
            average_bytes_per_ms,
        }
    }

    pub fn estimate_file_ms(self, size_bytes: u64) -> u64 {
        let size_estimate = if self.average_bytes_per_ms > 0.0 && size_bytes > 0 {
            (size_bytes as f64 / self.average_bytes_per_ms).round() as u64
        } else {
            0
        };

        match (self.average_file_ms, size_estimate) {
            (0, 0) => 1_500,
            (avg, 0) => avg.max(300),
            (0, estimate) => estimate.max(300),
            (avg, estimate) => {
                (((avg as f64 * 0.4) + (estimate as f64 * 0.6)).round() as u64).max(300)
            }
        }
    }
}

#[derive(Debug)]
pub struct MyApp {
    pub current_page: Page,
    pub menu_open: bool,
    pub period: TimePeriod,
    pub boot_until: Instant,
    pub records: Vec<ScanRecord>,
    pub timing_samples: Vec<TimingSample>,
    pub job: std::sync::Arc<std::sync::Mutex<ScanJobState>>,
    pub settings: SettingsState,
    pub single_file_path: String,
    pub report_search: String,
    pub history_search: String,
    pub report_verdict_filter: ReportVerdictFilter,
    pub report_storage_filter: ReportStorageFilter,
    pub report_sort_order: ReportSortOrder,
    pub history_quarantine_only: bool,
    pub selected_report_ids: HashSet<String>,
    pub focused_report_id: Option<String>,
    pub pending_confirmation: Option<PendingConfirmation>,
    pub status_message: String,
    pub base_pixels_per_point: Option<f32>,
    pub last_applied_scale: Option<f32>,
    pub ui_metrics: UiMetrics,
    pub last_download_poll: Instant,
    pub download_watch: HashMap<String, DownloadWatchEntry>,
    pub download_status: String,
}

#[derive(Debug, Clone)]
pub struct JobProgressUpdate {
    pub processed_files: usize,
    pub processed_bytes: u64,
    pub current_path: String,
    pub current_stage: String,
    pub current_file_progress: f32,
    pub current_file_elapsed_ms: u64,
    pub current_file_size: u64,
    pub total_elapsed_ms: u64,
    pub average_file_ms: u64,
    pub counts: (usize, usize, usize, usize),
    pub historical_bytes_per_ms: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct EtaEstimateInput {
    pub total_files: usize,
    pub total_bytes: u64,
    pub processed_files: usize,
    pub processed_bytes: u64,
    pub current_file_size: u64,
    pub current_file_progress: f32,
    pub current_file_elapsed_ms: u64,
    pub total_elapsed_ms: u64,
    pub average_file_ms: u64,
    pub historical_bytes_per_ms: f64,
}

#[cfg(test)]
mod tests {
    use super::{
        DetectionReason, QuarantineMetadata, RecordStorageState, ScanRecord, SeverityLevel, Verdict,
    };

    #[test]
    fn display_note_combines_primary_and_action_notes() {
        let record = ScanRecord {
            scan_id: "one".to_string(),
            path: "file.txt".to_string(),
            file_name: "file.txt".to_string(),
            extension: Some("txt".to_string()),
            sha256: None,
            sniffed_mime: None,
            detected_format: None,
            quarantine_path: None,
            report_path: None,
            storage_state: RecordStorageState::Unknown,
            last_modified_epoch: 0,
            scanned_at_epoch: 0,
            started_at_epoch: None,
            finished_at_epoch: None,
            duration_ms: 0,
            file_size_bytes: 0,
            verdict: Verdict::Suspicious,
            severity: SeverityLevel::Medium,
            summary_text: "Primary".to_string(),
            action_note: "Action".to_string(),
            risk_score: None,
            safety_score: None,
            signal_sources: vec!["heuristic".to_string()],
            detection_reasons: vec![DetectionReason::default()],
            warning_count: 1,
            error_count: 0,
            quarantine: QuarantineMetadata::default(),
        };

        assert_eq!(record.display_note(), "Primary | Action");
    }

    #[test]
    fn quick_type_prefers_detected_format() {
        let record = ScanRecord {
            scan_id: "two".to_string(),
            path: "file.bin".to_string(),
            file_name: "file.bin".to_string(),
            extension: Some("bin".to_string()),
            sha256: None,
            sniffed_mime: Some("application/octet-stream".to_string()),
            detected_format: Some("Pe".to_string()),
            quarantine_path: None,
            report_path: None,
            storage_state: RecordStorageState::Unknown,
            last_modified_epoch: 0,
            scanned_at_epoch: 0,
            started_at_epoch: None,
            finished_at_epoch: None,
            duration_ms: 0,
            file_size_bytes: 0,
            verdict: Verdict::Clean,
            severity: SeverityLevel::Clean,
            summary_text: String::new(),
            action_note: String::new(),
            risk_score: None,
            safety_score: None,
            signal_sources: Vec::new(),
            detection_reasons: Vec::new(),
            warning_count: 0,
            error_count: 0,
            quarantine: QuarantineMetadata::default(),
        };

        assert_eq!(record.quick_type_label(), "Pe");
    }
}
