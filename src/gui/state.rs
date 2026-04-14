use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Instant;

use crossbeam_channel::Receiver;
use notify::RecommendedWatcher;
use serde::{Deserialize, Serialize};

pub use crate::r#static::report::{
    NormalizedSeverity as SeverityLevel, QuarantineMetadata,
    QuarantineStatus as RecordStorageState, ReportReason as DetectionReason,
    ReportSummary as ScanRecord, SummaryVerdict as Verdict,
};

pub const HISTORY_PATH: &str = "quarantine/gui_scan_history.json";
pub const INDEX_PATH: &str = "quarantine/gui_index.json";
pub const SETTINGS_PATH: &str = "quarantine/gui_settings.json";
pub const PROTECTION_EVENTS_PATH: &str = "quarantine/gui_protection_events.json";
pub const PROTECTION_BACKLOG_PATH: &str = "quarantine/gui_protection_backlog.json";
pub const SCAN_RECORD_LIMIT: usize = 500;
pub const TIMING_SAMPLE_LIMIT: usize = 2048;
pub const PROTECTION_EVENT_LIMIT: usize = 512;

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
            Self::History => "Operations",
            Self::Settings => "Settings",
            Self::About => "About",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Analytics => "◪",
            Self::Scanner => "◎",
            Self::Reports => "▤",
            Self::History => "◷",
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchedPathConfig {
    pub path: String,
    #[serde(default = "default_recursive_watch")]
    pub recursive: bool,
}

fn default_recursive_watch() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedGuiSettings {
    pub settings: SettingsState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectionEventKind {
    Queued,
    Deferred,
    Completed,
    Throttled,
    Skipped,
    Error,
}

impl ProtectionEventKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Deferred => "Deferred",
            Self::Completed => "Completed",
            Self::Throttled => "Throttled",
            Self::Skipped => "Skipped",
            Self::Error => "Error",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ProtectionChangeClass {
    #[default]
    Modified,
    Created,
    Replaced,
}

impl ProtectionChangeClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Created => "Created",
            Self::Modified => "Modified",
            Self::Replaced => "Replaced",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ProtectionFileClass {
    Executable,
    Script,
    Archive,
    Document,
    TempCache,
    #[default]
    Other,
}

impl ProtectionFileClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Executable => "Executable",
            Self::Script => "Script",
            Self::Archive => "Archive",
            Self::Document => "Document",
            Self::TempCache => "Temp/cache",
            Self::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ProtectionPriority {
    Low,
    #[default]
    Normal,
    High,
}

impl ProtectionPriority {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Normal => "Normal",
            Self::High => "High",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtectionEvent {
    pub id: String,
    pub timestamp_epoch: u64,
    pub path: String,
    pub kind: String,
    pub note: String,
    #[serde(default)]
    pub workflow_source: String,
    #[serde(default)]
    pub event_source: String,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub storage_state: Option<String>,
    #[serde(default)]
    pub scan_id: Option<String>,
    #[serde(default = "default_grouped_change_count")]
    pub grouped_change_count: usize,
    #[serde(default)]
    pub burst_window_seconds: u64,
    #[serde(default)]
    pub change_class: ProtectionChangeClass,
    #[serde(default)]
    pub file_class: ProtectionFileClass,
    #[serde(default)]
    pub priority: ProtectionPriority,
}

fn default_grouped_change_count() -> usize {
    1
}

#[derive(Debug, Clone, Default)]
pub struct ProtectionSummary {
    pub enabled: bool,
    pub monitor_mode: String,
    pub monitor_state: String,
    pub watched_path_count: usize,
    pub tracked_file_count: usize,
    pub recent_event_count: usize,
    pub queued_event_count: usize,
    pub deferred_event_count: usize,
    pub throttled_event_count: usize,
    pub skipped_event_count: usize,
    pub backlog_count: usize,
    pub queue_health: String,
    pub queue_health_detail: String,
    pub event_drop_rate: String,
    pub dedupe_efficiency: String,
    pub backlog_recovery_rate: String,
    pub active_status: String,
    pub last_event_label: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedIndex {
    pub entries: Vec<ScanRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub path: PathBuf,
    pub last_modified_epoch: u64,
    pub size_bytes: u64,
    pub origin: ScanOrigin,
    pub priority: ProtectionPriority,
    pub file_class: ProtectionFileClass,
    #[serde(default = "default_grouped_change_count")]
    pub grouped_change_count: usize,
    #[serde(default)]
    pub burst_window_seconds: u64,
    #[serde(default)]
    pub change_class: ProtectionChangeClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanOrigin {
    Manual,
    DownloadMonitor,
    RealTimeProtection,
}

impl ScanOrigin {
    pub fn label(self) -> &'static str {
        match self {
            Self::Manual => "Manual scan",
            Self::DownloadMonitor => "Download monitoring",
            Self::RealTimeProtection => "Real-time protection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionEventKindFilter {
    All,
    Queued,
    Deferred,
    Completed,
    Throttled,
    Skipped,
    Error,
}

impl ProtectionEventKindFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All events",
            Self::Queued => "Queued",
            Self::Deferred => "Deferred",
            Self::Completed => "Completed",
            Self::Throttled => "Throttled",
            Self::Skipped => "Skipped",
            Self::Error => "Errors",
        }
    }

    pub fn matches(self, kind: &str) -> bool {
        match self {
            Self::All => true,
            Self::Queued => kind == ProtectionEventKind::Queued.label(),
            Self::Deferred => kind == ProtectionEventKind::Deferred.label(),
            Self::Completed => kind == ProtectionEventKind::Completed.label(),
            Self::Throttled => kind == ProtectionEventKind::Throttled.label(),
            Self::Skipped => kind == ProtectionEventKind::Skipped.label(),
            Self::Error => kind == ProtectionEventKind::Error.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionFileClassFilter {
    All,
    Executable,
    Script,
    Archive,
    Document,
    TempCache,
    Other,
}

impl ProtectionFileClassFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All file classes",
            Self::Executable => "Executable",
            Self::Script => "Script",
            Self::Archive => "Archive",
            Self::Document => "Document",
            Self::TempCache => "Temp/cache",
            Self::Other => "Other",
        }
    }

    pub fn matches(self, class: ProtectionFileClass) -> bool {
        match self {
            Self::All => true,
            Self::Executable => class == ProtectionFileClass::Executable,
            Self::Script => class == ProtectionFileClass::Script,
            Self::Archive => class == ProtectionFileClass::Archive,
            Self::Document => class == ProtectionFileClass::Document,
            Self::TempCache => class == ProtectionFileClass::TempCache,
            Self::Other => class == ProtectionFileClass::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionPriorityFilter {
    All,
    High,
    Normal,
    Low,
}

impl ProtectionPriorityFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All priorities",
            Self::High => "High",
            Self::Normal => "Normal",
            Self::Low => "Low",
        }
    }

    pub fn matches(self, priority: ProtectionPriority) -> bool {
        match self {
            Self::All => true,
            Self::High => priority == ProtectionPriority::High,
            Self::Normal => priority == ProtectionPriority::Normal,
            Self::Low => priority == ProtectionPriority::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionOriginFilter {
    All,
    RealTimeProtection,
    DownloadMonitoring,
    Manual,
}

impl ProtectionOriginFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All origins",
            Self::RealTimeProtection => "Real-time protection",
            Self::DownloadMonitoring => "Download monitoring",
            Self::Manual => "Manual scan",
        }
    }

    pub fn matches(self, origin: &str) -> bool {
        match self {
            Self::All => true,
            Self::RealTimeProtection => origin == ScanOrigin::RealTimeProtection.label(),
            Self::DownloadMonitoring => origin == ScanOrigin::DownloadMonitor.label(),
            Self::Manual => origin == ScanOrigin::Manual.label(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionVerdictFilter {
    All,
    Clean,
    Suspicious,
    Malicious,
    Error,
    None,
}

impl ProtectionVerdictFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All results",
            Self::Clean => "Clean",
            Self::Suspicious => "Suspicious",
            Self::Malicious => "Malicious",
            Self::Error => "Errors",
            Self::None => "No result yet",
        }
    }

    pub fn matches(self, verdict: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::Clean => verdict == Some("Clean"),
            Self::Suspicious => verdict == Some("Suspicious"),
            Self::Malicious => verdict == Some("Malicious"),
            Self::Error => verdict == Some("Error"),
            Self::None => verdict.is_none(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionActionFilter {
    All,
    Quarantined,
    Restored,
    Deleted,
    Unknown,
    None,
}

impl ProtectionActionFilter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "All actions",
            Self::Quarantined => "In quarantine",
            Self::Restored => "Restored",
            Self::Deleted => "Deleted",
            Self::Unknown => "Unknown",
            Self::None => "No action yet",
        }
    }

    pub fn matches(self, action: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::Quarantined => action == Some("In quarantine"),
            Self::Restored => action == Some("Restored"),
            Self::Deleted => action == Some("Deleted"),
            Self::Unknown => action == Some("Unknown"),
            Self::None => action.is_none(),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub enable_local_intelligence: bool,
    pub enable_external_intelligence: bool,
    pub enable_real_time_protection: bool,
    pub enable_download_monitoring: bool,
    #[serde(default = "default_enable_automatic_updates")]
    pub enable_automatic_updates: bool,
    #[serde(default)]
    pub watched_paths: Vec<WatchedPathConfig>,
}

fn default_enable_automatic_updates() -> bool {
    true
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
            enable_local_intelligence: true,
            enable_external_intelligence: false,
            enable_real_time_protection: false,
            enable_download_monitoring: false,
            enable_automatic_updates: true,
            watched_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AvailableUpdate {
    pub version: String,
    pub tag_name: String,
    pub published_at: String,
    pub html_url: String,
    pub asset_name: String,
    pub asset_url: String,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct UpdateCheckState {
    pub checking: bool,
    pub current_version: String,
    pub status: String,
    pub last_checked_epoch: u64,
    pub available_update: Option<AvailableUpdate>,
    pub last_error: Option<String>,
}

impl Default for UpdateCheckState {
    fn default() -> Self {
        Self {
            checking: false,
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            status: "Update checks have not run yet.".to_string(),
            last_checked_epoch: 0,
            available_update: None,
            last_error: None,
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

#[derive(Debug, Clone, Default)]
pub struct ProtectionWatchEntry {
    pub modified_epoch: u64,
    pub size_bytes: u64,
    pub last_queued_epoch: u64,
    pub burst_started_epoch: u64,
    pub burst_last_epoch: u64,
    pub grouped_change_count: usize,
    pub last_change_class: ProtectionChangeClass,
    pub needs_rescan: bool,
}

#[derive(Debug, Clone)]
pub struct ProtectionMonitorEvent {
    pub path: PathBuf,
    pub change_class: ProtectionChangeClass,
    pub source_label: String,
}

#[derive(Debug, Clone)]
pub enum ProtectionMonitorMessage {
    Event(ProtectionMonitorEvent),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectionMonitorMode {
    #[default]
    Disabled,
    EventDriven,
    PollingFallback,
}

impl ProtectionMonitorMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "Disabled",
            Self::EventDriven => "OS events",
            Self::PollingFallback => "Polling fallback",
        }
    }
}

pub struct ProtectionMonitorRuntime {
    pub mode: ProtectionMonitorMode,
    pub signature: String,
    pub source_label: String,
    pub health_note: String,
    pub last_error: Option<String>,
    pub receiver: Option<Receiver<ProtectionMonitorMessage>>,
    pub watcher: Option<RecommendedWatcher>,
}

impl Default for ProtectionMonitorRuntime {
    fn default() -> Self {
        Self {
            mode: ProtectionMonitorMode::Disabled,
            signature: String::new(),
            source_label: String::new(),
            health_note: String::new(),
            last_error: None,
            receiver: None,
            watcher: None,
        }
    }
}

impl std::fmt::Debug for ProtectionMonitorRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectionMonitorRuntime")
            .field("mode", &self.mode)
            .field("signature", &self.signature)
            .field("source_label", &self.source_label)
            .field("health_note", &self.health_note)
            .field("last_error", &self.last_error)
            .finish()
    }
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
    pub protection_path_input: String,
    pub single_file_path: String,
    pub report_search: String,
    pub history_search: String,
    pub protection_event_search: String,
    pub report_verdict_filter: ReportVerdictFilter,
    pub report_storage_filter: ReportStorageFilter,
    pub report_sort_order: ReportSortOrder,
    pub protection_kind_filter: ProtectionEventKindFilter,
    pub protection_file_filter: ProtectionFileClassFilter,
    pub protection_priority_filter: ProtectionPriorityFilter,
    pub protection_origin_filter: ProtectionOriginFilter,
    pub protection_verdict_filter: ProtectionVerdictFilter,
    pub protection_action_filter: ProtectionActionFilter,
    pub history_quarantine_only: bool,
    pub selected_report_ids: HashSet<String>,
    pub focused_report_id: Option<String>,
    pub pending_confirmation: Option<PendingConfirmation>,
    pub status_message: String,
    pub base_pixels_per_point: Option<f32>,
    pub last_applied_scale: Option<f32>,
    pub ui_metrics: UiMetrics,
    pub last_protection_poll: Instant,
    pub protection_watch: HashMap<String, ProtectionWatchEntry>,
    pub protection_events: Vec<ProtectionEvent>,
    pub protection_backlog: VecDeque<ScanTarget>,
    pub protection_monitor: ProtectionMonitorRuntime,
    pub protection_status: String,
    pub protection_summary: ProtectionSummary,
    pub last_download_poll: Instant,
    pub download_watch: HashMap<String, DownloadWatchEntry>,
    pub download_status: String,
    pub last_update_poll: Instant,
    pub update_state: std::sync::Arc<std::sync::Mutex<UpdateCheckState>>,
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
