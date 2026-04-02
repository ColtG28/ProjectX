use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use egui::{
    Align, Align2, CentralPanel, FontFamily, FontId, Layout, ProgressBar, SidePanel, TextEdit,
    TextStyle, TopBottomPanel,
};
use serde::{Deserialize, Serialize};

const HISTORY_PATH: &str = "quarantine/gui_scan_history.json";
const TIMING_SAMPLE_LIMIT: usize = 2048;

pub fn gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([920.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "ProjectX Security System",
        options,
        Box::new(|_cc| Box::new(MyApp::new())),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Analytics,
    Scanner,
    Reports,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimePeriod {
    Last24Hours,
    Last7Days,
    Last30Days,
    AllTime,
}

impl TimePeriod {
    fn label(self) -> &'static str {
        match self {
            Self::Last24Hours => "Last 24h",
            Self::Last7Days => "Last 7d",
            Self::Last30Days => "Last 30d",
            Self::AllTime => "All time",
        }
    }

    fn cutoff_epoch(self, now_epoch: u64) -> u64 {
        match self {
            Self::Last24Hours => now_epoch.saturating_sub(24 * 60 * 60),
            Self::Last7Days => now_epoch.saturating_sub(7 * 24 * 60 * 60),
            Self::Last30Days => now_epoch.saturating_sub(30 * 24 * 60 * 60),
            Self::AllTime => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Verdict {
    Good,
    Malicious,
    Unsure,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Good => "Good",
            Verdict::Malicious => "Malicious",
            Verdict::Unsure => "Unsure",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
enum RecordStorageState {
    #[default]
    Unknown,
    Restored,
    InQuarantine,
    Deleted,
}

impl RecordStorageState {
    fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Restored => "Back in place",
            Self::InQuarantine => "In quarantine",
            Self::Deleted => "Deleted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanRecord {
    path: String,
    #[serde(default)]
    quarantine_path: Option<String>,
    #[serde(default)]
    storage_state: RecordStorageState,
    last_modified_epoch: u64,
    scanned_at_epoch: u64,
    duration_ms: u64,
    #[serde(default)]
    file_size_bytes: u64,
    verdict: Verdict,
    note: String,
    #[serde(default)]
    action_note: String,
}

impl ScanRecord {
    fn resolved_storage_state(&self) -> RecordStorageState {
        if let Some(path) = self.quarantine_path.as_deref() {
            if Path::new(path).is_file() {
                return RecordStorageState::InQuarantine;
            }
        }

        match self.storage_state {
            RecordStorageState::Deleted => RecordStorageState::Deleted,
            RecordStorageState::Restored => RecordStorageState::Restored,
            RecordStorageState::InQuarantine => {
                if Path::new(&self.path).is_file() {
                    RecordStorageState::Restored
                } else {
                    RecordStorageState::Unknown
                }
            }
            RecordStorageState::Unknown => {
                if matches!(self.verdict, Verdict::Good) && Path::new(&self.path).is_file() {
                    RecordStorageState::Restored
                } else {
                    RecordStorageState::Unknown
                }
            }
        }
    }

    fn display_note(&self) -> String {
        match (self.note.trim(), self.action_note.trim()) {
            ("", "") => String::new(),
            ("", action) => action.to_string(),
            (note, "") => note.to_string(),
            (note, action) => format!("{note} | {action}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimingSample {
    file_size_bytes: u64,
    duration_ms: u64,
    scanned_at_epoch: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedHistory {
    records: Vec<ScanRecord>,
    #[serde(default)]
    timing_samples: Vec<TimingSample>,
}

#[derive(Debug, Clone)]
struct ScanTarget {
    path: PathBuf,
    last_modified_epoch: u64,
    size_bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct ScanJobState {
    running: bool,
    total: usize,
    total_bytes: u64,
    processed: usize,
    processed_bytes: u64,
    queued_files: usize,
    queued_bytes: u64,
    good: usize,
    malicious: usize,
    unsure: usize,
    current_path: String,
    current_stage: String,
    current_file_progress: f32,
    current_file_elapsed_ms: u64,
    current_file_size: u64,
    average_file_ms: u64,
    elapsed_ms: u64,
    eta_seconds: u64,
    finished: bool,
    new_records: Vec<ScanRecord>,
    new_timing_samples: Vec<TimingSample>,
    summary: String,
    pending_targets: VecDeque<ScanTarget>,
}

#[derive(Debug, Clone)]
struct SettingsState {
    include_entire_filesystem: bool,
    check_cached_scans: bool,
    max_files_per_bulk_scan: usize,
    enable_file_checks: bool,
    enable_string_extraction: bool,
    enable_normalization: bool,
    enable_decode: bool,
    enable_script_parsing: bool,
    enable_format_analysis: bool,
    enable_yara: bool,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            include_entire_filesystem: false,
            check_cached_scans: true,
            max_files_per_bulk_scan: 50_000,
            enable_file_checks: true,
            enable_string_extraction: true,
            enable_normalization: true,
            enable_decode: true,
            enable_script_parsing: true,
            enable_format_analysis: true,
            enable_yara: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RecordAction {
    Restore,
    Delete,
    Leave,
}

#[derive(Debug, Clone, Copy)]
struct UiMetrics {
    scale_factor: f32,
    menu_width: f32,
    compact: bool,
    content_max_width: f32,
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
struct TimingProfile {
    average_file_ms: u64,
    average_bytes_per_ms: f64,
}

impl TimingProfile {
    fn from_samples(samples: &[TimingSample]) -> Self {
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

    fn estimate_file_ms(self, size_bytes: u64) -> u64 {
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

struct MyApp {
    current_page: Page,
    menu_open: bool,
    period: TimePeriod,
    boot_until: Instant,
    records: Vec<ScanRecord>,
    timing_samples: Vec<TimingSample>,
    job: Arc<Mutex<ScanJobState>>,
    settings: SettingsState,
    single_file_path: String,
    report_search: String,
    status_message: String,
    base_pixels_per_point: Option<f32>,
    last_applied_scale: Option<f32>,
    ui_metrics: UiMetrics,
}

impl MyApp {
    fn new() -> Self {
        let persisted = load_history();
        Self {
            current_page: Page::Analytics,
            menu_open: true,
            period: TimePeriod::Last7Days,
            boot_until: Instant::now() + Duration::from_millis(1200),
            records: persisted.records,
            timing_samples: persisted.timing_samples,
            job: Arc::new(Mutex::new(ScanJobState::default())),
            settings: SettingsState::default(),
            single_file_path: String::new(),
            report_search: String::new(),
            status_message: String::new(),
            base_pixels_per_point: None,
            last_applied_scale: None,
            ui_metrics: UiMetrics::default(),
        }
    }

    fn is_booting(&self) -> bool {
        Instant::now() < self.boot_until
    }

    fn is_loading(&self) -> bool {
        if self.is_booting() {
            return true;
        }
        self.job.lock().map(|j| j.running).unwrap_or(false)
    }

    fn scan_config(&self) -> crate::r#static::config::ScanConfig {
        let mut config = crate::r#static::config::ScanConfig::default();
        config.features.enable_file_checks = self.settings.enable_file_checks;
        config.features.enable_string_extraction = self.settings.enable_string_extraction;
        config.features.enable_normalization =
            self.settings.enable_string_extraction && self.settings.enable_normalization;
        config.features.enable_decode =
            self.settings.enable_string_extraction && self.settings.enable_decode;
        config.features.enable_script_parsing =
            self.settings.enable_string_extraction && self.settings.enable_script_parsing;
        config.features.enable_format_analysis = self.settings.enable_format_analysis;
        config.features.enable_yara = self.settings.enable_yara;
        config
    }

    fn apply_responsive_scaling(&mut self, ctx: &egui::Context) {
        let screen = ctx.screen_rect();
        let width_points = screen.width().max(640.0);
        let height_points = screen.height().max(480.0);
        let physical_width = width_points * ctx.pixels_per_point();
        let physical_height = height_points * ctx.pixels_per_point();
        let compact = physical_width < 1120.0;
        let scale = if physical_width < 900.0 {
            0.92
        } else if physical_width < 1280.0 {
            0.98
        } else if physical_width < 1720.0 {
            1.0
        } else if physical_width < 2240.0 {
            1.06
        } else {
            1.12
        };

        let base = *self
            .base_pixels_per_point
            .get_or_insert_with(|| ctx.pixels_per_point());
        let target_pixels_per_point = (base * scale).clamp(base * 0.9, base * 1.15);
        if (ctx.pixels_per_point() - target_pixels_per_point).abs() > 0.01 {
            ctx.set_pixels_per_point(target_pixels_per_point);
        }

        if self
            .last_applied_scale
            .map(|previous| (previous - scale).abs() > 0.01)
            .unwrap_or(true)
        {
            let mut style = (*ctx.style()).clone();
            style.spacing.item_spacing = egui::vec2(10.0 * scale, 10.0 * scale);
            style.spacing.button_padding = egui::vec2(10.0 * scale, 7.0 * scale);
            style.text_styles.insert(
                TextStyle::Body,
                FontId::new((14.0 * scale).clamp(13.0, 17.0), FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Button,
                FontId::new((14.0 * scale).clamp(13.0, 17.0), FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Heading,
                FontId::new((22.0 * scale).clamp(20.0, 28.0), FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Monospace,
                FontId::new((13.0 * scale).clamp(12.0, 16.0), FontFamily::Monospace),
            );
            ctx.set_style(style);
            self.last_applied_scale = Some(scale);
        }

        self.ui_metrics = UiMetrics {
            scale_factor: scale,
            menu_width: if compact {
                (width_points * 0.22).clamp(132.0, 168.0)
            } else if physical_width < 1600.0 {
                172.0 * scale
            } else {
                192.0 * scale
            },
            compact,
            content_max_width: if compact {
                width_points - 40.0
            } else {
                (width_points * 0.76).min(if physical_height < 900.0 {
                    780.0
                } else {
                    900.0
                })
            },
        };
    }

    fn render_boot_screen(&self, ctx: &egui::Context) {
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(160.0 * self.ui_metrics.scale_factor);
                ui.heading("ProjectX");
                ui.label("Loading security dashboard...");
                ui.add_space(12.0 * self.ui_metrics.scale_factor);
                ui.spinner();
            });
        });
    }

    fn render_top_bar(&mut self, ctx: &egui::Context) {
        TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("☰").clicked() {
                    self.menu_open = !self.menu_open;
                }
                ui.heading("ProjectX Security");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("⚙").clicked() {
                        self.current_page = Page::Settings;
                    }
                });
            });
        });
    }

    fn render_menu(&mut self, ctx: &egui::Context) {
        if !self.menu_open {
            return;
        }
        SidePanel::left("side_menu")
            .default_width(self.ui_metrics.menu_width)
            .resizable(!self.ui_metrics.compact)
            .show(ctx, |ui| {
                ui.heading("Menu");
                ui.separator();
                self.page_button(ui, Page::Analytics, "Analytics");
                self.page_button(ui, Page::Scanner, "File Scanner");
                self.page_button(ui, Page::Reports, "Reports");
                self.page_button(ui, Page::Settings, "Settings");
            });
    }

    fn page_button(&mut self, ui: &mut egui::Ui, page: Page, label: &str) {
        let selected = self.current_page == page;
        if ui.selectable_label(selected, label).clicked() {
            self.current_page = page;
        }
    }

    fn render_analytics(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Analytics");
            egui::ComboBox::from_label("Time period")
                .selected_text(self.period.label())
                .show_ui(ui, |ui| {
                    for period in [
                        TimePeriod::Last24Hours,
                        TimePeriod::Last7Days,
                        TimePeriod::Last30Days,
                        TimePeriod::AllTime,
                    ] {
                        ui.selectable_value(&mut self.period, period, period.label());
                    }
                });
        });
        ui.separator();

        let now = now_epoch();
        let cutoff = self.period.cutoff_epoch(now);
        let filtered = self
            .records
            .iter()
            .filter(|record| record.scanned_at_epoch >= cutoff)
            .collect::<Vec<_>>();

        let files_scanned = filtered.len();
        let malicious_found = filtered
            .iter()
            .filter(|record| record.verdict == Verdict::Malicious)
            .count();
        let unsure_found = filtered
            .iter()
            .filter(|record| record.verdict == Verdict::Unsure)
            .count();

        ui.group(|ui| {
            ui.label(format!("Files scanned: {}", files_scanned));
            ui.label(format!("Malicious files found: {}", malicious_found));
            ui.label(format!("Unsure files: {}", unsure_found));
        });

        ui.separator();
        ui.heading("Latest 2 scanned files");
        let recent = filtered.iter().rev().take(2).collect::<Vec<_>>();
        if recent.is_empty() {
            ui.label("No scans recorded in this time period.");
        } else {
            for record in recent {
                ui.group(|ui| {
                    ui.label(format!("Path: {}", record.path));
                    ui.label(format!(
                        "Verdict: {} | Duration: {} | Size: {}",
                        record.verdict.label(),
                        format_elapsed_ms(record.duration_ms),
                        format_bytes(record.file_size_bytes)
                    ));
                });
            }
        }
    }

    fn render_scanner(&mut self, ui: &mut egui::Ui) {
        ui.heading("File Scanner");
        ui.label("Scan a single file or folder, queue more work while scanning, and watch live stage-by-stage progress.");
        ui.separator();

        let path_button_label = if self.is_loading() {
            "Queue path"
        } else {
            "Scan path"
        };
        if self.ui_metrics.compact {
            ui.vertical(|ui| {
                ui.label("File or folder path");
                ui.add_sized(
                    [ui.available_width(), 0.0],
                    TextEdit::singleline(&mut self.single_file_path)
                        .hint_text("/path/to/file-or-folder"),
                );
                if ui.button(path_button_label).clicked() {
                    self.submit_manual_path();
                }
            });
        } else {
            ui.horizontal(|ui| {
                ui.label("Path");
                ui.add_sized(
                    [ui.available_width() * 0.72, 0.0],
                    TextEdit::singleline(&mut self.single_file_path)
                        .hint_text("/path/to/file-or-folder"),
                );
                if ui.button(path_button_label).clicked() {
                    self.submit_manual_path();
                }
            });
        }

        ui.horizontal_wrapped(|ui| {
            let common_label = if self.is_loading() {
                "Queue common folders"
            } else {
                "Scan common folders"
            };
            if ui.button(common_label).clicked() {
                let mut roots = Vec::new();
                if let Some(home) = home_dir() {
                    roots.push(home.join("Desktop"));
                    roots.push(home.join("Documents"));
                    roots.push(home.join("Downloads"));
                }
                self.start_scan_from_roots(roots);
            }

            let all_label = if self.is_loading() {
                "Queue all files"
            } else {
                "Scan all files"
            };
            if ui.button(all_label).clicked() {
                let roots = if self.settings.include_entire_filesystem {
                    vec![PathBuf::from("/")]
                } else {
                    vec![home_dir().unwrap_or_else(|| PathBuf::from("/"))]
                };
                self.start_scan_from_roots(roots);
            }
        });

        if !self.status_message.is_empty() {
            ui.separator();
            ui.label(&self.status_message);
        }

        ui.separator();
        let snapshot = self.job.lock().map(|job| job.clone()).unwrap_or_default();
        let progress_width = if self.ui_metrics.compact {
            (ui.available_width() - 12.0).max(210.0)
        } else {
            ui.available_width().min(560.0)
        };
        let overall_progress = overall_progress(&snapshot);
        ui.label(format!(
            "Overall progress: {}/{} files | queued: {}",
            snapshot.processed, snapshot.total, snapshot.queued_files
        ));
        ui.add_sized(
            [progress_width, 0.0],
            ProgressBar::new(overall_progress).show_percentage(),
        );

        if snapshot.total_bytes > 0 {
            let completed_bytes = snapshot.processed_bytes
                + ((snapshot.current_file_size as f32
                    * snapshot.current_file_progress.clamp(0.0, 1.0)) as u64);
            ui.label(format!(
                "Scanned data: {} / {} | queued data: {}",
                format_bytes(completed_bytes),
                format_bytes(snapshot.total_bytes),
                format_bytes(snapshot.queued_bytes)
            ));
        }

        ui.separator();
        ui.label("Current file progress");
        ui.add_sized(
            [progress_width, 0.0],
            ProgressBar::new(snapshot.current_file_progress.clamp(0.0, 1.0)).show_percentage(),
        );
        ui.label(format!(
            "Current file: {}",
            if snapshot.current_path.is_empty() {
                "Waiting for queued work".to_string()
            } else {
                snapshot.current_path.clone()
            }
        ));
        ui.label(format!(
            "Section: {}",
            if snapshot.current_stage.is_empty() {
                "Idle".to_string()
            } else {
                snapshot.current_stage.clone()
            }
        ));
        ui.label(format!(
            "Current file elapsed: {} | Estimated time remaining: {}",
            format_elapsed_ms(snapshot.current_file_elapsed_ms),
            format_eta(snapshot.eta_seconds)
        ));
        ui.label(format!(
            "Good: {}  Malicious: {}  Unsure: {}",
            snapshot.good, snapshot.malicious, snapshot.unsure
        ));
        if !snapshot.summary.is_empty() {
            ui.label(format!("Last report: {}", snapshot.summary));
        }

        ui.separator();
        ui.heading("Recent scan results");
        egui::ScrollArea::vertical()
            .max_height(if self.ui_metrics.compact {
                220.0
            } else {
                280.0
            })
            .show(ui, |ui| {
                let indices = self.filtered_record_indices(15, "");
                self.render_record_list(ui, &indices);
            });
    }

    fn render_reports(&mut self, ui: &mut egui::Ui) {
        ui.heading("Reports");
        ui.label("Search recent scans and manage quarantined files.");
        ui.separator();

        ui.add_sized(
            [
                ui.available_width()
                    .min(self.ui_metrics.content_max_width - 16.0)
                    .max(220.0),
                0.0,
            ],
            TextEdit::singleline(&mut self.report_search)
                .hint_text("Search by path, note, verdict, storage, or quarantine path"),
        );
        let indices = self.filtered_record_indices(300, self.report_search.trim());
        ui.label(format!("Showing {} result(s)", indices.len()));
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| self.render_record_list(ui, &indices));
    }

    fn render_record_list(&mut self, ui: &mut egui::Ui, indices: &[usize]) {
        let mut pending_action = None;

        for &index in indices {
            let record = self.records[index].clone();
            let storage_state = record.resolved_storage_state();
            let note = record.display_note();

            ui.group(|ui| {
                ui.label(format!("Original path: {}", record.path));
                if let Some(quarantine_path) = record.quarantine_path.as_deref() {
                    ui.label(format!("Quarantine path: {}", quarantine_path));
                }
                ui.label(format!(
                    "Verdict: {} | Stored: {} | Duration: {} | Size: {} | Last modified: {}",
                    record.verdict.label(),
                    storage_state.label(),
                    format_elapsed_ms(record.duration_ms),
                    format_bytes(record.file_size_bytes),
                    record.last_modified_epoch
                ));
                if !note.is_empty() {
                    ui.label(format!("Note: {}", note));
                }

                let in_quarantine = matches!(storage_state, RecordStorageState::InQuarantine)
                    && record.quarantine_path.is_some();

                if self.ui_metrics.compact {
                    ui.vertical(|ui| {
                        if ui
                            .add_enabled(in_quarantine, egui::Button::new("Put back"))
                            .clicked()
                        {
                            pending_action = Some((index, RecordAction::Restore));
                        }
                        if ui
                            .add_enabled(in_quarantine, egui::Button::new("Delete"))
                            .clicked()
                        {
                            pending_action = Some((index, RecordAction::Delete));
                        }
                        if ui
                            .add_enabled(in_quarantine, egui::Button::new("Leave in quarantine"))
                            .clicked()
                        {
                            pending_action = Some((index, RecordAction::Leave));
                        }
                    });
                } else {
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(in_quarantine, egui::Button::new("Put back"))
                            .clicked()
                        {
                            pending_action = Some((index, RecordAction::Restore));
                        }
                        if ui
                            .add_enabled(in_quarantine, egui::Button::new("Delete"))
                            .clicked()
                        {
                            pending_action = Some((index, RecordAction::Delete));
                        }
                        if ui
                            .add_enabled(in_quarantine, egui::Button::new("Leave in quarantine"))
                            .clicked()
                        {
                            pending_action = Some((index, RecordAction::Leave));
                        }
                    });
                }
            });
        }

        if let Some((index, action)) = pending_action {
            self.apply_record_action(index, action);
        }
    }

    fn apply_record_action(&mut self, index: usize, action: RecordAction) {
        let Some(record) = self.records.get_mut(index) else {
            return;
        };

        let Some(quarantine_path) = record.quarantine_path.clone() else {
            self.status_message = "No quarantined file is recorded for that entry.".to_string();
            return;
        };

        let message = match action {
            RecordAction::Restore => {
                match crate::r#static::restore_quarantined_file(&quarantine_path, &record.path) {
                    Ok(()) => {
                        record.storage_state = RecordStorageState::Restored;
                        record.quarantine_path = None;
                        record.action_note = "User action: restored to original path.".to_string();
                        "File restored to its original location.".to_string()
                    }
                    Err(error) => format!("Restore failed: {error}"),
                }
            }
            RecordAction::Delete => {
                match crate::r#static::delete_quarantined_file(&quarantine_path) {
                    Ok(()) => {
                        record.storage_state = RecordStorageState::Deleted;
                        record.quarantine_path = None;
                        record.action_note = "User action: deleted from quarantine.".to_string();
                        "Quarantined file deleted.".to_string()
                    }
                    Err(error) => format!("Delete failed: {error}"),
                }
            }
            RecordAction::Leave => {
                if Path::new(&quarantine_path).is_file() {
                    record.storage_state = RecordStorageState::InQuarantine;
                    record.action_note = "User action: left in quarantine.".to_string();
                    "File left in quarantine.".to_string()
                } else {
                    "That file is no longer present in quarantine.".to_string()
                }
            }
        };

        self.status_message = message;
        save_history(&self.records, &self.timing_samples);
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();

        ui.checkbox(
            &mut self.settings.include_entire_filesystem,
            "Include entire filesystem for 'Scan all files' (can be very slow)",
        );
        ui.checkbox(
            &mut self.settings.check_cached_scans,
            "Skip files already scanned if last-edited timestamp matches",
        );

        ui.horizontal(|ui| {
            ui.label("Max files per bulk scan");
            ui.add(egui::DragValue::new(&mut self.settings.max_files_per_bulk_scan).speed(500.0));
        });

        ui.separator();
        ui.heading("Scanning stages");
        ui.label("Turn off broader generic stages if you want a lighter or narrower scan.");
        ui.checkbox(
            &mut self.settings.enable_file_checks,
            "File profiling and generic metadata checks",
        );
        ui.checkbox(
            &mut self.settings.enable_string_extraction,
            "String extraction",
        );
        ui.checkbox(
            &mut self.settings.enable_normalization,
            "String normalization",
        );
        ui.checkbox(&mut self.settings.enable_decode, "Generic decode attempts");
        ui.checkbox(
            &mut self.settings.enable_script_parsing,
            "Script heuristic parsing",
        );
        ui.checkbox(
            &mut self.settings.enable_format_analysis,
            "Format-specific analysis",
        );
        ui.checkbox(
            &mut self.settings.enable_yara,
            "YARA-style keyword matching",
        );

        ui.separator();
        ui.label(format!(
            "Stored timing samples for ETA learning: {}",
            self.timing_samples.len()
        ));
    }

    fn render_loading_indicator(&self, ctx: &egui::Context) {
        if !self.is_loading() {
            return;
        }

        egui::Area::new("global_loading_indicator")
            .anchor(Align2::RIGHT_BOTTOM, [-18.0, -18.0])
            .show(ctx, |ui| {
                ui.spinner();
            });
    }

    fn submit_manual_path(&mut self) {
        let input = self.single_file_path.trim().to_string();
        if input.is_empty() {
            self.status_message = "Enter a file or folder path first.".to_string();
        } else {
            self.start_scan_from_roots(vec![PathBuf::from(input)]);
        }
    }

    fn filtered_record_indices(&self, limit: usize, query: &str) -> Vec<usize> {
        (0..self.records.len())
            .rev()
            .filter(|&index| record_matches_query(&self.records[index], query))
            .take(limit)
            .collect()
    }

    fn poll_finished_job(&mut self) {
        let mut maybe_records = Vec::new();
        let mut maybe_timing_samples = Vec::new();

        if let Ok(mut job) = self.job.lock() {
            if job.finished {
                maybe_records = std::mem::take(&mut job.new_records);
                maybe_timing_samples = std::mem::take(&mut job.new_timing_samples);
                job.finished = false;
            }
        }

        if !maybe_records.is_empty() || !maybe_timing_samples.is_empty() {
            self.records.extend(maybe_records);
            self.timing_samples.extend(maybe_timing_samples);
            trim_timing_samples(&mut self.timing_samples);
            save_history(&self.records, &self.timing_samples);
        }
    }

    fn start_scan_from_roots(&mut self, roots: Vec<PathBuf>) {
        if roots.is_empty() {
            self.status_message = "No valid path was supplied.".to_string();
            return;
        }

        let missing = roots
            .iter()
            .filter(|path| !path.exists())
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            self.status_message = format!("Some paths do not exist: {}", missing.join(", "));
            return;
        }

        let targets = collect_scan_targets(&roots, self.settings.max_files_per_bulk_scan);
        self.start_scan(targets);
    }

    fn start_scan(&mut self, targets: Vec<ScanTarget>) {
        let targets = dedupe_targets(targets);
        if targets.is_empty() {
            self.status_message = "No files found to scan for this selection.".to_string();
            return;
        }

        if let Ok(mut job) = self.job.lock() {
            if job.running {
                let (added_count, added_bytes) = queue_targets_into_job(&mut job, targets);
                if added_count == 0 {
                    self.status_message =
                        "Those files are already queued or currently scanning.".to_string();
                } else {
                    self.status_message = format!(
                        "Queued {} file(s) for later scanning ({}).",
                        added_count,
                        format_bytes(added_bytes)
                    );
                }
                return;
            }
        }

        let latest_by_path = latest_record_map(&self.records);
        let timing_profile = TimingProfile::from_samples(&self.timing_samples);
        let config = self.scan_config();
        let total = targets.len();
        let total_bytes = targets.iter().map(|target| target.size_bytes).sum::<u64>();

        if let Ok(mut job) = self.job.lock() {
            *job = ScanJobState {
                running: true,
                total,
                total_bytes,
                queued_files: total,
                queued_bytes: total_bytes,
                average_file_ms: timing_profile.average_file_ms,
                current_stage: "Queued".to_string(),
                pending_targets: targets.into_iter().collect(),
                ..ScanJobState::default()
            };
        }

        self.status_message = format!(
            "Started scan for {} files ({} total).",
            total,
            format_bytes(total_bytes)
        );

        let job_ref = Arc::clone(&self.job);
        let check_cached = self.settings.check_cached_scans;
        thread::spawn(move || {
            run_scan_worker(
                job_ref,
                latest_by_path,
                timing_profile,
                config,
                check_cached,
            );
        });
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_responsive_scaling(ctx);
        self.poll_finished_job();

        if self.is_booting() {
            self.render_boot_screen(ctx);
            self.render_loading_indicator(ctx);
            ctx.request_repaint_after(Duration::from_millis(16));
            return;
        }

        self.render_top_bar(ctx);
        self.render_menu(ctx);

        CentralPanel::default().show(ctx, |ui| {
            ui.set_max_width(self.ui_metrics.content_max_width);
            match self.current_page {
                Page::Analytics => self.render_analytics(ui),
                Page::Scanner => self.render_scanner(ui),
                Page::Reports => self.render_reports(ui),
                Page::Settings => self.render_settings(ui),
            }
        });

        self.render_loading_indicator(ctx);

        if self.is_loading() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

#[derive(Debug, Clone)]
struct JobProgressUpdate {
    processed_files: usize,
    processed_bytes: u64,
    current_path: String,
    current_stage: String,
    current_file_progress: f32,
    current_file_elapsed_ms: u64,
    current_file_size: u64,
    total_elapsed_ms: u64,
    average_file_ms: u64,
    counts: (usize, usize, usize),
    historical_bytes_per_ms: f64,
}

#[derive(Debug, Clone, Copy)]
struct EtaEstimateInput {
    total_files: usize,
    total_bytes: u64,
    processed_files: usize,
    processed_bytes: u64,
    current_file_size: u64,
    current_file_progress: f32,
    current_file_elapsed_ms: u64,
    total_elapsed_ms: u64,
    average_file_ms: u64,
    historical_bytes_per_ms: f64,
}

fn update_job_progress(job_ref: &Arc<Mutex<ScanJobState>>, update: JobProgressUpdate) {
    if let Ok(mut job) = job_ref.lock() {
        job.processed = update.processed_files;
        job.processed_bytes = update.processed_bytes;
        job.current_path = update.current_path;
        job.current_stage = update.current_stage;
        job.current_file_progress = update.current_file_progress.clamp(0.0, 1.0);
        job.current_file_elapsed_ms = update.current_file_elapsed_ms;
        job.current_file_size = update.current_file_size;
        job.average_file_ms = update.average_file_ms;
        job.elapsed_ms = update.total_elapsed_ms;
        job.good = update.counts.0;
        job.malicious = update.counts.1;
        job.unsure = update.counts.2;
        job.queued_files = job.pending_targets.len();
        job.queued_bytes = job
            .pending_targets
            .iter()
            .map(|target| target.size_bytes)
            .sum::<u64>();
        job.eta_seconds = estimate_eta_seconds(EtaEstimateInput {
            total_files: job.total,
            total_bytes: job.total_bytes,
            processed_files: update.processed_files,
            processed_bytes: update.processed_bytes,
            current_file_size: update.current_file_size,
            current_file_progress: update.current_file_progress,
            current_file_elapsed_ms: update.current_file_elapsed_ms,
            total_elapsed_ms: update.total_elapsed_ms,
            average_file_ms: update.average_file_ms,
            historical_bytes_per_ms: update.historical_bytes_per_ms,
        });
    }
}

fn run_scan_worker(
    job_ref: Arc<Mutex<ScanJobState>>,
    latest_by_path: HashMap<String, ScanRecord>,
    timing_profile: TimingProfile,
    config: crate::r#static::config::ScanConfig,
    check_cached: bool,
) {
    let started = Instant::now();
    let mut local_records = Vec::new();
    let mut local_timing_samples = Vec::new();
    let mut good = 0usize;
    let mut malicious = 0usize;
    let mut unsure = 0usize;
    let mut processed_bytes = 0u64;
    let mut smoothed_duration_ms = Some(timing_profile.average_file_ms as f64);

    loop {
        let next_target = {
            let mut job = match job_ref.lock() {
                Ok(job) => job,
                Err(_) => return,
            };
            let target = job.pending_targets.pop_front();
            job.queued_files = job.pending_targets.len();
            job.queued_bytes = job
                .pending_targets
                .iter()
                .map(|queued| queued.size_bytes)
                .sum::<u64>();
            target
        };

        let Some(target) = next_target else {
            if let Ok(mut job) = job_ref.lock() {
                job.running = false;
                job.finished = true;
                job.current_path.clear();
                job.current_stage = "Idle".to_string();
                job.current_file_progress = 0.0;
                job.current_file_elapsed_ms = 0;
                job.current_file_size = 0;
                job.eta_seconds = 0;
                job.new_records = local_records;
                job.new_timing_samples = local_timing_samples;
                job.summary = format!(
                    "{} scanned | good={} malicious={} unsure={}",
                    job.processed, good, malicious, unsure
                );
            }
            break;
        };

        let processed_before = local_records.len();
        let current_path = target.path.to_string_lossy().to_string();
        let expected_duration_ms = blended_average_ms(
            smoothed_duration_ms,
            timing_profile.estimate_file_ms(target.size_bytes),
        );
        let mut duration_ms = 0u64;

        let mut record = if check_cached {
            if let Some(previous) = latest_by_path.get(&current_path) {
                if previous.last_modified_epoch == target.last_modified_epoch
                    && target.last_modified_epoch != 0
                {
                    update_job_progress(
                        &job_ref,
                        JobProgressUpdate {
                            processed_files: processed_before,
                            processed_bytes,
                            current_path: current_path.clone(),
                            current_stage: "Using cached result".to_string(),
                            current_file_progress: 1.0,
                            current_file_elapsed_ms: 0,
                            current_file_size: target.size_bytes,
                            total_elapsed_ms: started.elapsed().as_millis() as u64,
                            average_file_ms: expected_duration_ms,
                            counts: (good, malicious, unsure),
                            historical_bytes_per_ms: timing_profile.average_bytes_per_ms,
                        },
                    );
                    reused_cached_record(previous, target.last_modified_epoch, target.size_bytes)
                } else {
                    let current_file_started = Instant::now();
                    let mut record = run_scan(&target, &config, |update| {
                        update_job_progress(
                            &job_ref,
                            JobProgressUpdate {
                                processed_files: processed_before,
                                processed_bytes,
                                current_path: current_path.clone(),
                                current_stage: update.stage.to_string(),
                                current_file_progress: update.fraction,
                                current_file_elapsed_ms: current_file_started.elapsed().as_millis()
                                    as u64,
                                current_file_size: target.size_bytes,
                                total_elapsed_ms: started.elapsed().as_millis() as u64,
                                average_file_ms: expected_duration_ms,
                                counts: (good, malicious, unsure),
                                historical_bytes_per_ms: timing_profile.average_bytes_per_ms,
                            },
                        );
                    });
                    duration_ms = current_file_started.elapsed().as_millis() as u64;
                    record.duration_ms = duration_ms;
                    record
                }
            } else {
                let current_file_started = Instant::now();
                let mut record = run_scan(&target, &config, |update| {
                    update_job_progress(
                        &job_ref,
                        JobProgressUpdate {
                            processed_files: processed_before,
                            processed_bytes,
                            current_path: current_path.clone(),
                            current_stage: update.stage.to_string(),
                            current_file_progress: update.fraction,
                            current_file_elapsed_ms: current_file_started.elapsed().as_millis()
                                as u64,
                            current_file_size: target.size_bytes,
                            total_elapsed_ms: started.elapsed().as_millis() as u64,
                            average_file_ms: expected_duration_ms,
                            counts: (good, malicious, unsure),
                            historical_bytes_per_ms: timing_profile.average_bytes_per_ms,
                        },
                    );
                });
                duration_ms = current_file_started.elapsed().as_millis() as u64;
                record.duration_ms = duration_ms;
                record
            }
        } else {
            let current_file_started = Instant::now();
            let mut record = run_scan(&target, &config, |update| {
                update_job_progress(
                    &job_ref,
                    JobProgressUpdate {
                        processed_files: processed_before,
                        processed_bytes,
                        current_path: current_path.clone(),
                        current_stage: update.stage.to_string(),
                        current_file_progress: update.fraction,
                        current_file_elapsed_ms: current_file_started.elapsed().as_millis() as u64,
                        current_file_size: target.size_bytes,
                        total_elapsed_ms: started.elapsed().as_millis() as u64,
                        average_file_ms: expected_duration_ms,
                        counts: (good, malicious, unsure),
                        historical_bytes_per_ms: timing_profile.average_bytes_per_ms,
                    },
                );
            });
            duration_ms = current_file_started.elapsed().as_millis() as u64;
            record.duration_ms = duration_ms;
            record
        };

        match record.verdict {
            Verdict::Good => good += 1,
            Verdict::Malicious => malicious += 1,
            Verdict::Unsure => unsure += 1,
        }

        if duration_ms > 0 {
            smoothed_duration_ms = Some(match smoothed_duration_ms {
                Some(previous) => previous * 0.7 + duration_ms as f64 * 0.3,
                None => duration_ms as f64,
            });
            local_timing_samples.push(TimingSample {
                file_size_bytes: target.size_bytes,
                duration_ms,
                scanned_at_epoch: now_epoch(),
            });
        }

        processed_bytes = processed_bytes.saturating_add(target.size_bytes);
        record.scanned_at_epoch = now_epoch();
        local_records.push(record);

        update_job_progress(
            &job_ref,
            JobProgressUpdate {
                processed_files: local_records.len(),
                processed_bytes,
                current_path,
                current_stage: "Completed".to_string(),
                current_file_progress: 1.0,
                current_file_elapsed_ms: duration_ms,
                current_file_size: 0,
                total_elapsed_ms: started.elapsed().as_millis() as u64,
                average_file_ms: blended_average_ms(
                    smoothed_duration_ms,
                    timing_profile.average_file_ms,
                ),
                counts: (good, malicious, unsure),
                historical_bytes_per_ms: timing_profile.average_bytes_per_ms,
            },
        );
    }
}

fn blended_average_ms(smoothed_duration_ms: Option<f64>, fallback_ms: u64) -> u64 {
    match (smoothed_duration_ms, fallback_ms) {
        (Some(smoothed), 0) => smoothed.round() as u64,
        (None, 0) => 1_500,
        (None, fallback) => fallback.max(300),
        (Some(smoothed), fallback) => {
            (((smoothed * 0.65) + (fallback as f64 * 0.35)).round() as u64).max(300)
        }
    }
}

fn overall_progress(job: &ScanJobState) -> f32 {
    if job.total_bytes > 0 {
        let done_bytes = job.processed_bytes
            + ((job.current_file_size as f32 * job.current_file_progress.clamp(0.0, 1.0)) as u64);
        return (done_bytes as f32 / job.total_bytes as f32).clamp(0.0, 1.0);
    }

    if job.total == 0 {
        0.0
    } else {
        (job.processed as f32 / job.total as f32).clamp(0.0, 1.0)
    }
}

fn estimate_eta_seconds(input: EtaEstimateInput) -> u64 {
    let current_fraction = input.current_file_progress.clamp(0.0, 1.0) as f64;
    let virtual_done_bytes =
        input.processed_bytes as f64 + input.current_file_size as f64 * current_fraction;

    if input.total_bytes > 0 && virtual_done_bytes > 0.0 && input.total_elapsed_ms > 250 {
        let bytes_per_ms = virtual_done_bytes / input.total_elapsed_ms as f64;
        if bytes_per_ms > 0.0 {
            let remaining_bytes = input
                .total_bytes
                .saturating_sub(virtual_done_bytes.round() as u64);
            return ((remaining_bytes as f64 / bytes_per_ms) / 1000.0).ceil() as u64;
        }
    }

    if input.total_bytes > 0 && input.historical_bytes_per_ms > 0.0 {
        let remaining_bytes = input.total_bytes.saturating_sub(input.processed_bytes);
        return ((remaining_bytes as f64 / input.historical_bytes_per_ms) / 1000.0).ceil() as u64;
    }

    let remaining_current_ms = if input.current_file_size > 0 {
        if current_fraction > 0.05 {
            let estimated_total_ms = (input.current_file_elapsed_ms as f64 / current_fraction)
                .max(input.average_file_ms as f64);
            estimated_total_ms
                .max(input.current_file_elapsed_ms as f64)
                .round() as u64
                - input.current_file_elapsed_ms
        } else {
            input.average_file_ms
        }
    } else {
        0
    };

    let active_file_offset =
        usize::from(input.current_file_size > 0 && input.processed_files < input.total_files);
    let remaining_files = input
        .total_files
        .saturating_sub(input.processed_files + active_file_offset);
    ((remaining_current_ms + remaining_files as u64 * input.average_file_ms) as f64 / 1000.0).ceil()
        as u64
}

fn reused_cached_record(
    previous: &ScanRecord,
    modified_epoch: u64,
    file_size_bytes: u64,
) -> ScanRecord {
    let mut record = previous.clone();
    record.last_modified_epoch = modified_epoch;
    record.scanned_at_epoch = now_epoch();
    record.duration_ms = 0;
    record.file_size_bytes = file_size_bytes;
    record.note = if previous.note.is_empty() {
        "Already scanned before (unchanged file timestamp).".to_string()
    } else {
        format!(
            "Already scanned before (unchanged file timestamp). | {}",
            previous.note
        )
    };
    record
}

fn run_scan<F>(
    target: &ScanTarget,
    config: &crate::r#static::config::ScanConfig,
    progress: F,
) -> ScanRecord
where
    F: FnMut(crate::r#static::ScanProgress),
{
    let path = &target.path;
    let path_string = path.to_string_lossy().to_string();
    let Some(path_str) = path.to_str() else {
        return ScanRecord {
            path: path_string,
            quarantine_path: None,
            storage_state: RecordStorageState::Unknown,
            last_modified_epoch: target.last_modified_epoch,
            scanned_at_epoch: now_epoch(),
            duration_ms: 0,
            file_size_bytes: target.size_bytes,
            verdict: Verdict::Unsure,
            note: "Path is not valid UTF-8".to_string(),
            action_note: String::new(),
        };
    };

    if !path.is_file() {
        return ScanRecord {
            path: path_string,
            quarantine_path: None,
            storage_state: RecordStorageState::Unknown,
            last_modified_epoch: target.last_modified_epoch,
            scanned_at_epoch: now_epoch(),
            duration_ms: 0,
            file_size_bytes: target.size_bytes,
            verdict: Verdict::Unsure,
            note: "Not a file".to_string(),
            action_note: String::new(),
        };
    }

    match crate::r#static::scan_path_with_progress(path_str, Some(config.clone()), progress) {
        Ok(outcome) => {
            let verdict = match outcome.severity {
                crate::r#static::types::Severity::Clean => Verdict::Good,
                crate::r#static::types::Severity::Suspicious => Verdict::Unsure,
                crate::r#static::types::Severity::Malicious => Verdict::Malicious,
            };

            let mut note_parts = vec![outcome.summary];
            if !outcome.findings.is_empty() {
                note_parts.push(
                    outcome
                        .findings
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; "),
                );
            }

            ScanRecord {
                path: path_string,
                quarantine_path: (!outcome.restored_to_original_path)
                    .then(|| outcome.quarantine_path.to_string_lossy().to_string()),
                storage_state: if outcome.restored_to_original_path {
                    RecordStorageState::Restored
                } else {
                    RecordStorageState::InQuarantine
                },
                last_modified_epoch: target.last_modified_epoch,
                scanned_at_epoch: now_epoch(),
                duration_ms: 0,
                file_size_bytes: target.size_bytes,
                verdict,
                note: note_parts.join(" | "),
                action_note: String::new(),
            }
        }
        Err(error) => ScanRecord {
            path: path_string,
            quarantine_path: None,
            storage_state: RecordStorageState::Unknown,
            last_modified_epoch: target.last_modified_epoch,
            scanned_at_epoch: now_epoch(),
            duration_ms: 0,
            file_size_bytes: target.size_bytes,
            verdict: Verdict::Unsure,
            note: error,
            action_note: String::new(),
        },
    }
}

fn latest_record_map(records: &[ScanRecord]) -> HashMap<String, ScanRecord> {
    let mut latest_by_path: HashMap<String, ScanRecord> = HashMap::new();
    for record in records {
        match latest_by_path.get(&record.path) {
            Some(existing) if existing.scanned_at_epoch >= record.scanned_at_epoch => {}
            _ => {
                latest_by_path.insert(record.path.clone(), record.clone());
            }
        }
    }
    latest_by_path
}

fn queue_targets_into_job(job: &mut ScanJobState, targets: Vec<ScanTarget>) -> (usize, u64) {
    let mut known_paths = HashSet::new();
    if !job.current_path.is_empty() {
        known_paths.insert(PathBuf::from(&job.current_path));
    }
    for target in &job.pending_targets {
        known_paths.insert(target.path.clone());
    }

    let mut added_count = 0usize;
    let mut added_bytes = 0u64;
    for target in targets {
        if known_paths.insert(target.path.clone()) {
            added_count += 1;
            added_bytes = added_bytes.saturating_add(target.size_bytes);
            job.pending_targets.push_back(target);
        }
    }

    job.total += added_count;
    job.total_bytes = job.total_bytes.saturating_add(added_bytes);
    job.queued_files = job.pending_targets.len();
    job.queued_bytes = job
        .pending_targets
        .iter()
        .map(|target| target.size_bytes)
        .sum::<u64>();

    (added_count, added_bytes)
}

fn record_matches_query(record: &ScanRecord, query: &str) -> bool {
    let query = query.trim().to_ascii_lowercase();
    if query.is_empty() {
        return true;
    }

    let haystacks = [
        record.path.to_ascii_lowercase(),
        record
            .quarantine_path
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        record.note.to_ascii_lowercase(),
        record.action_note.to_ascii_lowercase(),
        record.verdict.label().to_ascii_lowercase(),
        record.resolved_storage_state().label().to_ascii_lowercase(),
    ];

    haystacks.iter().any(|value| value.contains(&query))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn dedupe_targets(targets: Vec<ScanTarget>) -> Vec<ScanTarget> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for target in targets {
        if seen.insert(target.path.clone()) {
            deduped.push(target);
        }
    }

    deduped
}

fn collect_scan_targets(roots: &[PathBuf], max_files: usize) -> Vec<ScanTarget> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut stack: Vec<PathBuf> = roots.to_vec();

    while let Some(path) = stack.pop() {
        if files.len() >= max_files {
            break;
        }
        if !seen.insert(path.clone()) {
            continue;
        }

        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };

        if metadata.file_type().is_symlink() {
            continue;
        }

        if metadata.is_file() {
            files.push(ScanTarget {
                path,
                last_modified_epoch: metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0),
                size_bytes: metadata.len(),
            });
            continue;
        }

        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };

            let mut children = entries
                .flatten()
                .map(|entry| entry.path())
                .collect::<Vec<_>>();
            children.sort();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }

    files
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0usize;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{value:.1} {}", UNITS[unit_index])
    }
}

fn format_elapsed_ms(duration_ms: u64) -> String {
    if duration_ms >= 1000 {
        format!("{:.1}s", duration_ms as f64 / 1000.0)
    } else {
        format!("{duration_ms} ms")
    }
}

fn format_eta(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn load_history() -> PersistedHistory {
    let text = fs::read_to_string(HISTORY_PATH).unwrap_or_default();
    if text.is_empty() {
        return PersistedHistory::default();
    }

    serde_json::from_str::<PersistedHistory>(&text).unwrap_or_default()
}

fn save_history(records: &[ScanRecord], timing_samples: &[TimingSample]) {
    let mut retained_samples = timing_samples.to_vec();
    trim_timing_samples(&mut retained_samples);
    let payload = PersistedHistory {
        records: records.to_vec(),
        timing_samples: retained_samples,
    };
    let Ok(text) = serde_json::to_string_pretty(&payload) else {
        return;
    };

    if let Some(parent) = Path::new(HISTORY_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(HISTORY_PATH, text);
}

fn trim_timing_samples(samples: &mut Vec<TimingSample>) {
    if samples.len() > TIMING_SAMPLE_LIMIT {
        let drain_count = samples.len() - TIMING_SAMPLE_LIMIT;
        samples.drain(0..drain_count);
    }
}
