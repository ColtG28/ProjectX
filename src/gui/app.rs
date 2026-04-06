use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use egui::{Align, Align2, CentralPanel, Layout, RichText, Sense, SidePanel, TopBottomPanel, Vec2};
use rfd::FileDialog;

use super::components::empty_state::empty_state;
use super::components::result_detail::render_result_detail;
use super::components::result_list::render_result_row;
use super::state::*;
use super::theme;

pub fn gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([920.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "ProjectX Defensive Scanner",
        options,
        Box::new(|_cc| Box::new(MyApp::new())),
    )
}

impl MyApp {
    pub fn new() -> Self {
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
            history_search: String::new(),
            report_verdict_filter: ReportVerdictFilter::All,
            report_storage_filter: ReportStorageFilter::All,
            report_sort_order: ReportSortOrder::NewestFirst,
            history_quarantine_only: false,
            selected_report_ids: HashSet::new(),
            focused_report_id: None,
            pending_confirmation: None,
            status_message: String::new(),
            base_pixels_per_point: None,
            last_applied_scale: None,
            ui_metrics: UiMetrics::default(),
            last_download_poll: Instant::now(),
            download_watch: HashMap::new(),
            download_status: String::new(),
        }
    }

    pub fn is_booting(&self) -> bool {
        Instant::now() < self.boot_until
    }

    pub fn is_loading(&self) -> bool {
        if self.is_booting() {
            return true;
        }
        self.job.lock().map(|j| j.running).unwrap_or(false)
    }

    pub fn scan_config(&self) -> crate::r#static::config::ScanConfig {
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
        config.features.enable_emulation = self.settings.enable_emulation;
        config.features.enable_runtime_yara = self.settings.enable_runtime_yara;
        config.features.enable_ml_scoring = self.settings.enable_ml_scoring;
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
            theme::apply_theme(ctx, scale);
            self.last_applied_scale = Some(scale);
        }

        self.ui_metrics = UiMetrics {
            scale_factor: scale,
            menu_width: if compact {
                (width_points * 0.2).clamp(126.0, 160.0)
            } else if physical_width < 1600.0 {
                162.0 * scale
            } else {
                182.0 * scale
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
                ui.label("Loading defensive scanning workspace...");
                ui.add_space(12.0 * self.ui_metrics.scale_factor);
                ui.spinner();
            });
        });
    }

    fn render_top_bar(&mut self, ctx: &egui::Context) {
        TopBottomPanel::top("top_bar")
            .exact_height(48.0 * self.ui_metrics.scale_factor)
            .show(ctx, |ui| {
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    if ui
                        .button(RichText::new("☰").size(18.0 * self.ui_metrics.scale_factor))
                        .clicked()
                    {
                        self.menu_open = !self.menu_open;
                    }
                    ui.add_space(4.0 * self.ui_metrics.scale_factor);
                    ui.label(
                        RichText::new("ProjectX Defensive Scanner")
                            .strong()
                            .size(22.0 * self.ui_metrics.scale_factor),
                    );
                    ui.add_space(10.0 * self.ui_metrics.scale_factor);
                    ui.label(
                        RichText::new(format!(
                            "{} {}",
                            self.current_page.icon(),
                            self.current_page.label()
                        ))
                        .color(egui::Color32::from_rgb(176, 221, 255)),
                    );
                    ui.add_space(10.0 * self.ui_metrics.scale_factor);
                    let snapshot = self.job.lock().map(|job| job.clone()).unwrap_or_default();
                    let live_status = if snapshot.running {
                        format!(
                            "Scanning {} / {}",
                            snapshot.processed.min(snapshot.total),
                            snapshot.total
                        )
                    } else if !self.download_status.is_empty() {
                        self.download_status.clone()
                    } else {
                        "Ready".to_string()
                    };
                    ui.label(
                        RichText::new(live_status)
                            .size(13.0 * self.ui_metrics.scale_factor)
                            .color(egui::Color32::from_rgb(190, 196, 201)),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button(RichText::new("⚙").size(19.0 * self.ui_metrics.scale_factor))
                            .clicked()
                        {
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
                ui.vertical_centered(|ui| {
                    ui.add_space(2.0 * self.ui_metrics.scale_factor);
                    ui.heading("Workspace");
                });
                ui.separator();
                self.page_button(ui, Page::Analytics);
                self.page_button(ui, Page::Scanner);
                self.page_button(ui, Page::Reports);
                self.page_button(ui, Page::History);
                self.page_button(ui, Page::Settings);
                self.page_button(ui, Page::About);
            });
    }

    fn page_button(&mut self, ui: &mut egui::Ui, page: Page) {
        let selected = self.current_page == page;
        let label = format!("{}  {}", page.icon(), page.label());
        if ui
            .add_sized(
                [ui.available_width(), 28.0 * self.ui_metrics.scale_factor],
                egui::SelectableLabel::new(selected, label),
            )
            .clicked()
        {
            self.current_page = page;
        }
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

    pub(crate) fn render_record_list(
        &mut self,
        ui: &mut egui::Ui,
        indices: &[usize],
        allow_selection: bool,
    ) {
        let mut pending_action: Option<(String, RecordAction)> = None;
        let mut pending_reveal = None;
        let mut pending_report_reveal = None;

        ui.horizontal(|ui| {
            if allow_selection {
                ui.add_sized([22.0, 0.0], egui::Label::new(""));
            }
            ui.add_sized(
                [72.0, 0.0],
                egui::Label::new(RichText::new("Verdict").strong()),
            );
            ui.add_sized(
                [82.0, 0.0],
                egui::Label::new(RichText::new("Name").strong()),
            );
            ui.add_sized(
                [96.0, 0.0],
                egui::Label::new(RichText::new("Type").strong()),
            );
            ui.add_sized(
                [74.0, 0.0],
                egui::Label::new(RichText::new("Size").strong()),
            );
            ui.add_sized(
                [88.0, 0.0],
                egui::Label::new(RichText::new("Timestamp").strong()),
            );
            ui.add_sized(
                [72.0, 0.0],
                egui::Label::new(RichText::new("Severity").strong()),
            );
            ui.label(RichText::new("Signals").strong());
        });
        ui.add_space(4.0);

        for &index in indices {
            let storage_state = self.records[index].resolved_storage_state();
            let record_id = self.records[index].record_id();
            let selected_row = self.focused_report_id.as_deref() == Some(record_id.as_str());
            let mut selected = self.selected_report_ids.contains(&record_id);
            let inspect = render_result_row(
                ui,
                &self.records[index],
                selected_row,
                allow_selection,
                &mut selected,
            );
            if allow_selection {
                if selected {
                    self.selected_report_ids.insert(record_id.clone());
                } else {
                    self.selected_report_ids.remove(&record_id);
                }
            }
            if inspect {
                self.focused_report_id = Some(record_id.clone());
            }

            let in_quarantine = matches!(storage_state, RecordStorageState::InQuarantine)
                && self.records[index].quarantine_path.is_some();
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Inspect").small().strong());
                if ui.small_button("Copy path").clicked() {
                    ui.output_mut(|output| output.copied_text = self.records[index].path.clone());
                    self.status_message = "Copied file path.".to_string();
                }
                if let Some(hash) = self.records[index].sha256.as_deref() {
                    if ui.small_button("Copy hash").clicked() {
                        ui.output_mut(|output| output.copied_text = hash.to_string());
                        self.status_message = "Copied SHA-256 hash.".to_string();
                    }
                }
                if ui.small_button("Reveal file").clicked() {
                    pending_reveal = Some(self.records[index].path.clone());
                }
                if let Some(report_path) = self.records[index].report_path.as_deref() {
                    if ui.small_button("Reveal report").clicked() {
                        pending_report_reveal = Some(report_path.to_string());
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Modify stored items").small().strong());
                if ui
                    .add_enabled(in_quarantine, egui::Button::new("Restore from quarantine"))
                    .clicked()
                {
                    pending_action = Some((record_id.clone(), RecordAction::Restore));
                }
                if ui
                    .add_enabled(in_quarantine, egui::Button::new("Delete quarantined copy"))
                    .clicked()
                {
                    pending_action = Some((record_id.clone(), RecordAction::Delete));
                }
                if ui
                    .add_enabled(in_quarantine, egui::Button::new("Keep in quarantine"))
                    .clicked()
                {
                    pending_action = Some((record_id.clone(), RecordAction::Leave));
                }
                if ui.small_button("Remove report").clicked() {
                    pending_action = Some((record_id.clone(), RecordAction::DeleteReport));
                }
            });
            ui.add_space(6.0);
        }

        if let Some((record_id, action)) = pending_action {
            match action {
                RecordAction::Restore | RecordAction::Delete | RecordAction::DeleteReport => {
                    self.queue_record_action_confirmation(record_id, action)
                }
                RecordAction::Leave => self.apply_record_action_by_id(&record_id, action),
            }
        }
        if let Some(path) = pending_reveal {
            self.status_message = match reveal_in_file_manager(Path::new(&path)) {
                Ok(()) => "Opened the file in the OS file manager.".to_string(),
                Err(error) => format!("Reveal failed: {error}"),
            };
        }
        if let Some(path) = pending_report_reveal {
            self.status_message = match reveal_in_file_manager(Path::new(&path)) {
                Ok(()) => "Opened the report in the OS file manager.".to_string(),
                Err(error) => format!("Reveal failed: {error}"),
            };
        }
    }

    fn apply_record_action_by_id(&mut self, record_id: &str, action: RecordAction) {
        let Some(index) = self
            .records
            .iter()
            .position(|record| record.record_id() == record_id)
        else {
            return;
        };
        if matches!(action, RecordAction::DeleteReport) {
            let Some(record) = self.records.get(index).cloned() else {
                return;
            };
            let removed = self.remove_report_files(record.report_path.as_deref());
            self.selected_report_ids.remove(&record.record_id());
            self.records.remove(index);
            self.status_message = if removed {
                "Report deleted from disk and removed from the GUI.".to_string()
            } else {
                "Report entry removed from the GUI.".to_string()
            };
            save_history(&self.records, &self.timing_samples);
            return;
        }

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
            RecordAction::DeleteReport => unreachable!(),
        };

        self.status_message = message;
        save_history(&self.records, &self.timing_samples);
    }

    fn queue_record_action_confirmation(&mut self, record_id: String, action: RecordAction) {
        let Some(record) = self
            .records
            .iter()
            .find(|record| record.record_id() == record_id)
        else {
            return;
        };
        let (title, message, confirm_label) = match action {
            RecordAction::Restore => (
                "Restore quarantined file".to_string(),
                format!(
                    "Restore '{}' from quarantine back to its original location? This writes the retained file back to disk and should only be used if you are confident the item is safe.",
                    record.display_name()
                ),
                "Restore file".to_string(),
            ),
            RecordAction::Delete => (
                "Delete quarantined copy".to_string(),
                format!(
                    "Permanently delete the quarantined copy of '{}' from local storage? This only removes the retained file from quarantine.",
                    record.display_name()
                ),
                "Delete quarantined file".to_string(),
            ),
            RecordAction::DeleteReport => (
                "Remove stored report".to_string(),
                format!(
                    "Remove the stored report entry for '{}'? This deletes local report data and removes the record from history, but does not execute or restore the file.",
                    record.display_name()
                ),
                "Remove report".to_string(),
            ),
            RecordAction::Leave => return,
        };
        self.pending_confirmation = Some(PendingConfirmation {
            title,
            message,
            confirm_label,
            target: PendingConfirmationTarget::RecordAction { record_id, action },
        });
    }

    fn queue_delete_selected_confirmation(&mut self, record_ids: Vec<String>) {
        if record_ids.is_empty() {
            return;
        }
        self.pending_confirmation = Some(PendingConfirmation {
            title: "Delete selected reports".to_string(),
            message: format!(
                "Remove {} selected report entrie(s) from the GUI and delete any stored report files still present on disk? This does not restore or execute quarantined files.",
                record_ids.len()
            ),
            confirm_label: "Delete selected reports".to_string(),
            target: PendingConfirmationTarget::DeleteReports { record_ids },
        });
    }

    fn render_pending_confirmation(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.pending_confirmation.clone() else {
            return;
        };

        egui::Window::new(dialog.title.clone())
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_min_width(420.0);
                ui.label(&dialog.message);
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        self.pending_confirmation = None;
                    }
                    if ui
                        .add(
                            egui::Button::new(dialog.confirm_label.clone())
                                .fill(egui::Color32::from_rgb(130, 67, 67)),
                        )
                        .clicked()
                    {
                        let target = dialog.target.clone();
                        self.pending_confirmation = None;
                        match target {
                            PendingConfirmationTarget::RecordAction { record_id, action } => {
                                self.apply_record_action_by_id(&record_id, action);
                            }
                            PendingConfirmationTarget::DeleteReports { record_ids } => {
                                self.delete_reports_by_ids(&record_ids);
                            }
                        }
                    }
                });
            });
    }

    pub(crate) fn render_record_detail(&mut self, ui: &mut egui::Ui) {
        self.hydrate_focused_record_from_report();
        let selected = self
            .focused_report_id
            .as_ref()
            .and_then(|id| self.records.iter().find(|record| record.record_id() == *id))
            .cloned()
            .or_else(|| self.records.last().cloned());

        let Some(record) = selected else {
            empty_state(
                ui,
                self.ui_metrics.scale_factor,
                "No result selected",
                "Pick Inspect on any result row to keep it pinned here.",
            );
            return;
        };

        render_result_detail(ui, self.ui_metrics.scale_factor, &record);
    }

    fn hydrate_focused_record_from_report(&mut self) {
        let Some(focused_id) = self.focused_report_id.clone() else {
            return;
        };
        let Some(index) = self
            .records
            .iter()
            .position(|record| record.record_id() == focused_id)
        else {
            return;
        };
        let needs_hydration = self.records[index].detection_reasons.is_empty()
            || self.records[index].sha256.is_none()
            || self.records[index].sniffed_mime.is_none();
        if !needs_hydration {
            return;
        }
        let Some(report_path) = self.records[index].report_path.clone() else {
            return;
        };
        if let Some(updated) =
            hydrate_record_from_report(&self.records[index], Path::new(&report_path))
        {
            self.records[index] = updated;
        }
    }

    pub(crate) fn submit_manual_path(&mut self) {
        let input = self.single_file_path.trim().to_string();
        if input.is_empty() {
            self.status_message = "Enter a file or folder path first.".to_string();
        } else {
            self.start_scan_from_roots(vec![PathBuf::from(input)]);
        }
    }

    pub(crate) fn pick_file_target(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.single_file_path = path.display().to_string();
            self.submit_manual_path();
        }
    }

    pub(crate) fn pick_folder_target(&mut self) {
        if let Some(path) = FileDialog::new().pick_folder() {
            self.single_file_path = path.display().to_string();
            self.submit_manual_path();
        }
    }

    pub(crate) fn filtered_record_indices(&self, limit: usize, query: &str) -> Vec<usize> {
        let mut indices = (0..self.records.len())
            .filter(|&index| {
                let record = &self.records[index];
                record_matches_query(record, query)
                    && self.report_verdict_filter.matches(record.verdict)
                    && self
                        .report_storage_filter
                        .matches(record.resolved_storage_state())
            })
            .collect::<Vec<_>>();

        match self.report_sort_order {
            ReportSortOrder::NewestFirst => indices
                .sort_by_key(|&index| std::cmp::Reverse(self.records[index].scanned_at_epoch)),
            ReportSortOrder::OldestFirst => {
                indices.sort_by_key(|&index| self.records[index].scanned_at_epoch)
            }
            ReportSortOrder::SeverityFirst => indices.sort_by_key(|&index| {
                let rank = match self.records[index].verdict {
                    Verdict::Malicious => 0,
                    Verdict::Suspicious => 1,
                    Verdict::Error => 2,
                    Verdict::Clean => 3,
                };
                (
                    rank,
                    std::cmp::Reverse(self.records[index].scanned_at_epoch),
                )
            }),
            ReportSortOrder::Name => indices
                .sort_by_key(|&index| self.records[index].display_name().to_ascii_lowercase()),
        }

        indices.into_iter().take(limit).collect()
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

    fn poll_download_monitor(&mut self) {
        if !self.settings.enable_download_monitoring {
            self.download_watch.clear();
            self.download_status.clear();
            return;
        }

        if self.last_download_poll.elapsed() < Duration::from_millis(1500) {
            return;
        }
        self.last_download_poll = Instant::now();

        let Some(downloads_dir) = home_dir().map(|home| home.join("Downloads")) else {
            self.download_status = "Downloads folder not available.".to_string();
            return;
        };
        if !downloads_dir.exists() {
            self.download_status = "Downloads folder not found.".to_string();
            return;
        }

        let mut seen = HashSet::new();
        let mut queued = 0usize;
        let now = now_epoch();
        let active_candidates = collect_active_downloads(&downloads_dir);
        for path in active_candidates {
            let Ok(metadata) = fs::metadata(&path) else {
                continue;
            };
            let path_string = path.to_string_lossy().to_string();
            let size = metadata.len();
            seen.insert(path_string.clone());

            let entry = self.download_watch.entry(path_string.clone()).or_default();
            let grew = size > entry.last_scanned_size;
            let changed_recently =
                entry.last_seen_epoch == 0 || now.saturating_sub(entry.last_seen_epoch) <= 5;
            entry.last_seen_epoch = now;
            entry.last_size = size;

            if grew && changed_recently {
                if let Some(target) = build_download_snapshot_target(&path, size) {
                    queued += 1;
                    entry.last_scanned_size = size;
                    self.start_scan(vec![target]);
                }
            }
        }

        self.download_watch.retain(|path, _| seen.contains(path));
        self.download_status = if queued > 0 {
            format!(
                "Queued {} download snapshot(s) from {}.",
                queued,
                downloads_dir.display()
            )
        } else if seen.is_empty() {
            "No active downloads detected.".to_string()
        } else {
            format!("Watching {} active download(s).", seen.len())
        };
    }

    fn remove_report_files(&self, report_path: Option<&str>) -> bool {
        let Some(report_path) = report_path else {
            return false;
        };
        let path = Path::new(report_path);
        if path.is_file() {
            fs::remove_file(path).is_ok()
        } else {
            false
        }
    }

    pub(crate) fn delete_selected_reports(&mut self, visible_ids: &HashSet<String>) {
        let selected_visible = self
            .selected_report_ids
            .iter()
            .filter(|id| visible_ids.contains(*id))
            .cloned()
            .collect::<HashSet<_>>();
        if selected_visible.is_empty() {
            return;
        }
        self.queue_delete_selected_confirmation(selected_visible.into_iter().collect());
    }

    fn delete_reports_by_ids(&mut self, record_ids: &[String]) {
        if record_ids.is_empty() {
            return;
        }
        let mut removed_files = 0usize;
        let removed_entries = record_ids.len();
        let report_paths_to_remove = self
            .records
            .iter()
            .filter(|record| record_ids.iter().any(|id| id == &record.record_id()))
            .filter_map(|record| record.report_path.clone())
            .collect::<Vec<_>>();
        for report_path in report_paths_to_remove {
            if self.remove_report_files(Some(&report_path)) {
                removed_files += 1;
            }
        }
        self.records
            .retain(|record| !record_ids.iter().any(|id| id == &record.record_id()));
        for id in record_ids {
            self.selected_report_ids.remove(id);
        }
        self.status_message = format!(
            "Deleted {} selected report entrie(s) and removed {} report file(s).",
            removed_entries, removed_files
        );
        save_history(&self.records, &self.timing_samples);
    }

    pub(crate) fn render_record_workspace(
        &mut self,
        ui: &mut egui::Ui,
        indices: &[usize],
        empty_title: &str,
        empty_body: &str,
        note: &str,
    ) {
        if indices.is_empty() {
            empty_state(ui, self.ui_metrics.scale_factor, empty_title, empty_body);
            return;
        }

        if self.ui_metrics.compact {
            egui::ScrollArea::vertical().show(ui, |ui| self.render_record_list(ui, indices, true));
            ui.separator();
            self.render_record_detail(ui);
            ui.add_space(8.0);
            self.render_workspace_note(ui, note);
        } else {
            ui.columns(2, |columns| {
                columns[0].vertical(|ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| self.render_record_list(ui, indices, true));
                });
                columns[1].vertical(|ui| {
                    self.render_record_detail(ui);
                    ui.add_space(8.0);
                    self.render_workspace_note(ui, note);
                });
            });
        }
    }

    fn render_workspace_note(&self, ui: &mut egui::Ui, note: &str) {
        ui.group(|ui| {
            ui.label(egui::RichText::new("Operational notes").strong());
            ui.label(note);
        });
    }

    pub(crate) fn start_scan_from_roots(&mut self, roots: Vec<PathBuf>) {
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

impl Default for MyApp {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_responsive_scaling(ctx);
        self.poll_finished_job();
        self.poll_download_monitor();

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
                Page::History => self.render_history(ui),
                Page::Settings => self.render_settings(ui),
                Page::About => self.render_about(ui),
            }
        });

        self.render_pending_confirmation(ctx);
        self.render_loading_indicator(ctx);

        if self.is_loading() || self.settings.enable_download_monitoring {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

pub fn update_job_progress(job_ref: &Arc<Mutex<ScanJobState>>, update: JobProgressUpdate) {
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
        job.errors = update.counts.3;
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
    let mut errors = 0usize;
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
                    "{} scanned | clean={} malicious={} suspicious={} errors={}",
                    job.processed, good, malicious, unsure, errors
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
                            counts: (good, malicious, unsure, errors),
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
                                counts: (good, malicious, unsure, errors),
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
                            counts: (good, malicious, unsure, errors),
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
                        counts: (good, malicious, unsure, errors),
                        historical_bytes_per_ms: timing_profile.average_bytes_per_ms,
                    },
                );
            });
            duration_ms = current_file_started.elapsed().as_millis() as u64;
            record.duration_ms = duration_ms;
            record
        };

        match record.verdict {
            Verdict::Clean => good += 1,
            Verdict::Malicious => malicious += 1,
            Verdict::Suspicious => unsure += 1,
            Verdict::Error => errors += 1,
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
                counts: (good, malicious, unsure, errors),
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

pub(crate) fn overall_progress(job: &ScanJobState) -> f32 {
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
    record.summary_text = if previous.summary_text.is_empty() {
        "Already scanned before (unchanged file timestamp).".to_string()
    } else {
        format!(
            "Already scanned before (unchanged file timestamp). | {}",
            previous.summary_text
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
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path_string.clone());

    let error_record = |message: String| ScanRecord {
        path: path_string.clone(),
        file_name: file_name.clone(),
        extension: path
            .extension()
            .map(|value| value.to_string_lossy().to_string()),
        sha256: None,
        sniffed_mime: None,
        detected_format: None,
        quarantine_path: None,
        report_path: None,
        storage_state: RecordStorageState::Unknown,
        last_modified_epoch: target.last_modified_epoch,
        scanned_at_epoch: now_epoch(),
        started_at_epoch: None,
        finished_at_epoch: Some(now_epoch()),
        duration_ms: 0,
        file_size_bytes: target.size_bytes,
        verdict: Verdict::Error,
        severity: SeverityLevel::Error,
        summary_text: message,
        action_note: String::new(),
        risk_score: None,
        safety_score: None,
        signal_sources: vec!["scanner".to_string()],
        detection_reasons: Vec::new(),
        warning_count: 0,
        error_count: 1,
        quarantine: QuarantineMetadata::default(),
        scan_id: format!("{}::{}", now_epoch(), path_string),
    };

    let Some(path_str) = path.to_str() else {
        return error_record("Path is not valid UTF-8".to_string());
    };

    if !path.is_file() {
        return error_record("Not a file".to_string());
    }

    match crate::r#static::scan_path_with_progress(path_str, Some(config.clone()), progress) {
        Ok(outcome) => {
            let warning_count = outcome.reason_entries.len();
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
                path: path_string.clone(),
                file_name: outcome.file_name,
                extension: Some(outcome.extension),
                sha256: Some(outcome.sha256),
                sniffed_mime: Some(outcome.sniffed_mime),
                detected_format: outcome.detected_format,
                quarantine_path: (!outcome.restored_to_original_path)
                    .then(|| outcome.quarantine_path.to_string_lossy().to_string()),
                report_path: Some(outcome.report_path.to_string_lossy().to_string()),
                storage_state: if outcome.restored_to_original_path {
                    RecordStorageState::Restored
                } else {
                    RecordStorageState::InQuarantine
                },
                last_modified_epoch: target.last_modified_epoch,
                scanned_at_epoch: now_epoch(),
                started_at_epoch: None,
                finished_at_epoch: Some(now_epoch()),
                duration_ms: 0,
                file_size_bytes: target.size_bytes.max(outcome.file_size_bytes),
                verdict: outcome.verdict,
                severity: outcome.normalized_severity,
                summary_text: note_parts.join(" | "),
                action_note: String::new(),
                risk_score: Some(outcome.risk_score),
                safety_score: Some(outcome.safety_score),
                signal_sources: outcome.signal_sources,
                detection_reasons: outcome
                    .reason_entries
                    .into_iter()
                    .map(|reason| DetectionReason {
                        reason_type: reason.reason_type,
                        name: reason.name,
                        description: reason.description,
                        weight: reason.weight,
                        source: reason.source,
                    })
                    .collect(),
                warning_count,
                error_count: 0,
                quarantine: QuarantineMetadata {
                    retained_in_quarantine: !outcome.restored_to_original_path,
                    restored_to_original_path: outcome.restored_to_original_path,
                },
                scan_id: format!("{}::{}", now_epoch(), path_string),
            }
        }
        Err(error) => error_record(error),
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
        record.display_name().to_ascii_lowercase(),
        record
            .quarantine_path
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        record
            .report_path
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        record.summary_text.to_ascii_lowercase(),
        record.action_note.to_ascii_lowercase(),
        record.verdict.label().to_ascii_lowercase(),
        record.severity.label().to_ascii_lowercase(),
        record.resolved_storage_state().label().to_ascii_lowercase(),
        record
            .sha256
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        record
            .sniffed_mime
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        record
            .detected_format
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        record
            .detection_reasons
            .iter()
            .map(|reason| format!("{} {} {}", reason.name, reason.description, reason.source))
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
    ];

    haystacks.iter().any(|value| value.contains(&query))
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

fn reveal_in_file_manager(path: &Path) -> Result<(), String> {
    let status = if cfg!(target_os = "macos") {
        Command::new("open")
            .arg("-R")
            .arg(path)
            .status()
            .map_err(|error| format!("Failed to run open: {error}"))?
    } else if cfg!(target_os = "windows") {
        Command::new("explorer")
            .arg("/select,")
            .arg(path)
            .status()
            .map_err(|error| format!("Failed to run explorer: {error}"))?
    } else {
        let directory = path.parent().unwrap_or(path);
        Command::new("xdg-open")
            .arg(directory)
            .status()
            .map_err(|error| format!("Failed to run xdg-open: {error}"))?
    };

    if status.success() {
        Ok(())
    } else {
        Err("The OS file manager command did not succeed.".to_string())
    }
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

fn collect_active_downloads(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            if looks_like_active_download(&path) {
                files.push(path);
            }
            continue;
        }
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
        }
    }

    files
}

fn looks_like_active_download(path: &Path) -> bool {
    let lower = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    lower.ends_with(".crdownload")
        || lower.ends_with(".download")
        || lower.ends_with(".part")
        || lower.ends_with(".tmp")
        || lower.ends_with(".partial")
}

fn build_download_snapshot_target(path: &Path, size: u64) -> Option<ScanTarget> {
    if size == 0 {
        return None;
    }

    let snapshot = write_download_snapshot(path)?;
    let metadata = fs::metadata(&snapshot).ok()?;
    Some(ScanTarget {
        path: snapshot,
        last_modified_epoch: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_else(now_epoch),
        size_bytes: metadata.len(),
    })
}

fn write_download_snapshot(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_string_lossy();
    let safe_name = sanitize_file_name(&file_name);
    let output_dir = Path::new("quarantine").join("download_monitor");
    fs::create_dir_all(&output_dir).ok()?;
    let snapshot = output_dir.join(format!("{}_{}", now_epoch(), safe_name));
    fs::copy(path, &snapshot).ok()?;
    Some(snapshot)
}

fn sanitize_file_name(name: &str) -> String {
    name.chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect()
}

pub(crate) fn draw_pie_chart(
    ui: &mut egui::Ui,
    id_source: &str,
    segments: &[(&str, usize, egui::Color32)],
) {
    let total = segments
        .iter()
        .map(|(_, value, _)| *value)
        .sum::<usize>()
        .max(1) as f32;
    let desired_size = Vec2::new(220.0, 220.0);
    let (rect, _) = ui.allocate_at_least(desired_size, Sense::hover());
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.42;
    let mut start_angle = -std::f32::consts::FRAC_PI_2;

    for (idx, (_, value, color)) in segments.iter().enumerate() {
        let sweep = (*value as f32 / total) * std::f32::consts::TAU;
        let end_angle = start_angle + sweep.max(0.001);
        let mut points = vec![center];
        let steps = ((sweep / std::f32::consts::TAU) * 48.0).ceil() as usize + 2;
        for step in 0..=steps {
            let t = step as f32 / steps as f32;
            let angle = start_angle + (end_angle - start_angle) * t;
            points.push(center + Vec2::angled(angle) * radius);
        }
        painter.add(egui::Shape::convex_polygon(
            points,
            *color,
            egui::Stroke::NONE,
        ));
        start_angle = end_angle;

        if idx == segments.len() - 1 {
            painter.circle_stroke(
                center,
                radius,
                egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 52, 54)),
            );
        }
    }
    let _ = id_source;
}

pub(crate) fn draw_segment_bar(ui: &mut egui::Ui, segments: &[(&str, usize, egui::Color32)]) {
    let total = segments
        .iter()
        .map(|(_, value, _)| *value)
        .sum::<usize>()
        .max(1) as f32;
    let desired_size = Vec2::new(ui.available_width().max(220.0), 28.0);
    let (rect, _) = ui.allocate_at_least(desired_size, Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 6.0, egui::Color32::from_rgb(27, 27, 29));

    let mut x = rect.left();
    for (_, value, color) in segments {
        if *value == 0 {
            continue;
        }
        let width = rect.width() * (*value as f32 / total);
        let segment_rect =
            egui::Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(width, rect.height()));
        painter.rect_filled(segment_rect, 6.0, *color);
        x += width;
    }

    painter.rect_stroke(
        rect,
        6.0,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 52, 54)),
    );
}

pub(crate) fn render_chart_legend(ui: &mut egui::Ui, segments: &[(&str, usize, egui::Color32)]) {
    for (label, value, color) in segments {
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_at_least(Vec2::new(12.0, 12.0), Sense::hover());
            ui.painter().rect_filled(rect, 2.0, *color);
            ui.label(format!("{label}: {value}"));
        });
    }
}

pub(crate) fn format_bytes(bytes: u64) -> String {
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

pub(crate) fn format_elapsed_ms(duration_ms: u64) -> String {
    if duration_ms >= 1000 {
        format!("{:.1}s", duration_ms as f64 / 1000.0)
    } else {
        format!("{duration_ms} ms")
    }
}

pub(crate) fn format_eta(seconds: u64) -> String {
    if seconds >= 3600 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn format_timestamp_compact(epoch: u64) -> String {
    format_local_timestamp(epoch, "%Y-%m-%d %H:%M").unwrap_or_else(|| format!("epoch {}", epoch))
}

pub(crate) fn format_timestamp_with_relative(epoch: u64) -> String {
    let absolute = format_local_timestamp(epoch, "%Y-%m-%d %H:%M:%S")
        .unwrap_or_else(|| format!("epoch {}", epoch));
    format!("{absolute} ({})", format_relative_time(epoch))
}

fn format_relative_time(epoch: u64) -> String {
    let now = now_epoch();
    if epoch == 0 {
        return "unknown time".to_string();
    }
    let delta = now.saturating_sub(epoch);
    if delta < 60 {
        "just now".to_string()
    } else if delta < 3600 {
        format!("{} min ago", delta / 60)
    } else if delta < 86_400 {
        format!("{} hr ago", delta / 3600)
    } else {
        format!("{} d ago", delta / 86_400)
    }
}

fn format_local_timestamp(epoch: u64, pattern: &str) -> Option<String> {
    if epoch == 0 {
        return None;
    }

    #[cfg(unix)]
    unsafe {
        let time = epoch as libc::time_t;
        let mut local = std::mem::zeroed::<libc::tm>();
        if libc::localtime_r(&time, &mut local).is_null() {
            return None;
        }
        let mut buffer = [0u8; 64];
        let format = std::ffi::CString::new(pattern).ok()?;
        let written = libc::strftime(
            buffer.as_mut_ptr() as *mut libc::c_char,
            buffer.len(),
            format.as_ptr(),
            &local,
        );
        if written == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buffer[..written]).to_string())
    }

    #[cfg(not(unix))]
    {
        let _ = pattern;
        Some(format!("epoch {}", epoch))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RecordMetrics {
    pub total: usize,
    pub clean: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub errors: usize,
    pub in_quarantine: usize,
    pub restored: usize,
    pub deleted: usize,
    pub warning_total: usize,
    pub error_total: usize,
    pub high_severity: usize,
    pub medium_severity: usize,
}

pub(crate) fn summarize_record_refs(records: &[&ScanRecord]) -> RecordMetrics {
    let mut metrics = RecordMetrics {
        total: records.len(),
        ..RecordMetrics::default()
    };
    for record in records {
        match record.verdict {
            Verdict::Clean => metrics.clean += 1,
            Verdict::Malicious => metrics.malicious += 1,
            Verdict::Suspicious => metrics.suspicious += 1,
            Verdict::Error => metrics.errors += 1,
        }
        match record.resolved_storage_state() {
            RecordStorageState::InQuarantine => metrics.in_quarantine += 1,
            RecordStorageState::Restored => metrics.restored += 1,
            RecordStorageState::Deleted => metrics.deleted += 1,
            RecordStorageState::Unknown => {}
        }
        metrics.warning_total += record.warning_count;
        metrics.error_total += record.error_count;
        match record.severity {
            SeverityLevel::High => metrics.high_severity += 1,
            SeverityLevel::Medium => metrics.medium_severity += 1,
            _ => {}
        }
    }
    metrics
}

fn load_history() -> PersistedHistory {
    let timing_samples = fs::read_to_string(HISTORY_PATH)
        .ok()
        .and_then(|text| serde_json::from_str::<PersistedHistory>(&text).ok())
        .map(|history| history.timing_samples)
        .unwrap_or_default();

    let records = fs::read_to_string(INDEX_PATH)
        .ok()
        .and_then(|text| serde_json::from_str::<PersistedIndex>(&text).ok())
        .map(|index| index.entries)
        .or_else(|| {
            fs::read_to_string(HISTORY_PATH)
                .ok()
                .and_then(|text| serde_json::from_str::<PersistedHistory>(&text).ok())
                .map(|history| history.records)
        })
        .unwrap_or_default();

    PersistedHistory {
        records,
        timing_samples,
    }
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
    save_index(records);
}

fn trim_timing_samples(samples: &mut Vec<TimingSample>) {
    if samples.len() > TIMING_SAMPLE_LIMIT {
        let drain_count = samples.len() - TIMING_SAMPLE_LIMIT;
        samples.drain(0..drain_count);
    }
}

fn save_index(records: &[ScanRecord]) {
    let index = PersistedIndex {
        entries: records.to_vec(),
    };
    let Ok(text) = serde_json::to_string_pretty(&index) else {
        return;
    };
    if let Some(parent) = Path::new(INDEX_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(INDEX_PATH, text);
}

fn hydrate_record_from_report(record: &ScanRecord, report_path: &Path) -> Option<ScanRecord> {
    let text = fs::read_to_string(report_path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    let mut updated = record.clone();
    updated.sha256 = updated
        .sha256
        .or_else(|| value["file"]["sha256"].as_str().map(str::to_string));
    updated.sniffed_mime = updated
        .sniffed_mime
        .or_else(|| value["file"]["sniffed_mime"].as_str().map(str::to_string));
    updated.detected_format = updated.detected_format.or_else(|| {
        value["file"]["detected_format"]
            .as_str()
            .map(str::to_string)
    });
    updated.file_name = if updated.file_name.is_empty() {
        value["file"]["name"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| updated.file_name.clone())
    } else {
        updated.file_name
    };
    updated.severity = value["verdict"]["normalized_severity"]
        .as_str()
        .map(severity_level_from_label)
        .unwrap_or(updated.severity);
    updated.detection_reasons = value["reasons"]
        .as_array()
        .map(|reasons| {
            reasons
                .iter()
                .map(|reason| DetectionReason {
                    reason_type: reason["reason_type"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    name: reason["name"].as_str().unwrap_or_default().to_string(),
                    description: reason["description"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    weight: reason["weight"].as_f64().unwrap_or(0.0),
                    source: reason["source"].as_str().unwrap_or("heuristic").to_string(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    updated.signal_sources = value["summary"]["signal_sources"]
        .as_array()
        .map(|sources| {
            sources
                .iter()
                .filter_map(|source| source.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| updated.signal_sources.clone());
    updated.warning_count = value["summary"]["warning_count"]
        .as_u64()
        .map(|value| value as usize)
        .unwrap_or(updated.warning_count);
    updated.error_count = value["summary"]["error_count"]
        .as_u64()
        .map(|value| value as usize)
        .unwrap_or(updated.error_count);
    Some(updated)
}

fn severity_level_from_label(label: &str) -> SeverityLevel {
    match label {
        "clean" => SeverityLevel::Clean,
        "low" => SeverityLevel::Low,
        "medium" => SeverityLevel::Medium,
        "high" => SeverityLevel::High,
        "error" => SeverityLevel::Error,
        _ => SeverityLevel::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mapping_normalizes_labels() {
        assert_eq!(severity_level_from_label("clean"), SeverityLevel::Clean);
        assert_eq!(severity_level_from_label("low"), SeverityLevel::Low);
        assert_eq!(severity_level_from_label("medium"), SeverityLevel::Medium);
        assert_eq!(severity_level_from_label("high"), SeverityLevel::High);
        assert_eq!(severity_level_from_label("error"), SeverityLevel::Error);
    }

    #[test]
    fn formats_timestamps_readably() {
        let compact = format_timestamp_compact(1_700_000_000);
        let detailed = format_timestamp_with_relative(1_700_000_000);
        assert!(!compact.is_empty());
        assert!(detailed.contains('('));
    }

    #[test]
    fn index_roundtrip_preserves_core_fields() {
        let record = ScanRecord {
            scan_id: "demo".to_string(),
            path: "/tmp/demo.bin".to_string(),
            file_name: "demo.bin".to_string(),
            extension: Some("bin".to_string()),
            sha256: Some("abc".to_string()),
            sniffed_mime: Some("application/octet-stream".to_string()),
            detected_format: Some("Pe".to_string()),
            quarantine_path: Some("quarantine/demo.bin".to_string()),
            report_path: Some("quarantine/reports/demo.json".to_string()),
            storage_state: RecordStorageState::InQuarantine,
            last_modified_epoch: 1,
            scanned_at_epoch: 2,
            started_at_epoch: Some(1),
            finished_at_epoch: Some(2),
            duration_ms: 25,
            file_size_bytes: 4096,
            verdict: Verdict::Malicious,
            severity: SeverityLevel::High,
            summary_text: "flagged".to_string(),
            action_note: String::new(),
            risk_score: Some(8.1),
            safety_score: Some(0.2),
            signal_sources: vec!["heuristic".to_string(), "rule".to_string()],
            detection_reasons: vec![DetectionReason::default()],
            warning_count: 2,
            error_count: 0,
            quarantine: QuarantineMetadata {
                retained_in_quarantine: true,
                restored_to_original_path: false,
            },
        };

        let entry = record.clone();
        let hydrated = entry;
        assert_eq!(hydrated.path, record.path);
        assert_eq!(hydrated.file_name, record.file_name);
        assert_eq!(hydrated.severity, SeverityLevel::High);
        assert_eq!(hydrated.signal_sources.len(), 2);
        assert_eq!(hydrated.warning_count, 2);
    }

    #[test]
    fn hydrates_summary_from_full_report_json() {
        let path =
            std::env::temp_dir().join(format!("projectx_report_{}.json", std::process::id()));
        std::fs::write(
            &path,
            serde_json::json!({
                "file": {
                    "name": "sample.txt",
                    "sha256": "deadbeef",
                    "sniffed_mime": "text/plain",
                    "detected_format": "PlainText"
                },
                "verdict": {
                    "normalized_severity": "medium"
                },
                "summary": {
                    "warning_count": 3,
                    "error_count": 1,
                    "signal_sources": ["heuristic", "rule"]
                },
                "reasons": [
                    {
                        "reason_type": "heuristic",
                        "source": "heuristic",
                        "name": "SCRIPT_CONCAT_EVAL",
                        "description": "Suspicious script concatenation pattern",
                        "weight": 1.5
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let record = ScanRecord {
            scan_id: "demo2".to_string(),
            path: "/tmp/sample.txt".to_string(),
            file_name: String::new(),
            extension: None,
            sha256: None,
            sniffed_mime: None,
            detected_format: None,
            quarantine_path: None,
            report_path: Some(path.display().to_string()),
            storage_state: RecordStorageState::Unknown,
            quarantine: QuarantineMetadata::default(),
            last_modified_epoch: 0,
            scanned_at_epoch: 0,
            started_at_epoch: None,
            finished_at_epoch: None,
            duration_ms: 0,
            file_size_bytes: 0,
            verdict: Verdict::Suspicious,
            severity: SeverityLevel::Low,
            summary_text: String::new(),
            action_note: String::new(),
            risk_score: None,
            safety_score: None,
            signal_sources: Vec::new(),
            detection_reasons: Vec::new(),
            warning_count: 0,
            error_count: 0,
        };

        let hydrated = hydrate_record_from_report(&record, &path).unwrap();
        assert_eq!(hydrated.file_name, "sample.txt");
        assert_eq!(hydrated.sha256.as_deref(), Some("deadbeef"));
        assert_eq!(hydrated.severity, SeverityLevel::Medium);
        assert_eq!(hydrated.warning_count, 3);
        assert_eq!(hydrated.error_count, 1);
        assert_eq!(hydrated.detection_reasons.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn summarizes_operational_record_metrics() {
        let mut quarantined = demo_record();
        quarantined.verdict = Verdict::Malicious;
        quarantined.severity = SeverityLevel::High;
        quarantined.warning_count = 2;
        quarantined.storage_state = RecordStorageState::InQuarantine;
        let quarantine_path =
            std::env::temp_dir().join(format!("projectx_quarantine_{}.bin", std::process::id()));
        std::fs::write(&quarantine_path, b"fixture").unwrap();
        quarantined.quarantine_path = Some(quarantine_path.to_string_lossy().to_string());

        let mut restored = demo_record();
        restored.scan_id = "two".to_string();
        restored.storage_state = RecordStorageState::Restored;
        restored.warning_count = 1;
        restored.error_count = 1;

        let refs = vec![&quarantined, &restored];
        let metrics = summarize_record_refs(&refs);
        assert_eq!(metrics.total, 2);
        assert_eq!(metrics.malicious, 1);
        assert_eq!(metrics.clean, 1);
        assert_eq!(metrics.in_quarantine, 1);
        assert_eq!(metrics.restored, 1);
        assert_eq!(metrics.warning_total, 3);
        assert_eq!(metrics.error_total, 1);
        assert_eq!(metrics.high_severity, 1);

        let _ = std::fs::remove_file(quarantine_path);
    }

    fn demo_record() -> ScanRecord {
        ScanRecord {
            scan_id: "one".to_string(),
            path: "/tmp/demo.bin".to_string(),
            file_name: "demo.bin".to_string(),
            extension: Some("bin".to_string()),
            sha256: Some("abc".to_string()),
            sniffed_mime: Some("application/octet-stream".to_string()),
            detected_format: Some("Pe".to_string()),
            quarantine_path: None,
            report_path: Some("quarantine/reports/demo.json".to_string()),
            storage_state: RecordStorageState::Unknown,
            last_modified_epoch: 1,
            scanned_at_epoch: 2,
            started_at_epoch: Some(1),
            finished_at_epoch: Some(2),
            duration_ms: 25,
            file_size_bytes: 4096,
            verdict: Verdict::Clean,
            severity: SeverityLevel::Clean,
            summary_text: "flagged".to_string(),
            action_note: String::new(),
            risk_score: Some(1.0),
            safety_score: Some(0.9),
            signal_sources: vec!["heuristic".to_string()],
            detection_reasons: vec![DetectionReason::default()],
            warning_count: 0,
            error_count: 0,
            quarantine: QuarantineMetadata::default(),
        }
    }
}
