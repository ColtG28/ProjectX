use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use egui::{Align, Align2, CentralPanel, Layout, RichText, Sense, SidePanel, TopBottomPanel, Vec2};
use notify::{
    Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use rfd::FileDialog;

use super::components::empty_state::empty_state;
use super::components::result_detail::render_result_detail;
use super::components::result_list::render_result_row;
use super::state::*;
use super::theme;

const AUTO_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const UPDATE_REPOSITORY: &str = "ColtG-28/ProjectX";

pub fn gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([920.0, 640.0])
            .with_icon(Arc::new(projectx_icon())),
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
        let settings = load_gui_settings();
        let mut app = Self {
            current_page: Page::Analytics,
            menu_open: true,
            period: TimePeriod::Last7Days,
            boot_until: Instant::now() + Duration::from_millis(1200),
            records: persisted.records,
            timing_samples: persisted.timing_samples,
            job: Arc::new(Mutex::new(ScanJobState::default())),
            settings,
            protection_path_input: String::new(),
            single_file_path: String::new(),
            report_search: String::new(),
            history_search: String::new(),
            protection_event_search: String::new(),
            report_verdict_filter: ReportVerdictFilter::All,
            report_storage_filter: ReportStorageFilter::All,
            report_sort_order: ReportSortOrder::NewestFirst,
            protection_kind_filter: ProtectionEventKindFilter::All,
            protection_file_filter: ProtectionFileClassFilter::All,
            protection_priority_filter: ProtectionPriorityFilter::All,
            protection_origin_filter: ProtectionOriginFilter::All,
            protection_verdict_filter: ProtectionVerdictFilter::All,
            protection_action_filter: ProtectionActionFilter::All,
            history_quarantine_only: false,
            selected_report_ids: HashSet::new(),
            focused_report_id: None,
            pending_confirmation: None,
            status_message: String::new(),
            base_pixels_per_point: None,
            last_applied_scale: None,
            ui_metrics: UiMetrics::default(),
            last_protection_poll: Instant::now(),
            protection_watch: HashMap::new(),
            protection_events: load_protection_events(),
            protection_backlog: load_protection_backlog(),
            protection_monitor: ProtectionMonitorRuntime::default(),
            protection_status: String::new(),
            protection_summary: ProtectionSummary::default(),
            last_download_poll: Instant::now(),
            download_watch: HashMap::new(),
            download_status: String::new(),
            last_update_poll: Instant::now() - AUTO_UPDATE_CHECK_INTERVAL,
            update_state: Arc::new(Mutex::new(UpdateCheckState::default())),
        };
        app.refresh_protection_summary();
        app
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
        config.features.enable_local_intelligence = self.settings.enable_local_intelligence;
        config.features.enable_external_intelligence = self.settings.enable_external_intelligence;
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
                    } else if self.settings.enable_real_time_protection {
                        if self.protection_summary.active_status.is_empty() {
                            "Protection active".to_string()
                        } else {
                            self.protection_summary.active_status.clone()
                        }
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

        let protection_event = self.protection_events.iter().rev().find(|event| {
            event.scan_id.as_deref() == Some(record.record_id().as_str())
                || (!event.path.is_empty()
                    && event.path == record.path
                    && event.workflow_source == record.workflow_origin.clone().unwrap_or_default())
        });

        render_result_detail(ui, self.ui_metrics.scale_factor, &record, protection_event);
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

    pub(crate) fn filtered_protection_event_indices(&self, limit: usize) -> Vec<usize> {
        let query = self.protection_event_search.trim().to_ascii_lowercase();
        let mut indices = (0..self.protection_events.len())
            .filter(|&index| {
                let event = &self.protection_events[index];
                self.protection_kind_filter.matches(&event.kind)
                    && self.protection_file_filter.matches(event.file_class)
                    && self.protection_priority_filter.matches(event.priority)
                    && self
                        .protection_origin_filter
                        .matches(&event.workflow_source)
                    && self
                        .protection_verdict_filter
                        .matches(event.verdict.as_deref())
                    && self
                        .protection_action_filter
                        .matches(event.storage_state.as_deref())
                    && (query.is_empty()
                        || event.path.to_ascii_lowercase().contains(&query)
                        || event.note.to_ascii_lowercase().contains(&query)
                        || event.workflow_source.to_ascii_lowercase().contains(&query)
                        || event.kind.to_ascii_lowercase().contains(&query)
                        || event
                            .verdict
                            .as_deref()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(&query)
                        || event
                            .storage_state
                            .as_deref()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(&query))
            })
            .collect::<Vec<_>>();
        indices
            .sort_by_key(|&index| std::cmp::Reverse(self.protection_events[index].timestamp_epoch));
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
            for record in &maybe_records {
                if let Some(origin) = record.workflow_origin.as_deref() {
                    if origin == ScanOrigin::RealTimeProtection.label()
                        || origin == ScanOrigin::DownloadMonitor.label()
                    {
                        self.record_protection_event(ProtectionEventInput {
                            kind: ProtectionEventKind::Completed,
                            path: record.path.clone(),
                            note: format!(
                                "Automatic scan completed with {} and {}.",
                                record.verdict.label(),
                                record.resolved_storage_state().label()
                            ),
                            workflow_source: origin.to_string(),
                            event_source: "Automatic scan result".to_string(),
                            verdict: Some(record.verdict.label().to_string()),
                            storage_state: Some(
                                record.resolved_storage_state().label().to_string(),
                            ),
                            scan_id: Some(record.record_id()),
                            grouped_change_count: 1,
                            burst_window_seconds: 0,
                            change_class: ProtectionChangeClass::Modified,
                            file_class: classify_protection_file(Path::new(&record.path)),
                            priority: classify_protection_priority(
                                Path::new(&record.path),
                                classify_protection_file(Path::new(&record.path)),
                            ),
                        });
                    }
                }
            }
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
        let mut queued_targets = Vec::new();
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
                    entry.last_scanned_size = size;
                    queued_targets.push(target);
                }
            }
        }

        self.download_watch.retain(|path, _| seen.contains(path));
        if !queued_targets.is_empty() {
            self.start_scan(queued_targets.clone());
            for target in &queued_targets {
                self.record_protection_event(ProtectionEventInput {
                    kind: ProtectionEventKind::Queued,
                    path: target.path.to_string_lossy().to_string(),
                    note: "Captured an in-progress download snapshot for passive scanning."
                        .to_string(),
                    workflow_source: target.origin.label().to_string(),
                    event_source: "Download snapshot".to_string(),
                    verdict: None,
                    storage_state: None,
                    scan_id: None,
                    grouped_change_count: 1,
                    burst_window_seconds: 0,
                    change_class: ProtectionChangeClass::Modified,
                    file_class: target.file_class,
                    priority: target.priority,
                });
            }
        }
        self.download_status = if !queued_targets.is_empty() {
            format!(
                "Queued {} download snapshot(s) from {}.",
                queued_targets.len(),
                downloads_dir.display()
            )
        } else if seen.is_empty() {
            "No active downloads detected.".to_string()
        } else {
            format!("Watching {} active download(s).", seen.len())
        };
    }

    fn poll_update_checker(&mut self) {
        if !self.settings.enable_automatic_updates {
            return;
        }

        if self.last_update_poll.elapsed() < AUTO_UPDATE_CHECK_INTERVAL {
            return;
        }

        self.start_update_check(false);
    }

    pub(crate) fn start_update_check(&mut self, manual: bool) {
        self.last_update_poll = Instant::now();

        let Ok(mut state) = self.update_state.lock() else {
            return;
        };
        if state.checking {
            return;
        }
        state.checking = true;
        state.last_error = None;
        state.status = if manual {
            "Checking for updates...".to_string()
        } else {
            "Running automatic update check...".to_string()
        };
        drop(state);

        let update_state = Arc::clone(&self.update_state);
        thread::spawn(move || {
            let outcome = fetch_latest_release_info();
            if let Ok(mut state) = update_state.lock() {
                state.checking = false;
                state.last_checked_epoch = now_epoch();
                match outcome {
                    Ok(Some(update)) => {
                        state.status = format!("Update {} is available.", update.version);
                        state.available_update = Some(update);
                        state.last_error = None;
                    }
                    Ok(None) => {
                        state.status = "ProjectX is up to date.".to_string();
                        state.available_update = None;
                        state.last_error = None;
                    }
                    Err(error) => {
                        state.status = "Update check failed.".to_string();
                        state.available_update = None;
                        state.last_error = Some(error);
                    }
                }
            }
        });
    }

    pub(crate) fn open_available_update(&mut self) {
        let available_update = self
            .update_state
            .lock()
            .ok()
            .and_then(|state| state.available_update.clone());
        let Some(update) = available_update else {
            self.status_message = "No newer update is available right now.".to_string();
            return;
        };

        self.status_message = match open_external_target(&update.asset_url) {
            Ok(()) => format!("Opened {} for download.", update.asset_name),
            Err(error) => format!("Failed to open update download: {error}"),
        };
    }

    pub(crate) fn open_release_notes(&mut self) {
        let release_url = self
            .update_state
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .available_update
                    .as_ref()
                    .map(|update| update.html_url.clone())
            })
            .unwrap_or_else(releases_page_url);

        self.status_message = match open_external_target(&release_url) {
            Ok(()) => "Opened the latest ProjectX release page.".to_string(),
            Err(error) => format!("Failed to open release page: {error}"),
        };
    }

    fn ensure_protection_monitor(&mut self) {
        let signature = protection_watch_signature(&self.settings.watched_paths);
        if !self.settings.enable_real_time_protection {
            self.protection_monitor = ProtectionMonitorRuntime::default();
            return;
        }

        if self.settings.watched_paths.is_empty() {
            self.protection_monitor.mode = ProtectionMonitorMode::Disabled;
            self.protection_monitor.signature = signature;
            self.protection_monitor.source_label = os_event_source_label().to_string();
            self.protection_monitor.health_note =
                "Protection is enabled, but no watched paths are configured.".to_string();
            self.protection_monitor.last_error = None;
            self.protection_monitor.receiver = None;
            self.protection_monitor.watcher = None;
            return;
        }

        if self.protection_monitor.mode == ProtectionMonitorMode::EventDriven
            && self.protection_monitor.signature == signature
            && self.protection_monitor.watcher.is_some()
        {
            return;
        }

        let (tx, rx) = crossbeam_channel::unbounded();
        match create_os_protection_watcher(&self.settings.watched_paths, tx) {
            Ok(watcher) => {
                self.protection_monitor = ProtectionMonitorRuntime {
                    mode: ProtectionMonitorMode::EventDriven,
                    signature,
                    source_label: os_event_source_label().to_string(),
                    health_note: format!(
                        "Watching {} path(s) using {}.",
                        self.settings.watched_paths.len(),
                        os_event_source_label()
                    ),
                    last_error: None,
                    receiver: Some(rx),
                    watcher: Some(watcher),
                };
            }
            Err(error) => {
                self.protection_monitor = ProtectionMonitorRuntime {
                    mode: ProtectionMonitorMode::PollingFallback,
                    signature,
                    source_label: "Polling fallback".to_string(),
                    health_note:
                        "OS event monitoring is unavailable; using grouped polling fallback."
                            .to_string(),
                    last_error: Some(error),
                    receiver: None,
                    watcher: None,
                };
            }
        }
    }

    fn process_protection_monitor(&mut self) {
        match self.protection_monitor.mode {
            ProtectionMonitorMode::Disabled => {
                self.protection_watch.clear();
                self.protection_status.clear();
                self.refresh_protection_summary();
            }
            ProtectionMonitorMode::PollingFallback => self.poll_real_time_protection(),
            ProtectionMonitorMode::EventDriven => self.drain_protection_monitor_events(),
        }
    }

    fn drain_protection_monitor_events(&mut self) {
        if !self.settings.enable_real_time_protection {
            return;
        }
        let watched = self
            .settings
            .watched_paths
            .iter()
            .filter(|entry| !entry.path.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        if watched.is_empty() {
            self.protection_status =
                "Protection enabled, but no watched folders or files are configured.".to_string();
            self.refresh_protection_summary();
            return;
        }

        let Some(receiver) = self.protection_monitor.receiver.clone() else {
            self.protection_monitor.mode = ProtectionMonitorMode::PollingFallback;
            self.protection_monitor.health_note =
                "OS event stream was unavailable; using polling fallback.".to_string();
            self.poll_real_time_protection();
            return;
        };

        let mut messages = Vec::new();
        while messages.len() < 512 {
            match receiver.try_recv() {
                Ok(message) => messages.push(message),
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    self.protection_monitor.mode = ProtectionMonitorMode::PollingFallback;
                    self.protection_monitor.health_note =
                        "OS event stream disconnected; using polling fallback.".to_string();
                    self.protection_monitor.last_error =
                        Some("Watcher channel disconnected".to_string());
                    self.poll_real_time_protection();
                    return;
                }
            }
        }

        if messages.is_empty() {
            self.protection_status = format!(
                "Protection active using {} across {} watched path(s).",
                self.protection_monitor.source_label,
                watched.len()
            );
            self.refresh_protection_summary();
            return;
        }

        let mut changed_targets = HashMap::<String, ScanTarget>::new();
        let mut throttled = 0usize;
        let mut deferred = 0usize;
        let mut skipped = 0usize;
        let queue_backlog = self
            .job
            .lock()
            .map(|job| job.pending_targets.len())
            .unwrap_or_default();
        let pending_paths = self
            .job
            .lock()
            .map(|job| {
                job.pending_targets
                    .iter()
                    .map(|target| target.path.clone())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let queue_capacity = self
            .settings
            .max_files_per_bulk_scan
            .saturating_mul(20)
            .max(200);
        let now = now_epoch();

        for message in messages {
            match message {
                ProtectionMonitorMessage::Error(error) => {
                    self.protection_monitor.last_error = Some(error.clone());
                    self.protection_monitor.health_note =
                        "OS event monitor reported an error; protection will keep using the last healthy configuration."
                            .to_string();
                    self.record_protection_event(ProtectionEventInput {
                        kind: ProtectionEventKind::Error,
                        path: "(watcher)".to_string(),
                        note: error,
                        workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                        event_source: self.protection_monitor.source_label.clone(),
                        verdict: None,
                        storage_state: None,
                        scan_id: None,
                        grouped_change_count: 1,
                        burst_window_seconds: 0,
                        change_class: ProtectionChangeClass::Modified,
                        file_class: ProtectionFileClass::Other,
                        priority: ProtectionPriority::Normal,
                    });
                }
                ProtectionMonitorMessage::Event(event) => {
                    if !is_path_watched(&watched, &event.path) {
                        continue;
                    }
                    let Ok(metadata) = fs::metadata(&event.path) else {
                        continue;
                    };
                    if !metadata.is_file() {
                        continue;
                    }
                    let path_string = event.path.to_string_lossy().to_string();
                    let file_class = classify_protection_file(&event.path);
                    let priority = classify_protection_priority(&event.path, file_class);
                    let target = changed_targets
                        .entry(path_string)
                        .or_insert_with(|| ScanTarget {
                            path: event.path.clone(),
                            last_modified_epoch: metadata
                                .modified()
                                .ok()
                                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                                .map(|duration| duration.as_secs())
                                .unwrap_or(now),
                            size_bytes: metadata.len(),
                            origin: ScanOrigin::RealTimeProtection,
                            priority,
                            file_class,
                            grouped_change_count: 0,
                            burst_window_seconds: 0,
                            change_class: event.change_class,
                        });
                    target.last_modified_epoch = target.last_modified_epoch.max(
                        metadata
                            .modified()
                            .ok()
                            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                            .map(|duration| duration.as_secs())
                            .unwrap_or(now),
                    );
                    target.size_bytes = metadata.len();
                    target.priority = target.priority.max(priority);
                    target.file_class = file_class;
                    target.grouped_change_count = target.grouped_change_count.saturating_add(1);
                    target.change_class =
                        if matches!(target.change_class, ProtectionChangeClass::Replaced)
                            || matches!(event.change_class, ProtectionChangeClass::Replaced)
                        {
                            ProtectionChangeClass::Replaced
                        } else if matches!(target.change_class, ProtectionChangeClass::Created)
                            || matches!(event.change_class, ProtectionChangeClass::Created)
                        {
                            ProtectionChangeClass::Created
                        } else {
                            ProtectionChangeClass::Modified
                        };
                }
            }
        }

        let mut queued_targets = Vec::new();
        for (key, mut discovered) in changed_targets {
            let entry = self.protection_watch.entry(key.clone()).or_default();
            if entry.grouped_change_count == 0 {
                entry.burst_started_epoch = now;
            }
            entry.burst_last_epoch = now;
            entry.grouped_change_count = entry
                .grouped_change_count
                .saturating_add(discovered.grouped_change_count.max(1));
            entry.last_change_class = discovered.change_class;
            entry.modified_epoch = discovered.last_modified_epoch;
            entry.size_bytes = discovered.size_bytes;
            discovered.grouped_change_count = entry.grouped_change_count.max(1);
            discovered.burst_window_seconds = entry
                .burst_last_epoch
                .saturating_sub(entry.burst_started_epoch);

            if should_skip_as_noise(&discovered) {
                skipped += 1;
                entry.needs_rescan = false;
                entry.grouped_change_count = 0;
                entry.burst_started_epoch = 0;
                entry.burst_last_epoch = 0;
                self.record_protection_event(ProtectionEventInput {
                    kind: ProtectionEventKind::Skipped,
                    path: key.clone(),
                    note: "Skipped a low-value temp/cache change because it matched passive noise heuristics."
                        .to_string(),
                    workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                    event_source: self.protection_monitor.source_label.clone(),
                    verdict: None,
                    storage_state: None,
                    scan_id: None,
                    grouped_change_count: discovered.grouped_change_count,
                    burst_window_seconds: discovered.burst_window_seconds,
                    change_class: discovered.change_class,
                    file_class: discovered.file_class,
                    priority: discovered.priority,
                });
                continue;
            }

            let cooldown = per_file_cooldown(&discovered);
            let should_throttle = entry.last_queued_epoch != 0
                && now.saturating_sub(entry.last_queued_epoch) < cooldown.as_secs();
            if should_throttle {
                throttled += 1;
                self.record_protection_event(ProtectionEventInput {
                    kind: ProtectionEventKind::Throttled,
                    path: key.clone(),
                    note: "Grouped rapid OS file events into the active protection burst instead of queueing another scan immediately."
                        .to_string(),
                    workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                    event_source: self.protection_monitor.source_label.clone(),
                    verdict: None,
                    storage_state: None,
                    scan_id: None,
                    grouped_change_count: discovered.grouped_change_count,
                    burst_window_seconds: discovered.burst_window_seconds,
                    change_class: discovered.change_class,
                    file_class: discovered.file_class,
                    priority: discovered.priority,
                });
                continue;
            }

            let queue_busy = queue_backlog + queued_targets.len() >= queue_capacity;
            let already_queued = queued_targets
                .iter()
                .any(|target: &ScanTarget| target.path == discovered.path)
                || pending_paths.contains(&discovered.path);
            if queue_busy {
                deferred += 1;
                entry.last_queued_epoch = now;
                entry.needs_rescan = false;
                entry.grouped_change_count = 0;
                entry.burst_started_epoch = 0;
                entry.burst_last_epoch = 0;
                self.defer_protection_target(
                    discovered.clone(),
                    "Deferred protection scan because the event-driven queue is busy; the latest file snapshot will be retried when load drops.",
                    ProtectionEventKind::Deferred,
                );
                continue;
            }
            if already_queued {
                deferred += 1;
                entry.last_queued_epoch = now;
                entry.needs_rescan = false;
                entry.grouped_change_count = 0;
                entry.burst_started_epoch = 0;
                entry.burst_last_epoch = 0;
                self.defer_protection_target(
                    discovered.clone(),
                    "Grouped additional OS file events into a deferred follow-up because this file already has an active protection scan queued.",
                    ProtectionEventKind::Deferred,
                );
                continue;
            }

            entry.last_queued_epoch = now;
            entry.needs_rescan = false;
            entry.grouped_change_count = 0;
            entry.burst_started_epoch = 0;
            entry.burst_last_epoch = 0;
            queued_targets.push(discovered.clone());
            self.record_protection_event(ProtectionEventInput {
                kind: ProtectionEventKind::Queued,
                path: key.clone(),
                note: queued_event_note(
                    discovered.change_class,
                    discovered.grouped_change_count,
                    discovered.file_class,
                ),
                workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                event_source: self.protection_monitor.source_label.clone(),
                verdict: None,
                storage_state: None,
                scan_id: None,
                grouped_change_count: discovered.grouped_change_count,
                burst_window_seconds: discovered.burst_window_seconds,
                change_class: discovered.change_class,
                file_class: discovered.file_class,
                priority: discovered.priority,
            });
        }

        let queued_count = queued_targets.len();
        if !queued_targets.is_empty() {
            self.start_scan(queued_targets);
        }
        self.protection_status = format!(
            "Protection active using {} across {} watched path(s), queued {} grouped event(s){}{}{}.",
            self.protection_monitor.source_label,
            watched.len(),
            queued_count,
            if throttled > 0 {
                format!(", throttled {}", throttled)
            } else {
                String::new()
            },
            if deferred > 0 {
                format!(", deferred {}", deferred)
            } else {
                String::new()
            },
            if skipped > 0 {
                format!(", skipped {}", skipped)
            } else {
                String::new()
            }
        );
        self.refresh_protection_summary();
    }

    fn poll_real_time_protection(&mut self) {
        if !self.settings.enable_real_time_protection {
            self.protection_watch.clear();
            self.protection_status.clear();
            self.refresh_protection_summary();
            return;
        }

        if self.last_protection_poll.elapsed() < Duration::from_millis(1800) {
            return;
        }
        self.last_protection_poll = Instant::now();

        let watched = self
            .settings
            .watched_paths
            .iter()
            .filter(|entry| !entry.path.trim().is_empty())
            .cloned()
            .collect::<Vec<_>>();
        if watched.is_empty() {
            self.protection_status =
                "Protection enabled, but no watched folders or files are configured.".to_string();
            self.refresh_protection_summary();
            return;
        }

        let max_files = self
            .settings
            .max_files_per_bulk_scan
            .saturating_mul(40)
            .clamp(200, 5_000);
        let now = now_epoch();
        let mut seen_paths = HashSet::new();
        let mut queued_targets = Vec::new();
        let mut throttled = 0usize;
        let mut deferred = 0usize;
        let mut skipped = 0usize;
        let queue_backlog = self
            .job
            .lock()
            .map(|job| job.pending_targets.len())
            .unwrap_or_default();
        let pending_paths = self
            .job
            .lock()
            .map(|job| {
                job.pending_targets
                    .iter()
                    .map(|target| target.path.clone())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let queue_capacity = self
            .settings
            .max_files_per_bulk_scan
            .saturating_mul(20)
            .max(200);

        for watched_path in watched {
            let mut queued_for_path = 0usize;
            let path_limit = watched_path_rate_limit(&watched_path.path);
            for discovered in collect_protection_targets(&watched_path, max_files) {
                let key = discovered.path.to_string_lossy().to_string();
                seen_paths.insert(key.clone());

                let (changed, change_class, grouped_change_count, burst_window_seconds) = {
                    let entry = self.protection_watch.entry(key.clone()).or_default();
                    let changed = entry.needs_rescan
                        || entry.modified_epoch != discovered.last_modified_epoch
                        || entry.size_bytes != discovered.size_bytes;
                    let change_class = if changed {
                        classify_change(entry, &discovered)
                    } else {
                        entry.last_change_class
                    };

                    if changed {
                        if entry.grouped_change_count == 0 {
                            entry.burst_started_epoch = now;
                        }
                        entry.burst_last_epoch = now;
                        entry.grouped_change_count = entry.grouped_change_count.saturating_add(1);
                        entry.last_change_class = change_class;
                        entry.needs_rescan = true;
                    }
                    entry.modified_epoch = discovered.last_modified_epoch;
                    entry.size_bytes = discovered.size_bytes;
                    (
                        changed,
                        change_class,
                        entry.grouped_change_count.max(1),
                        entry
                            .burst_last_epoch
                            .saturating_sub(entry.burst_started_epoch),
                    )
                };

                if !changed {
                    continue;
                }

                let mut discovered = discovered;
                discovered.grouped_change_count = grouped_change_count;
                discovered.burst_window_seconds = burst_window_seconds;
                discovered.change_class = change_class;

                if should_skip_as_noise(&discovered) {
                    skipped += 1;
                    if let Some(entry) = self.protection_watch.get_mut(&key) {
                        entry.needs_rescan = false;
                        entry.grouped_change_count = 0;
                        entry.burst_started_epoch = 0;
                        entry.burst_last_epoch = 0;
                    }
                    self.record_protection_event(ProtectionEventInput {
                        kind: ProtectionEventKind::Skipped,
                        path: key.clone(),
                        note: "Skipped a low-value temp/cache change because it matched passive noise heuristics."
                            .to_string(),
                        workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                        event_source: "Polling fallback".to_string(),
                        verdict: None,
                        storage_state: None,
                        scan_id: None,
                        grouped_change_count,
                        burst_window_seconds,
                        change_class,
                        file_class: discovered.file_class,
                        priority: discovered.priority,
                    });
                    continue;
                }

                let cooldown = per_file_cooldown(&discovered);
                let should_throttle = self.protection_watch.get(&key).is_some_and(|entry| {
                    entry.last_queued_epoch != 0
                        && now.saturating_sub(entry.last_queued_epoch) < cooldown.as_secs()
                });
                let over_path_limit = queued_for_path >= path_limit;
                let queue_busy = queue_backlog + queued_targets.len() >= queue_capacity;
                let already_queued = queued_targets
                    .iter()
                    .any(|target: &ScanTarget| target.path == discovered.path)
                    || pending_paths.contains(&discovered.path);

                if should_throttle {
                    throttled += 1;
                    self.record_protection_event(ProtectionEventInput {
                        kind: ProtectionEventKind::Throttled,
                        path: key.clone(),
                        note: "Grouped rapid repeat file changes into the active protection burst instead of queueing another scan immediately."
                            .to_string(),
                        workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                        event_source: "Polling fallback".to_string(),
                        verdict: None,
                        storage_state: None,
                        scan_id: None,
                        grouped_change_count,
                        burst_window_seconds,
                        change_class,
                        file_class: discovered.file_class,
                        priority: discovered.priority,
                    });
                    continue;
                }

                if over_path_limit || queue_busy || already_queued {
                    deferred += 1;
                    if let Some(entry) = self.protection_watch.get_mut(&key) {
                        entry.last_queued_epoch = now;
                        entry.needs_rescan = false;
                        entry.grouped_change_count = 0;
                        entry.burst_started_epoch = 0;
                        entry.burst_last_epoch = 0;
                    }
                    let note = if already_queued {
                        "Grouped additional changes into a deferred follow-up because this file already has an active protection scan queued."
                    } else if queue_busy {
                        "Deferred protection scan because the queue is busy; the latest file snapshot will be retried when load drops."
                    } else {
                        "Deferred extra changes for this watched path into the protection backlog to avoid flooding the active queue."
                    };
                    self.defer_protection_target(
                        discovered.clone(),
                        note,
                        ProtectionEventKind::Deferred,
                    );
                    continue;
                }

                if let Some(entry) = self.protection_watch.get_mut(&key) {
                    entry.last_queued_epoch = now;
                    entry.needs_rescan = false;
                    entry.grouped_change_count = 0;
                    entry.burst_started_epoch = 0;
                    entry.burst_last_epoch = 0;
                }
                queued_for_path = queued_for_path.saturating_add(1);
                queued_targets.push(discovered.clone());
                self.record_protection_event(ProtectionEventInput {
                    kind: ProtectionEventKind::Queued,
                    path: key.clone(),
                    note: queued_event_note(
                        change_class,
                        grouped_change_count,
                        discovered.file_class,
                    ),
                    workflow_source: ScanOrigin::RealTimeProtection.label().to_string(),
                    event_source: "Polling fallback".to_string(),
                    verdict: None,
                    storage_state: None,
                    scan_id: None,
                    grouped_change_count,
                    burst_window_seconds,
                    change_class,
                    file_class: discovered.file_class,
                    priority: discovered.priority,
                });
            }
        }

        self.protection_watch
            .retain(|path, _| seen_paths.contains(path));

        let queued_count = queued_targets.len();
        if !queued_targets.is_empty() {
            self.start_scan(queued_targets);
        }

        self.protection_status = format!(
            "Protection watching {} location(s), tracking {} file(s), queued {} grouped event(s){}{}{}.",
            self.settings.watched_paths.len(),
            self.protection_watch.len(),
            queued_count,
            if throttled > 0 {
                format!(", throttled {}", throttled)
            } else {
                String::new()
            },
            if deferred > 0 {
                format!(", deferred {}", deferred)
            } else {
                String::new()
            },
            if skipped > 0 {
                format!(", skipped {}", skipped)
            } else {
                String::new()
            }
        );
        self.refresh_protection_summary();
    }

    fn defer_protection_target(
        &mut self,
        target: ScanTarget,
        note: &str,
        kind: ProtectionEventKind,
    ) {
        if let Some(existing) = self
            .protection_backlog
            .iter_mut()
            .find(|queued| queued.path == target.path)
        {
            existing.last_modified_epoch =
                existing.last_modified_epoch.max(target.last_modified_epoch);
            existing.size_bytes = target.size_bytes;
            existing.priority = existing.priority.max(target.priority);
            existing.file_class = target.file_class;
            existing.grouped_change_count = existing
                .grouped_change_count
                .saturating_add(target.grouped_change_count.max(1));
            existing.burst_window_seconds = existing
                .burst_window_seconds
                .max(target.burst_window_seconds);
            existing.change_class = target.change_class;
        } else {
            self.protection_backlog.push_back(target.clone());
        }
        save_protection_backlog(&self.protection_backlog);
        self.record_protection_event(ProtectionEventInput {
            kind,
            path: target.path.to_string_lossy().to_string(),
            note: note.to_string(),
            workflow_source: target.origin.label().to_string(),
            event_source: if matches!(
                self.protection_monitor.mode,
                ProtectionMonitorMode::EventDriven
            ) {
                self.protection_monitor.source_label.clone()
            } else {
                "Polling fallback".to_string()
            },
            verdict: None,
            storage_state: None,
            scan_id: None,
            grouped_change_count: target.grouped_change_count.max(1),
            burst_window_seconds: target.burst_window_seconds,
            change_class: target.change_class,
            file_class: target.file_class,
            priority: target.priority,
        });
    }

    fn drain_protection_backlog(&mut self) {
        if !self.settings.enable_real_time_protection || self.protection_backlog.is_empty() {
            return;
        }
        let queue_backlog = self
            .job
            .lock()
            .map(|job| job.pending_targets.len())
            .unwrap_or_default();
        let queue_capacity = self
            .settings
            .max_files_per_bulk_scan
            .saturating_mul(20)
            .max(200);
        let pending_paths = self
            .job
            .lock()
            .map(|job| {
                job.pending_targets
                    .iter()
                    .map(|target| target.path.clone())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let available = queue_capacity.saturating_sub(queue_backlog);
        if available == 0 {
            self.refresh_protection_summary();
            return;
        }

        let mut resumed = Vec::new();
        let retry_budget = available.min(24);
        while resumed.len() < retry_budget {
            let Some(index) =
                highest_priority_backlog_index(&self.protection_backlog, &pending_paths)
            else {
                break;
            };
            let Some(target) = self.protection_backlog.remove(index) else {
                break;
            };
            resumed.push(target);
        }
        if resumed.is_empty() {
            return;
        }
        save_protection_backlog(&self.protection_backlog);
        for target in &resumed {
            self.record_protection_event(ProtectionEventInput {
                kind: ProtectionEventKind::Queued,
                path: target.path.to_string_lossy().to_string(),
                note: "Queued a previously deferred protection event after queue pressure dropped."
                    .to_string(),
                workflow_source: target.origin.label().to_string(),
                event_source: if matches!(
                    self.protection_monitor.mode,
                    ProtectionMonitorMode::EventDriven
                ) {
                    self.protection_monitor.source_label.clone()
                } else {
                    "Polling fallback".to_string()
                },
                verdict: None,
                storage_state: None,
                scan_id: None,
                grouped_change_count: target.grouped_change_count.max(1),
                burst_window_seconds: target.burst_window_seconds,
                change_class: target.change_class,
                file_class: target.file_class,
                priority: target.priority,
            });
        }
        self.start_scan(resumed);
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

    pub(crate) fn add_watched_path(&mut self, path: PathBuf, recursive: bool) {
        let normalized = path.to_string_lossy().to_string();
        if normalized.is_empty() {
            return;
        }
        if self
            .settings
            .watched_paths
            .iter()
            .any(|entry| entry.path == normalized)
        {
            self.status_message = "That path is already being watched.".to_string();
            return;
        }
        self.settings.watched_paths.push(WatchedPathConfig {
            path: normalized.clone(),
            recursive,
        });
        save_gui_settings(&self.settings);
        self.refresh_protection_summary();
        self.status_message = format!("Added watched path: {normalized}");
    }

    pub(crate) fn remove_watched_path(&mut self, path: &str) {
        self.settings
            .watched_paths
            .retain(|entry| entry.path != path);
        self.protection_watch
            .retain(|tracked, _| !tracked.starts_with(path));
        self.protection_backlog
            .retain(|target| !target.path.to_string_lossy().starts_with(path));
        save_protection_backlog(&self.protection_backlog);
        save_gui_settings(&self.settings);
        self.refresh_protection_summary();
        self.status_message = format!("Removed watched path: {path}");
    }

    fn record_protection_event(&mut self, input: ProtectionEventInput) {
        let timestamp = now_epoch();
        let kind_label = input.kind.label().to_string();
        if let Some(existing) = self.protection_events.iter_mut().rev().find(|event| {
            event.path == input.path
                && event.kind == kind_label
                && event.workflow_source == input.workflow_source
                && event.event_source == input.event_source
                && timestamp.saturating_sub(event.timestamp_epoch) <= 10
        }) {
            existing.timestamp_epoch = timestamp;
            existing.grouped_change_count = existing
                .grouped_change_count
                .max(1)
                .saturating_add(input.grouped_change_count.saturating_sub(1));
            existing.burst_window_seconds = existing
                .burst_window_seconds
                .max(input.burst_window_seconds);
            existing.note = input.note;
            existing.event_source = input.event_source;
            existing.change_class = input.change_class;
            existing.file_class = input.file_class;
            existing.priority = input.priority;
            if let Some(verdict) = input.verdict {
                existing.verdict = Some(verdict);
            }
            if let Some(storage_state) = input.storage_state {
                existing.storage_state = Some(storage_state);
            }
            if input.scan_id.is_some() {
                existing.scan_id = input.scan_id;
            }
        } else {
            self.protection_events.push(ProtectionEvent {
                id: format!("{}::{}", timestamp, input.path),
                timestamp_epoch: timestamp,
                path: input.path,
                kind: kind_label,
                note: input.note,
                workflow_source: input.workflow_source,
                event_source: input.event_source,
                verdict: input.verdict,
                storage_state: input.storage_state,
                scan_id: input.scan_id,
                grouped_change_count: input.grouped_change_count.max(1),
                burst_window_seconds: input.burst_window_seconds,
                change_class: input.change_class,
                file_class: input.file_class,
                priority: input.priority,
            });
        }
        trim_protection_events(&mut self.protection_events);
        save_protection_events(&self.protection_events);
        self.refresh_protection_summary();
    }

    pub(crate) fn refresh_protection_summary(&mut self) {
        let queued_event_count = self
            .protection_events
            .iter()
            .filter(|event| event.kind == ProtectionEventKind::Queued.label())
            .count();
        let deferred_event_count = self
            .protection_events
            .iter()
            .filter(|event| event.kind == ProtectionEventKind::Deferred.label())
            .count();
        let throttled_event_count = self
            .protection_events
            .iter()
            .filter(|event| event.kind == ProtectionEventKind::Throttled.label())
            .count();
        let skipped_event_count = self
            .protection_events
            .iter()
            .filter(|event| event.kind == ProtectionEventKind::Skipped.label())
            .count();
        let queue_capacity = self
            .settings
            .max_files_per_bulk_scan
            .saturating_mul(20)
            .max(200);
        let live_queue_backlog = self
            .job
            .lock()
            .map(|job| job.pending_targets.len())
            .unwrap_or_default();
        let recent_window_start = now_epoch().saturating_sub(120);
        let recent_deferred = self
            .protection_events
            .iter()
            .filter(|event| {
                event.timestamp_epoch >= recent_window_start
                    && event.kind == ProtectionEventKind::Deferred.label()
            })
            .count();
        let recent_throttled = self
            .protection_events
            .iter()
            .filter(|event| {
                event.timestamp_epoch >= recent_window_start
                    && event.kind == ProtectionEventKind::Throttled.label()
            })
            .count();
        let last_event_label = self
            .protection_events
            .last()
            .map(|event| {
                format!(
                    "{} {} [{} | {}]",
                    event.kind,
                    format_timestamp_compact(event.timestamp_epoch),
                    event.change_class.label(),
                    event.file_class.label()
                )
            })
            .unwrap_or_else(|| "No recent protection events".to_string());
        let (queue_health, queue_health_detail) = protection_queue_health(
            self.protection_backlog.len(),
            live_queue_backlog,
            queue_capacity,
            recent_deferred,
            recent_throttled,
        );
        let dropped_events = self
            .protection_events
            .iter()
            .filter(|event| event.kind == ProtectionEventKind::Skipped.label())
            .count();
        let event_drop_rate = percent_label(dropped_events, self.protection_events.len());
        let grouped_change_total = self
            .protection_events
            .iter()
            .map(|event| event.grouped_change_count.max(1))
            .sum::<usize>();
        let dedupe_efficiency = if grouped_change_total == 0 {
            "0%".to_string()
        } else {
            percent_label(
                grouped_change_total.saturating_sub(self.protection_events.len()),
                grouped_change_total,
            )
        };
        let recovered_backlog = self
            .protection_events
            .iter()
            .filter(|event| {
                event.kind == ProtectionEventKind::Queued.label()
                    && event.note.contains("previously deferred")
            })
            .count();
        let backlog_recovery_rate = percent_label(recovered_backlog, deferred_event_count.max(1));

        self.protection_summary = ProtectionSummary {
            enabled: self.settings.enable_real_time_protection,
            monitor_mode: self.protection_monitor.mode.label().to_string(),
            monitor_state: if !self.settings.enable_real_time_protection {
                "Inactive".to_string()
            } else if matches!(
                self.protection_monitor.mode,
                ProtectionMonitorMode::PollingFallback
            ) {
                "Degraded".to_string()
            } else if self.protection_monitor.last_error.is_some()
                && matches!(
                    self.protection_monitor.mode,
                    ProtectionMonitorMode::Disabled
                )
            {
                "Unavailable".to_string()
            } else {
                "Active".to_string()
            },
            watched_path_count: self.settings.watched_paths.len(),
            tracked_file_count: self.protection_watch.len(),
            recent_event_count: self.protection_events.len().min(25),
            queued_event_count,
            deferred_event_count,
            throttled_event_count,
            skipped_event_count,
            backlog_count: self.protection_backlog.len(),
            queue_health,
            queue_health_detail,
            event_drop_rate,
            dedupe_efficiency,
            backlog_recovery_rate,
            active_status: if !self.settings.enable_real_time_protection {
                "Protection disabled.".to_string()
            } else if !self.protection_monitor.health_note.is_empty() {
                format!(
                    "{} {}",
                    self.protection_monitor.health_note, self.protection_status
                )
                .trim()
                .to_string()
            } else if self.protection_status.is_empty() {
                "Protection active and waiting for file changes.".to_string()
            } else {
                self.protection_status.clone()
            },
            last_event_label,
        };
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

        let targets = collect_scan_targets(
            &roots,
            self.settings.max_files_per_bulk_scan,
            ScanOrigin::Manual,
        );
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
        self.ensure_protection_monitor();
        self.drain_protection_backlog();
        self.process_protection_monitor();
        self.poll_download_monitor();
        self.poll_update_checker();

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

        if self.is_loading()
            || self.settings.enable_download_monitoring
            || self.settings.enable_real_time_protection
            || self
                .update_state
                .lock()
                .map(|state| state.checking)
                .unwrap_or(false)
        {
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
                    reused_cached_record(
                        previous,
                        target.last_modified_epoch,
                        target.size_bytes,
                        target.origin,
                    )
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
    origin: ScanOrigin,
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
    record.workflow_origin = Some(origin.label().to_string());
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
        workflow_origin: Some(target.origin.label().to_string()),
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
            if !matches!(target.origin, ScanOrigin::Manual) {
                note_parts.insert(0, format!("Triggered by {}", target.origin.label()));
            }
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
                workflow_origin: Some(target.origin.label().to_string()),
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

#[derive(Debug)]
struct ProtectionEventInput {
    kind: ProtectionEventKind,
    path: String,
    note: String,
    workflow_source: String,
    event_source: String,
    verdict: Option<String>,
    storage_state: Option<String>,
    scan_id: Option<String>,
    grouped_change_count: usize,
    burst_window_seconds: u64,
    change_class: ProtectionChangeClass,
    file_class: ProtectionFileClass,
    priority: ProtectionPriority,
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
    let mut prioritized = targets;
    prioritized.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.path.cmp(&right.path))
    });

    for target in prioritized {
        if known_paths.insert(target.path.clone()) {
            added_count += 1;
            added_bytes = added_bytes.saturating_add(target.size_bytes);
            if target.priority == ProtectionPriority::High {
                job.pending_targets.push_front(target);
            } else {
                job.pending_targets.push_back(target);
            }
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

fn protection_watch_signature(paths: &[WatchedPathConfig]) -> String {
    let mut entries = paths
        .iter()
        .map(|entry| format!("{}::{}", entry.path, entry.recursive))
        .collect::<Vec<_>>();
    entries.sort();
    entries.join("|")
}

fn os_event_source_label() -> &'static str {
    match std::env::consts::OS {
        "windows" => "Windows file events",
        "macos" => "macOS file events",
        "linux" => "Linux file events",
        _ => "OS file events",
    }
}

fn create_os_protection_watcher(
    watched_paths: &[WatchedPathConfig],
    sender: crossbeam_channel::Sender<ProtectionMonitorMessage>,
) -> Result<RecommendedWatcher, String> {
    let mut watcher = RecommendedWatcher::new(
        move |result: Result<Event, notify::Error>| match result {
            Ok(event) => {
                for protection_event in translate_notify_event(event) {
                    let _ = sender.send(ProtectionMonitorMessage::Event(protection_event));
                }
            }
            Err(error) => {
                let _ = sender.send(ProtectionMonitorMessage::Error(error.to_string()));
            }
        },
        NotifyConfig::default(),
    )
    .map_err(|error| error.to_string())?;

    for watched in watched_paths
        .iter()
        .filter(|entry| !entry.path.trim().is_empty())
    {
        watcher
            .watch(
                Path::new(&watched.path),
                if watched.recursive {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                },
            )
            .map_err(|error| format!("{} ({})", error, watched.path))?;
    }

    Ok(watcher)
}

fn translate_notify_event(event: Event) -> Vec<ProtectionMonitorEvent> {
    let Some(change_class) = notify_change_class(&event.kind) else {
        return Vec::new();
    };
    event
        .paths
        .into_iter()
        .filter(|path| path.is_file() || path.extension().is_some())
        .map(|path| ProtectionMonitorEvent {
            path,
            change_class,
            source_label: os_event_source_label().to_string(),
        })
        .collect()
}

fn notify_change_class(kind: &EventKind) -> Option<ProtectionChangeClass> {
    use notify::event::{CreateKind, ModifyKind, RenameMode};

    match kind {
        EventKind::Create(CreateKind::Any | CreateKind::File | CreateKind::Folder) => {
            Some(ProtectionChangeClass::Created)
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Any))
        | EventKind::Modify(ModifyKind::Name(RenameMode::Both))
        | EventKind::Modify(ModifyKind::Name(RenameMode::From))
        | EventKind::Modify(ModifyKind::Name(RenameMode::To))
        | EventKind::Modify(ModifyKind::Name(RenameMode::Other)) => {
            Some(ProtectionChangeClass::Replaced)
        }
        EventKind::Modify(_) => Some(ProtectionChangeClass::Modified),
        _ => None,
    }
}

fn is_path_watched(watched: &[WatchedPathConfig], path: &Path) -> bool {
    watched.iter().any(|entry| {
        let root = Path::new(&entry.path);
        if entry.recursive {
            path.starts_with(root)
        } else {
            path == root || path.parent().is_some_and(|parent| parent == root)
        }
    })
}

fn protection_queue_health(
    backlog: usize,
    queued: usize,
    capacity: usize,
    recent_deferred: usize,
    recent_throttled: usize,
) -> (String, String) {
    let safe_capacity = capacity.max(1);
    let load_ratio = queued as f32 / safe_capacity as f32;
    if backlog >= safe_capacity / 8 || load_ratio >= 0.8 || recent_deferred >= 3 {
        (
            "Backed up".to_string(),
            format!(
                "{} queued of {}, {} backlog, {} recent deferrals, {} recent throttles",
                queued, safe_capacity, backlog, recent_deferred, recent_throttled
            ),
        )
    } else if backlog > 0 || load_ratio >= 0.4 || recent_throttled >= 4 || recent_deferred > 0 {
        (
            "Busy".to_string(),
            format!(
                "{} queued of {}, {} backlog, {} recent deferrals, {} recent throttles",
                queued, safe_capacity, backlog, recent_deferred, recent_throttled
            ),
        )
    } else {
        (
            "Healthy".to_string(),
            format!(
                "{} queued of {}, no deferred backlog, {} recent throttles",
                queued, safe_capacity, recent_throttled
            ),
        )
    }
}

fn highest_priority_backlog_index(
    backlog: &VecDeque<ScanTarget>,
    pending_paths: &HashSet<PathBuf>,
) -> Option<usize> {
    backlog
        .iter()
        .enumerate()
        .filter(|(_, target)| !pending_paths.contains(&target.path))
        .max_by_key(|(index, target)| (target.priority, std::cmp::Reverse(*index)))
        .map(|(index, _)| index)
}

fn classify_change(
    previous: &ProtectionWatchEntry,
    discovered: &ScanTarget,
) -> ProtectionChangeClass {
    if previous.modified_epoch == 0 && previous.size_bytes == 0 {
        ProtectionChangeClass::Created
    } else if discovered.size_bytes.saturating_add(4_096) < previous.size_bytes
        || discovered.last_modified_epoch < previous.modified_epoch
    {
        ProtectionChangeClass::Replaced
    } else {
        ProtectionChangeClass::Modified
    }
}

fn classify_protection_file(path: &Path) -> ProtectionFileClass {
    let lowered = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let path_lower = path.to_string_lossy().to_ascii_lowercase();

    if is_temp_or_cache_path(&path_lower) {
        return ProtectionFileClass::TempCache;
    }

    match lowered.as_str() {
        "tmp" | "temp" | "cache" | "crdownload" | "download" | "partial" | "part" => {
            ProtectionFileClass::TempCache
        }
        "exe" | "dll" | "sys" | "msi" | "com" | "app" | "pkg" | "dmg" | "deb" | "rpm" | "bin"
        | "so" | "dylib" => ProtectionFileClass::Executable,
        "ps1" | "psm1" | "js" | "jse" | "vbs" | "vba" | "bat" | "cmd" | "sh" | "zsh" | "py"
        | "rb" => ProtectionFileClass::Script,
        "zip" | "rar" | "7z" | "tar" | "gz" | "tgz" | "xz" => ProtectionFileClass::Archive,
        "doc" | "docm" | "docx" | "xls" | "xlsm" | "xlsx" | "ppt" | "pptm" | "pdf" | "rtf" => {
            ProtectionFileClass::Document
        }
        _ => ProtectionFileClass::Other,
    }
}

fn should_skip_as_noise(target: &ScanTarget) -> bool {
    matches!(target.file_class, ProtectionFileClass::TempCache)
        && target.size_bytes <= 2_048
        && matches!(target.change_class, ProtectionChangeClass::Created)
}

fn classify_protection_priority(path: &Path, class: ProtectionFileClass) -> ProtectionPriority {
    let path_lower = path.to_string_lossy().to_ascii_lowercase();
    if is_downloads_path(&path_lower)
        || matches!(
            class,
            ProtectionFileClass::Executable | ProtectionFileClass::Script
        )
    {
        ProtectionPriority::High
    } else if matches!(class, ProtectionFileClass::TempCache) {
        ProtectionPriority::Low
    } else {
        ProtectionPriority::Normal
    }
}

fn per_file_cooldown(target: &ScanTarget) -> Duration {
    match (target.priority, target.file_class) {
        (ProtectionPriority::High, _) => Duration::from_secs(2),
        (_, ProtectionFileClass::TempCache) => Duration::from_secs(12),
        (_, ProtectionFileClass::Archive | ProtectionFileClass::Document) => Duration::from_secs(6),
        _ => Duration::from_secs(5),
    }
}

fn watched_path_rate_limit(path: &str) -> usize {
    let lowered = path.to_ascii_lowercase();
    if is_downloads_path(&lowered) {
        12
    } else if is_temp_or_cache_path(&lowered) {
        2
    } else {
        6
    }
}

fn is_downloads_path(path: &str) -> bool {
    path.contains("/downloads") || path.contains("\\downloads")
}

fn is_temp_or_cache_path(path: &str) -> bool {
    path.contains("/cache/")
        || path.contains("\\cache\\")
        || path.contains("/.cache/")
        || path.contains("/logs/")
}

fn queued_event_note(
    change_class: ProtectionChangeClass,
    grouped_change_count: usize,
    file_class: ProtectionFileClass,
) -> String {
    if grouped_change_count > 1 {
        format!(
            "Queued one passive scan after {} {} change(s) were grouped for this {} file.",
            grouped_change_count,
            change_class.label().to_ascii_lowercase(),
            file_class.label().to_ascii_lowercase()
        )
    } else {
        format!(
            "Queued an automatic passive scan after the watched {} file was {}.",
            file_class.label().to_ascii_lowercase(),
            change_class.label().to_ascii_lowercase()
        )
    }
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
        record
            .workflow_origin
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
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

fn projectx_icon() -> egui::IconData {
    let width = 128usize;
    let height = 128usize;
    let mut rgba = vec![0u8; width * height * 4];

    let background = [17u8, 80u8, 63u8, 255u8];
    let accent = [228u8, 117u8, 49u8, 255u8];
    let light = [245u8, 239u8, 225u8, 255u8];
    let shadow = [12u8, 42u8, 34u8, 255u8];

    fill_rounded_rect(&mut rgba, width, 0, 0, width, height, 26, background);
    fill_circle(&mut rgba, width, 102, 28, 22, accent);
    fill_circle(&mut rgba, width, 26, 104, 16, shadow);

    draw_p(&mut rgba, width, 26, 24, 30, 78, light);
    draw_x(&mut rgba, width, 72, 26, 28, 74, light);

    egui::IconData {
        rgba,
        width: width as u32,
        height: height as u32,
    }
}

fn set_pixel(rgba: &mut [u8], width: usize, x: usize, y: usize, color: [u8; 4]) {
    let index = (y * width + x) * 4;
    rgba[index..index + 4].copy_from_slice(&color);
}

fn fill_rect(
    rgba: &mut [u8],
    width: usize,
    x: usize,
    y: usize,
    rect_width: usize,
    rect_height: usize,
    color: [u8; 4],
) {
    for yy in y..(y + rect_height) {
        for xx in x..(x + rect_width) {
            set_pixel(rgba, width, xx, yy, color);
        }
    }
}

fn fill_circle(
    rgba: &mut [u8],
    width: usize,
    center_x: usize,
    center_y: usize,
    radius: usize,
    color: [u8; 4],
) {
    let radius_sq = (radius * radius) as isize;
    for yy in center_y.saturating_sub(radius)..=(center_y + radius).min(width - 1) {
        for xx in center_x.saturating_sub(radius)..=(center_x + radius).min(width - 1) {
            let dx = xx as isize - center_x as isize;
            let dy = yy as isize - center_y as isize;
            if dx * dx + dy * dy <= radius_sq {
                set_pixel(rgba, width, xx, yy, color);
            }
        }
    }
}

fn fill_rounded_rect(
    rgba: &mut [u8],
    width: usize,
    x: usize,
    y: usize,
    rect_width: usize,
    rect_height: usize,
    radius: usize,
    color: [u8; 4],
) {
    for yy in y..(y + rect_height) {
        for xx in x..(x + rect_width) {
            let local_x = xx - x;
            let local_y = yy - y;
            let dx = if local_x < radius {
                radius - local_x
            } else if local_x >= rect_width - radius {
                local_x - (rect_width - radius - 1)
            } else {
                0
            };
            let dy = if local_y < radius {
                radius - local_y
            } else if local_y >= rect_height - radius {
                local_y - (rect_height - radius - 1)
            } else {
                0
            };

            if dx == 0 || dy == 0 || (dx * dx + dy * dy) as isize <= (radius * radius) as isize {
                set_pixel(rgba, width, xx, yy, color);
            }
        }
    }
}

fn draw_p(
    rgba: &mut [u8],
    width: usize,
    x: usize,
    y: usize,
    letter_width: usize,
    letter_height: usize,
    color: [u8; 4],
) {
    let stroke = 10usize;
    fill_rect(rgba, width, x, y, stroke, letter_height, color);
    fill_rect(rgba, width, x, y, letter_width, stroke, color);
    fill_rect(
        rgba,
        width,
        x,
        y + letter_height / 2 - stroke / 2,
        letter_width - 4,
        stroke,
        color,
    );
    fill_rect(
        rgba,
        width,
        x + letter_width - stroke,
        y + stroke,
        stroke,
        letter_height / 2 - stroke,
        color,
    );
}

fn draw_x(
    rgba: &mut [u8],
    width: usize,
    x: usize,
    y: usize,
    letter_width: usize,
    letter_height: usize,
    color: [u8; 4],
) {
    let thickness = 5isize;
    for yy in 0..letter_height {
        for xx in 0..letter_width {
            let dx1 =
                xx as isize - (yy as isize * (letter_width as isize - 1) / letter_height as isize);
            let dx2 = xx as isize
                - ((letter_width as isize - 1)
                    - (yy as isize * (letter_width as isize - 1) / letter_height as isize));
            if dx1.abs() <= thickness || dx2.abs() <= thickness {
                set_pixel(rgba, width, x + xx, y + yy, color);
            }
        }
    }
}

fn open_external_target(target: &str) -> Result<(), String> {
    let status = if cfg!(target_os = "macos") {
        Command::new("open")
            .arg(target)
            .status()
            .map_err(|error| format!("Failed to run open: {error}"))?
    } else if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "start", "", target])
            .status()
            .map_err(|error| format!("Failed to run start: {error}"))?
    } else {
        Command::new("xdg-open")
            .arg(target)
            .status()
            .map_err(|error| format!("Failed to run xdg-open: {error}"))?
    };

    if status.success() {
        Ok(())
    } else {
        Err("The OS open command did not succeed.".to_string())
    }
}

fn fetch_latest_release_info() -> Result<Option<AvailableUpdate>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|error| format!("Failed to build update client: {error}"))?;
    let value = fetch_release_json(&client)?;

    let tag_name = value["tag_name"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_string();
    if tag_name.is_empty() {
        return Err("Latest release metadata did not include a tag.".to_string());
    }

    let latest_version = normalize_version_label(&tag_name);
    if !is_version_newer(&latest_version, env!("CARGO_PKG_VERSION")) {
        return Ok(None);
    }

    let html_url = value["html_url"].as_str().unwrap_or_default().to_string();
    let published_at = value["published_at"]
        .as_str()
        .or_else(|| value["created_at"].as_str())
        .unwrap_or_default()
        .to_string();
    let body = value["body"].as_str().unwrap_or_default().to_string();
    let assets = value["assets"].as_array().cloned().unwrap_or_default();
    let Some(asset) = select_platform_asset(&assets) else {
        return Err("A matching download asset for this platform was not found.".to_string());
    };

    Ok(Some(AvailableUpdate {
        version: latest_version,
        tag_name,
        published_at,
        html_url,
        asset_name: asset["name"].as_str().unwrap_or_default().to_string(),
        asset_url: asset["browser_download_url"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        body,
    }))
}

fn fetch_release_json(client: &reqwest::blocking::Client) -> Result<serde_json::Value, String> {
    let latest_url = format!("https://api.github.com/repos/{UPDATE_REPOSITORY}/releases/latest");
    let latest_response = client
        .get(&latest_url)
        .header(reqwest::header::USER_AGENT, "ProjectX-UpdateChecker")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .map_err(|error| format!("Failed to contact GitHub Releases: {error}"))?;

    if latest_response.status().is_success() {
        let text = latest_response
            .text()
            .map_err(|error| format!("Failed to read latest release metadata: {error}"))?;
        return serde_json::from_str::<serde_json::Value>(&text)
            .map_err(|error| format!("Failed to parse latest release metadata: {error}"));
    }

    if latest_response.status() != reqwest::StatusCode::NOT_FOUND {
        return Err(format!(
            "GitHub Releases returned {}.",
            latest_response.status()
        ));
    }

    let releases_url = format!("https://api.github.com/repos/{UPDATE_REPOSITORY}/releases");
    let releases_response = client
        .get(&releases_url)
        .header(reqwest::header::USER_AGENT, "ProjectX-UpdateChecker")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .map_err(|error| format!("Failed to contact GitHub release list: {error}"))?;

    if !releases_response.status().is_success() {
        return Err(format!(
            "GitHub release list returned {}.",
            releases_response.status()
        ));
    }

    let text = releases_response
        .text()
        .map_err(|error| format!("Failed to read release list metadata: {error}"))?;
    let releases = serde_json::from_str::<Vec<serde_json::Value>>(&text)
        .map_err(|error| format!("Failed to parse release list metadata: {error}"))?;

    releases
        .into_iter()
        .find(|release| {
            !release["draft"].as_bool().unwrap_or(false)
                && !release["prerelease"].as_bool().unwrap_or(false)
        })
        .ok_or_else(|| {
            format!(
                "No published GitHub release was found. Open {} to create one.",
                releases_page_url()
            )
        })
}

fn releases_page_url() -> String {
    format!("https://github.com/{UPDATE_REPOSITORY}/releases")
}

fn select_platform_asset(assets: &[serde_json::Value]) -> Option<serde_json::Value> {
    let expected_platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };

    assets.iter().find_map(|asset| {
        let name = asset["name"].as_str()?.to_ascii_lowercase();
        if name.contains(expected_platform) && !name.ends_with(".sha256") {
            Some(asset.clone())
        } else {
            None
        }
    })
}

fn normalize_version_label(version: &str) -> String {
    version
        .trim_start_matches(|ch: char| !ch.is_ascii_digit())
        .to_string()
}

fn is_version_newer(candidate: &str, current: &str) -> bool {
    compare_versionish(candidate, current).is_gt()
}

fn compare_versionish(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts = parse_versionish_parts(left);
    let right_parts = parse_versionish_parts(right);
    let max_len = left_parts.len().max(right_parts.len());

    for index in 0..max_len {
        let left_part = *left_parts.get(index).unwrap_or(&0);
        let right_part = *right_parts.get(index).unwrap_or(&0);
        match left_part.cmp(&right_part) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    std::cmp::Ordering::Equal
}

fn parse_versionish_parts(value: &str) -> Vec<u64> {
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<u64>().ok())
        .collect()
}

fn percent_label(part: usize, total: usize) -> String {
    if total == 0 {
        "0%".to_string()
    } else {
        format!("{:.1}%", (part as f64 / total as f64) * 100.0)
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

    deduped.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.path.cmp(&right.path))
    });

    deduped
}

fn collect_scan_targets(
    roots: &[PathBuf],
    max_files: usize,
    origin: ScanOrigin,
) -> Vec<ScanTarget> {
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
                file_class: classify_protection_file(&path),
                priority: classify_protection_priority(&path, classify_protection_file(&path)),
                path,
                last_modified_epoch: metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0),
                size_bytes: metadata.len(),
                origin,
                grouped_change_count: 1,
                burst_window_seconds: 0,
                change_class: ProtectionChangeClass::Modified,
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

fn collect_protection_targets(watched: &WatchedPathConfig, max_files: usize) -> Vec<ScanTarget> {
    let root = PathBuf::from(&watched.path);
    let Ok(metadata) = fs::symlink_metadata(&root) else {
        return Vec::new();
    };
    if metadata.file_type().is_symlink() {
        return Vec::new();
    }

    if metadata.is_file() {
        return vec![ScanTarget {
            file_class: classify_protection_file(&root),
            priority: classify_protection_priority(&root, classify_protection_file(&root)),
            path: root,
            last_modified_epoch: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
            size_bytes: metadata.len(),
            origin: ScanOrigin::RealTimeProtection,
            grouped_change_count: 1,
            burst_window_seconds: 0,
            change_class: ProtectionChangeClass::Created,
        }];
    }

    if !metadata.is_dir() {
        return Vec::new();
    }

    if watched.recursive {
        return crate::r#static::collect_scan_inputs(&[root], max_files)
            .into_iter()
            .filter_map(|path| fs::metadata(&path).ok().map(|metadata| (path, metadata)))
            .filter(|(_, metadata)| metadata.is_file())
            .map(|(path, metadata)| ScanTarget {
                file_class: classify_protection_file(&path),
                priority: classify_protection_priority(&path, classify_protection_file(&path)),
                path,
                last_modified_epoch: metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0),
                size_bytes: metadata.len(),
                origin: ScanOrigin::RealTimeProtection,
                grouped_change_count: 1,
                burst_window_seconds: 0,
                change_class: ProtectionChangeClass::Created,
            })
            .collect();
    }

    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(max_files)
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = entry.metadata().ok()?;
            metadata.is_file().then_some(ScanTarget {
                file_class: classify_protection_file(&path),
                priority: classify_protection_priority(&path, classify_protection_file(&path)),
                path,
                last_modified_epoch: metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0),
                size_bytes: metadata.len(),
                origin: ScanOrigin::RealTimeProtection,
                grouped_change_count: 1,
                burst_window_seconds: 0,
                change_class: ProtectionChangeClass::Created,
            })
        })
        .collect()
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
        file_class: ProtectionFileClass::TempCache,
        priority: ProtectionPriority::High,
        path: snapshot,
        last_modified_epoch: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_else(now_epoch),
        size_bytes: metadata.len(),
        origin: ScanOrigin::DownloadMonitor,
        grouped_change_count: 1,
        burst_window_seconds: 0,
        change_class: ProtectionChangeClass::Modified,
    })
}

fn write_download_snapshot(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_string_lossy();
    let safe_name = sanitize_file_name(&file_name);
    let output_dir = crate::app_paths::download_monitor_dir();
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
    let inner_radius = radius * 0.42;
    let mut start_angle = -std::f32::consts::FRAC_PI_2;

    painter.circle_filled(center, radius, egui::Color32::from_rgb(20, 24, 29));

    for (_, value, color) in segments.iter() {
        let sweep = (*value as f32 / total) * std::f32::consts::TAU;
        let end_angle = start_angle + sweep.max(0.001).min(std::f32::consts::TAU);
        let steps = ((sweep / std::f32::consts::TAU) * 64.0).ceil() as usize + 4;
        let mut points = Vec::with_capacity(steps * 2 + 2);
        for step in 0..=steps {
            let t = step as f32 / steps as f32;
            let angle = start_angle + (end_angle - start_angle) * t;
            points.push(center + Vec2::angled(angle) * radius);
        }
        for step in (0..=steps).rev() {
            let t = step as f32 / steps as f32;
            let angle = start_angle + (end_angle - start_angle) * t;
            points.push(center + Vec2::angled(angle) * inner_radius);
        }
        painter.add(egui::Shape::convex_polygon(
            points,
            *color,
            egui::Stroke::NONE,
        ));
        start_angle = end_angle;
    }
    painter.circle_filled(
        center,
        inner_radius - 1.0,
        egui::Color32::from_rgb(23, 28, 34),
    );
    painter.circle_stroke(
        center,
        radius,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 52, 54)),
    );
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
    let history_path = history_path();
    let index_path = index_path();
    let timing_samples = fs::read_to_string(&history_path)
        .ok()
        .and_then(|text| serde_json::from_str::<PersistedHistory>(&text).ok())
        .map(|history| history.timing_samples)
        .unwrap_or_default();

    let mut records = fs::read_to_string(&index_path)
        .ok()
        .and_then(|text| serde_json::from_str::<PersistedIndex>(&text).ok())
        .map(|index| index.entries)
        .or_else(|| {
            fs::read_to_string(&history_path)
                .ok()
                .and_then(|text| serde_json::from_str::<PersistedHistory>(&text).ok())
                .map(|history| history.records)
        })
        .unwrap_or_default();
    trim_records(&mut records);

    PersistedHistory {
        records,
        timing_samples,
    }
}

pub(crate) fn load_gui_settings() -> SettingsState {
    fs::read_to_string(settings_path())
        .ok()
        .and_then(|text| serde_json::from_str::<PersistedGuiSettings>(&text).ok())
        .map(|persisted| persisted.settings)
        .unwrap_or_default()
}

pub(crate) fn save_gui_settings(settings: &SettingsState) {
    let payload = PersistedGuiSettings {
        settings: settings.clone(),
    };
    let Ok(text) = serde_json::to_string_pretty(&payload) else {
        return;
    };
    let settings_path = settings_path();
    if let Some(parent) = settings_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(settings_path, text);
}

fn load_protection_events() -> Vec<ProtectionEvent> {
    fs::read_to_string(protection_events_path())
        .ok()
        .and_then(|text| serde_json::from_str::<Vec<ProtectionEvent>>(&text).ok())
        .unwrap_or_default()
}

fn load_protection_backlog() -> VecDeque<ScanTarget> {
    load_protection_backlog_from(&protection_backlog_path())
}

fn load_protection_backlog_from(path: &Path) -> VecDeque<ScanTarget> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<VecDeque<ScanTarget>>(&text).ok())
        .unwrap_or_default()
}

fn save_protection_events(events: &[ProtectionEvent]) {
    let Ok(text) = serde_json::to_string_pretty(events) else {
        return;
    };
    let events_path = protection_events_path();
    if let Some(parent) = events_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(events_path, text);
}

fn save_protection_backlog(backlog: &VecDeque<ScanTarget>) {
    save_protection_backlog_to(&protection_backlog_path(), backlog);
}

fn save_protection_backlog_to(path: &Path, backlog: &VecDeque<ScanTarget>) {
    let Ok(text) = serde_json::to_string_pretty(backlog) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, text);
}

fn save_history(records: &[ScanRecord], timing_samples: &[TimingSample]) {
    let mut retained_records = records.to_vec();
    trim_records(&mut retained_records);
    remove_stale_report_files(records, &retained_records);

    let mut retained_samples = timing_samples.to_vec();
    trim_timing_samples(&mut retained_samples);
    let payload = PersistedHistory {
        records: retained_records.clone(),
        timing_samples: retained_samples,
    };
    let Ok(text) = serde_json::to_string_pretty(&payload) else {
        return;
    };

    let history_path = history_path();
    if let Some(parent) = history_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(history_path, text);
    save_index(&retained_records);
}

fn trim_records(records: &mut Vec<ScanRecord>) {
    if records.len() > SCAN_RECORD_LIMIT {
        let drain_count = records.len() - SCAN_RECORD_LIMIT;
        records.drain(0..drain_count);
    }
}

fn trim_timing_samples(samples: &mut Vec<TimingSample>) {
    if samples.len() > TIMING_SAMPLE_LIMIT {
        let drain_count = samples.len() - TIMING_SAMPLE_LIMIT;
        samples.drain(0..drain_count);
    }
}

fn trim_protection_events(events: &mut Vec<ProtectionEvent>) {
    if events.len() > PROTECTION_EVENT_LIMIT {
        let drain_count = events.len() - PROTECTION_EVENT_LIMIT;
        events.drain(0..drain_count);
    }
}

fn remove_stale_report_files(all_records: &[ScanRecord], retained_records: &[ScanRecord]) {
    let retained_report_paths = retained_records
        .iter()
        .filter_map(|record| record.report_path.as_deref())
        .collect::<HashSet<_>>();

    for report_path in all_records
        .iter()
        .filter_map(|record| record.report_path.as_deref())
    {
        if retained_report_paths.contains(report_path) {
            continue;
        }
        let path = Path::new(report_path);
        if path.is_file() {
            let _ = fs::remove_file(path);
        }
    }
}

fn save_index(records: &[ScanRecord]) {
    let index = PersistedIndex {
        entries: records.to_vec(),
    };
    let Ok(text) = serde_json::to_string_pretty(&index) else {
        return;
    };
    let index_path = index_path();
    if let Some(parent) = index_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(index_path, text);
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
