use eframe::egui;
use egui::{Color32, ProgressBar, TextEdit};

use crate::gui::app::{format_bytes, format_elapsed_ms, format_eta, overall_progress};
use crate::gui::components::{empty_state::empty_state, summary_chip::stat_chip};
use crate::gui::state::{FeedbackScope, MyApp};
use crate::gui::theme;

impl MyApp {
    pub fn render_scanner(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan Workspace");
        ui.label("Queue files or folders, watch passive analysis progress, and review the latest result without leaving the page.");
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                theme::card_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new("Scan configuration").strong());
                    let path_button_label = if self.is_loading() {
                        "Queue path"
                    } else {
                        "Scan path"
                    };
                    ui.label("File or folder path");
                    ui.add_sized(
                        [ui.available_width().min(ui.available_width()), 0.0],
                        TextEdit::singleline(&mut self.single_file_path)
                            .hint_text("/path/to/file-or-folder"),
                    );
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Browse file").clicked() {
                            self.pick_file_target();
                        }
                        if ui.button("Browse folder").clicked() {
                            self.pick_folder_target();
                        }
                        if ui.button(path_button_label).clicked() {
                            self.submit_manual_path();
                        }
                    });

                    ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
                    ui.horizontal_wrapped(|ui| {
                        let common_label = if self.is_loading() {
                            "Queue common folders"
                        } else {
                            "Scan common folders"
                        };
                        if ui.button(common_label).clicked() {
                            let mut roots = Vec::new();
                            if let Some(home) = crate::gui::app::home_dir() {
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
                            self.queue_scan_all_confirmation();
                        }
                    });

                    let scope_copy = if self.settings.include_entire_filesystem {
                        "all mounted files visible from /"
                    } else {
                        "your home folder"
                    };
                    ui.small(format!(
                        "Scan all files will walk {}. Use it for full sweeps, not quick spot checks.",
                        scope_copy
                    ));
                });

                ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
                self.render_feedback_banner(ui, FeedbackScope::Scan);
                self.render_feedback_banner(ui, FeedbackScope::Protection);

                ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
                theme::card_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new("Real-time protection").strong());
                    ui.horizontal_wrapped(|ui| {
                        stat_chip(
                            ui,
                            "Status",
                            if self.protection_summary.enabled {
                                self.protection_summary.monitor_state.clone()
                            } else {
                                "Disabled".to_string()
                            },
                            if self.protection_summary.enabled {
                                Color32::from_rgb(127, 191, 127)
                            } else {
                                Color32::from_rgb(170, 170, 180)
                            },
                        );
                        stat_chip(
                            ui,
                            "Watched paths",
                            self.protection_summary.watched_path_count.to_string(),
                            Color32::from_rgb(176, 221, 255),
                        );
                        stat_chip(
                            ui,
                            "Recent events",
                            self.protection_summary.recent_event_count.to_string(),
                            Color32::from_rgb(132, 170, 214),
                        );
                        stat_chip(
                            ui,
                            "Grouped queue",
                            self.protection_summary.queued_event_count.to_string(),
                            Color32::from_rgb(127, 191, 127),
                        );
                        stat_chip(
                            ui,
                            "Backlog",
                            self.protection_summary.backlog_count.to_string(),
                            Color32::from_rgb(224, 185, 105),
                        );
                        stat_chip(
                            ui,
                            "Throttled",
                            self.protection_summary.throttled_event_count.to_string(),
                            Color32::from_rgb(224, 185, 105),
                        );
                        stat_chip(
                            ui,
                            "Health",
                            self.protection_summary.queue_health.clone(),
                            Color32::from_rgb(176, 221, 255),
                        );
                        stat_chip(
                            ui,
                            "Monitor",
                            self.protection_summary.monitor_mode.clone(),
                            Color32::from_rgb(132, 170, 214),
                        );
                    });
                    if !self.protection_summary.active_status.is_empty() {
                        ui.label(&self.protection_summary.active_status);
                    } else {
                        ui.label("Automatic protection scans will appear here when watched files change.");
                    }
                    if !self.protection_summary.queue_health_detail.is_empty() {
                        ui.label(format!(
                            "Queue detail: {}",
                            self.protection_summary.queue_health_detail
                        ));
                    }
                    ui.label(format!("Last event: {}", self.protection_summary.last_event_label));
                    if self.protection_summary.backlog_count > 0 {
                        ui.label(format!(
                            "Deferred protection backlog: {} item(s) waiting for queue capacity.",
                            self.protection_summary.backlog_count
                        ));
                    }
                    if !self.settings.watched_paths.is_empty() {
                        ui.label("Watched locations");
                        for watched in self.settings.watched_paths.iter().take(4) {
                            ui.horizontal_wrapped(|ui| {
                                ui.monospace(&watched.path);
                                ui.label(if watched.recursive {
                                    "Recursive"
                                } else {
                                    "Top level only"
                                });
                            });
                        }
                    }
                    if !self.protection_events.is_empty() {
                        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
                        ui.label("Recent protection events");
                        for event in self.protection_events.iter().rev().take(5) {
                            theme::subtle_frame().show(ui, |ui| {
                                ui.label(format!(
                                    "{} | {} | {} | {} | {}",
                                    event.kind,
                                    crate::gui::app::format_timestamp_compact(event.timestamp_epoch),
                                    event.workflow_source,
                                    event.change_class.label(),
                                    event.file_class.label()
                                ));
                                ui.monospace(&event.path);
                                if event.grouped_change_count > 1 || event.burst_window_seconds > 0 {
                                    ui.label(format!(
                                        "Grouped {} change(s) across {}s | priority {}",
                                        event.grouped_change_count,
                                        event.burst_window_seconds,
                                        event.priority.label()
                                    ));
                                }
                                ui.label(&event.note);
                            });
                        }
                    }
                });

                ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
                let snapshot = self.job.lock().map(|job| job.clone()).unwrap_or_default();
                theme::card_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new("Live job status").strong());
                    ui.horizontal_wrapped(|ui| {
                stat_chip(
                    ui,
                    "Queued",
                    snapshot.queued_files.to_string(),
                    Color32::from_rgb(176, 221, 255),
                );
                stat_chip(
                    ui,
                    "Clean",
                    snapshot.good.to_string(),
                    Color32::from_rgb(127, 191, 127),
                );
                stat_chip(
                    ui,
                    "Malicious",
                    snapshot.malicious.to_string(),
                    Color32::from_rgb(216, 100, 100),
                );
                stat_chip(
                    ui,
                    "Suspicious",
                    snapshot.unsure.to_string(),
                    Color32::from_rgb(224, 185, 105),
                );
                stat_chip(
                    ui,
                    "Errors",
                    snapshot.errors.to_string(),
                    Color32::from_rgb(170, 170, 180),
                );
                    });

                    let progress_width = ui.available_width().min(560.0).max(220.0);
                    let overall = overall_progress(&snapshot);
                    ui.label(format!(
                        "Overall progress: {}/{} files | queued: {}",
                        snapshot.processed, snapshot.total, snapshot.queued_files
                    ));
                    ui.add_sized(
                        [progress_width, 0.0],
                        ProgressBar::new(overall).show_percentage(),
                    );

                    if snapshot.total_bytes > 0 {
                        let completed_bytes = snapshot.processed_bytes
                            + ((snapshot.current_file_size as f32
                                * snapshot.current_file_progress.clamp(0.0, 1.0))
                                as u64);
                        ui.label(format!(
                            "Scanned data: {} / {} | queued data: {}",
                            format_bytes(completed_bytes),
                            format_bytes(snapshot.total_bytes),
                            format_bytes(snapshot.queued_bytes)
                        ));
                    }

                    ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
                    ui.label("Current file progress");
                    ui.add_sized(
                        [progress_width, 0.0],
                        ProgressBar::new(snapshot.current_file_progress.clamp(0.0, 1.0))
                            .show_percentage(),
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
                        "Stage: {}",
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
                    if !snapshot.summary.is_empty() {
                        ui.label(format!("Last completed batch: {}", snapshot.summary));
                    }
                });

                ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
                theme::card_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new("Most recent scan result").strong());
                    let indices = self.filtered_record_indices(1, "");
                    if indices.is_empty() {
                        empty_state(
                            ui,
                            self.ui_metrics.scale_factor,
                            "No completed scans yet",
                            "Use Browse file, Browse folder, or Scan common folders to start the first scan.",
                        );
                    } else {
                        self.render_record_list(ui, &indices, false);
                    }
                });

                ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
                self.render_notification_center(
                    ui,
                    "Recent scanner activity",
                    &[FeedbackScope::Scan, FeedbackScope::Protection, FeedbackScope::Updater],
                    6,
                );
                ui.add_space(14.0 * self.ui_metrics.scale_factor);
            });
    }
}
