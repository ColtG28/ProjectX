use std::path::PathBuf;

use eframe::egui;
use egui::{Color32, ProgressBar, TextEdit};

use crate::gui::app::{format_bytes, format_elapsed_ms, format_eta, overall_progress};
use crate::gui::components::{empty_state::empty_state, summary_chip::stat_chip};
use crate::gui::state::MyApp;

impl MyApp {
    pub fn render_scanner(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan Workspace");
        ui.label("Queue files or folders, watch passive analysis progress, and review the latest result without leaving the page.");
        ui.separator();

        ui.group(|ui| {
            ui.label(egui::RichText::new("Scan configuration").strong());
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
                });
            } else {
                ui.horizontal(|ui| {
                    ui.label("Path");
                    ui.add_sized(
                        [ui.available_width() * 0.5, 0.0],
                        TextEdit::singleline(&mut self.single_file_path)
                            .hint_text("/path/to/file-or-folder"),
                    );
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
            }

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
                    let roots = if self.settings.include_entire_filesystem {
                        vec![PathBuf::from("/")]
                    } else {
                        vec![crate::gui::app::home_dir().unwrap_or_else(|| PathBuf::from("/"))]
                    };
                    self.start_scan_from_roots(roots);
                }
            });
        });

        if !self.status_message.is_empty() {
            ui.add_space(8.0);
            ui.label(&self.status_message);
        }

        ui.separator();
        let snapshot = self.job.lock().map(|job| job.clone()).unwrap_or_default();
        ui.group(|ui| {
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

            let progress_width = if self.ui_metrics.compact {
                (ui.available_width() - 12.0).max(210.0)
            } else {
                ui.available_width().min(560.0)
            };
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

            ui.add_space(8.0);
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

        ui.separator();
        ui.heading("Most Recent Scan Result");
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
        ui.add_space(14.0 * self.ui_metrics.scale_factor);
    }
}
