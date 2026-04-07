use eframe::egui;

use crate::gui::app::{home_dir, save_gui_settings};
use crate::gui::state::MyApp;

impl MyApp {
    pub fn render_settings(&mut self, ui: &mut egui::Ui) {
        let mut settings_changed = false;

        ui.heading("Scanner Settings");
        ui.label("Tune passive scan coverage, protection behavior, and privacy defaults.");
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Scope and performance").strong());
                    settings_changed |= ui
                        .checkbox(
                            &mut self.settings.include_entire_filesystem,
                            "Include entire filesystem for 'Scan all files' (can be very slow)",
                        )
                        .changed();
                    settings_changed |= ui
                        .checkbox(
                            &mut self.settings.check_cached_scans,
                            "Reuse prior results when file timestamps have not changed",
                        )
                        .changed();
                    ui.horizontal(|ui| {
                        ui.label("Max files per bulk scan");
                        settings_changed |= ui
                            .add(
                                egui::DragValue::new(&mut self.settings.max_files_per_bulk_scan)
                                    .speed(500.0),
                            )
                            .changed();
                    });
                    self.settings.max_files_per_bulk_scan =
                        self.settings.max_files_per_bulk_scan.clamp(1, 50_000);
                });

                ui.add_space(8.0 * self.ui_metrics.scale_factor);
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Passive analysis stages").strong());
                    ui.label("These toggles control local analysis only. The desktop product does not execute, detonate, or modify runtime environments.");
                    settings_changed |= ui.checkbox(&mut self.settings.enable_file_checks, "File profiling and metadata checks").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_string_extraction, "String extraction").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_normalization, "Text normalization").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_decode, "Decode attempts").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_script_parsing, "Script heuristic parsing").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_format_analysis, "Format-specific analysis").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_yara, "Local signature / rule matching").changed();
                    settings_changed |= ui
                        .checkbox(
                            &mut self.settings.enable_local_intelligence,
                            "Local reputation, trust, and provenance intelligence",
                        )
                        .changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_emulation, "Lightweight emulation").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_runtime_yara, "IOC enrichment from passive outputs").changed();
                    settings_changed |= ui.checkbox(&mut self.settings.enable_ml_scoring, "Local ML scoring").changed();
                });

                ui.add_space(8.0 * self.ui_metrics.scale_factor);
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Real-time protection").strong());
                    ui.label("Real-time protection watches selected files or folders and automatically queues passive scans when content changes.");
                    settings_changed |= ui
                        .checkbox(
                            &mut self.settings.enable_real_time_protection,
                            "Enable real-time protection",
                        )
                        .changed();
                    settings_changed |= ui
                        .checkbox(
                            &mut self.settings.enable_download_monitoring,
                            "Also snapshot active downloads during transfer",
                        )
                        .changed();
                    if self.settings.enable_download_monitoring {
                        ui.label("Active downloads are copied into quarantine snapshots for passive scanning without interrupting the download stream.");
                    }

                    ui.add_space(6.0 * self.ui_metrics.scale_factor);
                    ui.horizontal(|ui| {
                        ui.label("Watched path");
                        ui.add_sized(
                            [ui.available_width() * 0.55, 0.0],
                            egui::TextEdit::singleline(&mut self.protection_path_input)
                                .hint_text("/path/to/watch"),
                        );
                        if ui.button("Add path").clicked() {
                            let path = std::path::PathBuf::from(self.protection_path_input.trim());
                            if path.exists() {
                                self.add_watched_path(path, true);
                                self.protection_path_input.clear();
                            } else {
                                self.status_message = "That watched path does not exist.".to_string();
                            }
                        }
                        if ui.button("Add folder…").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.add_watched_path(path, true);
                            }
                        }
                        if ui.button("Add file…").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                self.add_watched_path(path, false);
                            }
                        }
                        if ui.button("Add Downloads").clicked() {
                            if let Some(downloads) = home_dir().map(|home| home.join("Downloads")) {
                                self.add_watched_path(downloads, true);
                            }
                        }
                    });

                    if self.settings.watched_paths.is_empty() {
                        ui.label("No watched paths configured yet.");
                    } else {
                        let mut remove_path = None;
                        for watched in &mut self.settings.watched_paths {
                            ui.horizontal_wrapped(|ui| {
                                ui.monospace(&watched.path);
                                settings_changed |= ui.checkbox(&mut watched.recursive, "Recursive").changed();
                                if ui.button("Remove").clicked() {
                                    remove_path = Some(watched.path.clone());
                                }
                            });
                        }
                        if let Some(path) = remove_path {
                            self.remove_watched_path(&path);
                            settings_changed = false;
                        }
                    }

                    if !self.protection_summary.active_status.is_empty() {
                        ui.add_space(4.0 * self.ui_metrics.scale_factor);
                        ui.label(&self.protection_summary.active_status);
                        ui.label(format!(
                            "Monitor: {} ({}) | queue health: {} | backlog {} | deferred {} | throttled {}",
                            self.protection_summary.monitor_mode,
                            self.protection_summary.monitor_state,
                            self.protection_summary.queue_health,
                            self.protection_summary.backlog_count,
                            self.protection_summary.deferred_event_count,
                            self.protection_summary.throttled_event_count
                        ));
                        if !self.protection_summary.queue_health_detail.is_empty() {
                            ui.label(&self.protection_summary.queue_health_detail);
                        }
                        ui.label(format!(
                            "Last event: {}",
                            self.protection_summary.last_event_label
                        ));
                    }
                });

                ui.add_space(8.0 * self.ui_metrics.scale_factor);
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Privacy and safety defaults").strong());
                    ui.label("External lookups are off by default. Execution, detonation, and runtime environment modification are not part of the GUI product flow.");
                    settings_changed |= ui
                        .checkbox(
                            &mut self.settings.enable_external_intelligence,
                            "Allow explicit external intelligence lookups",
                        )
                        .changed();
                    ui.label("External intelligence remains opt-in and is surfaced as a separate confidence input instead of silently overriding local analysis.");
                });

                ui.separator();
                ui.label(format!(
                    "Stored timing samples for ETA learning: {}",
                    self.timing_samples.len()
                ));
            });

        if settings_changed {
            save_gui_settings(&self.settings);
        }
    }
}
