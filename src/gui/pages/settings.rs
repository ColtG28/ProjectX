use eframe::egui;

use crate::gui::app::{home_dir, save_gui_settings};
use crate::gui::state::{FeedbackScope, FeedbackSeverity, MyApp, SettingsPanel};
use crate::gui::theme;

impl MyApp {
    pub fn render_settings(&mut self, ui: &mut egui::Ui) {
        let mut settings_changed = false;

        ui.heading("Scanner Settings");
        ui.separator();
        self.render_feedback_banner(ui, FeedbackScope::Settings);
        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));

        render_settings_panel_picker(ui, &mut self.settings_panel);
        ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| match self.settings_panel {
                SettingsPanel::General => {
                    self.render_settings_general(ui, &mut settings_changed);
                }
                SettingsPanel::Protection => {
                    self.render_settings_protection(ui, &mut settings_changed);
                }
                SettingsPanel::Advanced => {
                    self.render_settings_advanced(ui, &mut settings_changed);
                }
            });

        if settings_changed {
            save_gui_settings(&self.settings);
        }
    }

    fn render_settings_general(&mut self, ui: &mut egui::Ui, settings_changed: &mut bool) {
        settings_section(
            ui,
            "General / Scope",
            "Choose how much ProjectX should scan and how aggressively it reuses previous results.",
            self.ui_metrics.scale_factor,
        );
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.include_entire_filesystem,
                "Let 'Scan all files' cover the entire filesystem",
            )
            .changed();
        ui.small("When this is off, the wide scan action only covers your home folder.");
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.check_cached_scans,
                "Reuse prior results when file timestamps have not changed",
            )
            .changed();
        ui.horizontal(|ui| {
            ui.label("Max files per bulk scan");
            *settings_changed |= ui
                .add(egui::DragValue::new(&mut self.settings.max_files_per_bulk_scan).speed(500.0))
                .changed();
        });
        self.settings.max_files_per_bulk_scan =
            self.settings.max_files_per_bulk_scan.clamp(1, 50_000);

        ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
        theme::card_frame().show(ui, |ui| {
            theme::card_title(ui, "Quick status", self.ui_metrics.scale_factor);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = theme::badge_spacing(self.ui_metrics.scale_factor);
                settings_pill(
                    ui,
                    "Bulk cap",
                    &self.settings.max_files_per_bulk_scan.to_string(),
                );
                settings_pill(
                    ui,
                    "Reuse cached",
                    if self.settings.check_cached_scans {
                        "On"
                    } else {
                        "Off"
                    },
                );
                settings_pill(
                    ui,
                    "Wide scan target",
                    if self.settings.include_entire_filesystem {
                        "Filesystem"
                    } else {
                        "Home folder"
                    },
                );
            });
        });
    }

    fn render_settings_protection(&mut self, ui: &mut egui::Ui, settings_changed: &mut bool) {
        settings_section(
            ui,
            "Protection",
            "Watch selected locations and queue passive scans when files change.",
            self.ui_metrics.scale_factor,
        );
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_real_time_protection,
                "Enable real-time protection",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_download_monitoring,
                "Also snapshot active downloads during transfer",
            )
            .changed();
        if self.settings.enable_download_monitoring {
            ui.small("Download snapshots are copied for passive scanning without interrupting the original transfer.");
        }

        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
        ui.horizontal_wrapped(|ui| {
            settings_pill(
                ui,
                "Monitor",
                &format!(
                    "{} ({})",
                    self.protection_summary.monitor_mode, self.protection_summary.monitor_state
                ),
            );
            settings_pill(ui, "Queue health", &self.protection_summary.queue_health);
            settings_pill(
                ui,
                "Watched paths",
                &self.settings.watched_paths.len().to_string(),
            );
            settings_pill(
                ui,
                "Backlog",
                &self.protection_summary.backlog_count.to_string(),
            );
        });

        ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
        theme::card_frame().show(ui, |ui| {
            theme::card_title(ui, "Watched locations", self.ui_metrics.scale_factor);
            ui.horizontal(|ui| {
                ui.label("Watched path");
                ui.add_sized(
                    [ui.available_width() * 0.5, 0.0],
                    egui::TextEdit::singleline(&mut self.protection_path_input)
                        .hint_text("/path/to/watch"),
                );
                if ui.button("Add path").clicked() {
                    let path = std::path::PathBuf::from(self.protection_path_input.trim());
                    if path.exists() {
                        self.add_watched_path(path, true);
                        self.protection_path_input.clear();
                    } else {
                        self.set_feedback(
                            FeedbackScope::Settings,
                            FeedbackSeverity::Warning,
                            "That watched path does not exist.",
                        );
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
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
                ui.small("No watched paths configured yet.");
            } else {
                let mut remove_path = None;
                theme::subtle_frame().show(ui, |ui| {
                    for watched in &mut self.settings.watched_paths {
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(&watched.path);
                            *settings_changed |=
                                ui.checkbox(&mut watched.recursive, "Recursive").changed();
                            if ui.button("Remove").clicked() {
                                remove_path = Some(watched.path.clone());
                            }
                        });
                    }
                });
                if let Some(path) = remove_path {
                    self.remove_watched_path(&path);
                    *settings_changed = false;
                }
            }
        });

        if !self.protection_summary.active_status.is_empty() {
            ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
            ui.small(&self.protection_summary.active_status);
        }
        self.render_notification_center(
            ui,
            "Recent protection activity",
            &[FeedbackScope::Protection, FeedbackScope::Settings],
            6,
        );
    }

    fn render_settings_advanced(&mut self, ui: &mut egui::Ui, settings_changed: &mut bool) {
        settings_section(
            ui,
            "Advanced",
            "These toggles affect local passive analysis only. ProjectX remains passive-first from the GUI.",
            self.ui_metrics.scale_factor,
        );
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_file_checks,
                "File profiling and metadata checks",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_string_extraction,
                "String extraction",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_normalization,
                "Text normalization",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(&mut self.settings.enable_decode, "Decode attempts")
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_script_parsing,
                "Script heuristic parsing",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_format_analysis,
                "Format-specific analysis",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_yara,
                "Local signature / rule matching",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_local_intelligence,
                "Local reputation, trust, and provenance intelligence",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(&mut self.settings.enable_emulation, "Lightweight emulation")
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_runtime_yara,
                "IOC enrichment from passive outputs",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(&mut self.settings.enable_ml_scoring, "Local ML scoring")
            .changed();

        ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
        theme::card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new("Privacy and safety defaults").strong());
            *settings_changed |= ui
                .checkbox(
                    &mut self.settings.enable_external_intelligence,
                    "Allow explicit external intelligence lookups",
                )
                .changed();
            ui.small("External intelligence remains opt-in and is surfaced as a separate confidence input instead of silently overriding local analysis.");
            ui.small(format!(
                "Stored timing samples for ETA learning: {}",
                self.timing_samples.len()
            ));
        });
    }
}

fn render_settings_panel_picker(ui: &mut egui::Ui, active_panel: &mut SettingsPanel) {
    ui.horizontal_wrapped(|ui| {
        for panel in [
            SettingsPanel::General,
            SettingsPanel::Protection,
            SettingsPanel::Advanced,
        ] {
            let selected = *active_panel == panel;
            let button = egui::Button::new(panel.label()).fill(if selected {
                egui::Color32::from_rgb(52, 68, 88)
            } else {
                theme::CARD_FILL
            });
            if ui.add(button).clicked() {
                *active_panel = panel;
            }
        }
    });
}

fn settings_section(ui: &mut egui::Ui, title: &str, body: &str, scale: f32) {
    theme::card_frame().show(ui, |ui| {
        theme::card_title(ui, title, scale);
        ui.small(body);
    });
    ui.add_space(theme::item_gap(scale));
}

fn settings_pill(ui: &mut egui::Ui, label: &str, value: &str) {
    theme::subtle_frame().show(ui, |ui| {
        ui.spacing_mut().item_spacing =
            egui::vec2(theme::card_row_gap(1.0), theme::card_row_gap(1.0));
        ui.horizontal(|ui| {
            ui.small(egui::RichText::new(label).strong());
            ui.label(value);
        });
    });
}
