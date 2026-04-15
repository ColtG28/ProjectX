use eframe::egui;

use crate::gui::app::{format_timestamp_with_relative, home_dir, save_gui_settings};
use crate::gui::state::{FeedbackScope, FeedbackSeverity, MyApp, SettingsPanel};
use crate::gui::theme;
use crate::update::UpdateStatusKind;

impl MyApp {
    pub fn render_settings(&mut self, ui: &mut egui::Ui) {
        let mut settings_changed = false;

        ui.heading("Scanner Settings");
        ui.label("Tune scan scope, protection, and update behavior without leaving the current workflow.");
        ui.separator();
        self.render_feedback_banner(ui, FeedbackScope::Settings);
        self.render_feedback_banner(ui, FeedbackScope::Updater);
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
                SettingsPanel::Updates => {
                    self.render_settings_updates(ui, &mut settings_changed);
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
            ui.label(egui::RichText::new("Quick status").strong());
            ui.horizontal_wrapped(|ui| {
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
            ui.label(egui::RichText::new("Watched locations").strong());
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

    fn render_settings_updates(&mut self, ui: &mut egui::Ui, settings_changed: &mut bool) {
        settings_section(
            ui,
            "Updates",
            "ProjectX checks GitHub Releases safely. It can optionally pre-download updates, but it never auto-installs them.",
        );
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_automatic_updates,
                "Enable automatic update checks",
            )
            .changed();
        *settings_changed |= ui
            .checkbox(
                &mut self.settings.enable_automatic_update_downloads,
                "Automatically download updates after a successful background check (do not install)",
            )
            .changed();

        let update_snapshot = self
            .update_state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default();
        let status_color = update_status_color(update_snapshot.status_kind);

        theme::card_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                settings_pill(ui, "Current", &update_snapshot.current_version);
                settings_pill(
                    ui,
                    "Latest",
                    update_snapshot
                        .latest_release
                        .as_ref()
                        .map(|release| release.version.as_str())
                        .unwrap_or("Unknown"),
                );
                settings_pill(ui, "Source", &update_snapshot.repo_label);
            });
            ui.add_space(4.0);
            ui.colored_label(
                status_color,
                egui::RichText::new(update_snapshot.status_kind.user_label()).strong(),
            );
            ui.small(update_snapshot.status_kind.user_summary());
            if !update_snapshot.status.is_empty() {
                ui.label(&update_snapshot.status);
            }
            if update_snapshot.last_checked_epoch > 0 {
                ui.small(format!(
                    "Last checked: {}",
                    format_timestamp_with_relative(update_snapshot.last_checked_epoch)
                ));
            }
            if update_snapshot.last_successful_check_epoch > 0 {
                ui.small(format!(
                    "Last successful lookup: {}",
                    format_timestamp_with_relative(update_snapshot.last_successful_check_epoch)
                ));
            }
            if let Some(error) = &update_snapshot.last_error {
                ui.colored_label(
                    egui::Color32::from_rgb(198, 114, 114),
                    format!("Last check detail: {error}"),
                );
            }
            if update_snapshot.last_automatic_check_epoch > 0 {
                ui.small(format!(
                    "Last automatic check: {}",
                    format_timestamp_with_relative(update_snapshot.last_automatic_check_epoch)
                ));
            }
            if update_snapshot.next_scheduled_check_epoch > 0 {
                ui.small(format!(
                    "Next scheduled check: {}",
                    format_timestamp_with_relative(update_snapshot.next_scheduled_check_epoch)
                ));
            }
        });

        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(!update_snapshot.checking, egui::Button::new("Check now"))
                .clicked()
            {
                self.start_update_check(true);
            }

            if ui
                .add_enabled(
                    update_snapshot.available_update.is_some(),
                    egui::Button::new("Download latest update"),
                )
                .clicked()
            {
                self.open_available_update();
            }

            if ui.button("Open release page").clicked() {
                self.open_release_notes();
            }
            if ui
                .add_enabled(
                    update_snapshot.download_path.is_some(),
                    egui::Button::new("Reveal downloaded update"),
                )
                .clicked()
            {
                self.open_downloaded_update_folder();
            }
        });

        theme::subtle_frame().show(ui, |ui| {
            ui.label(egui::RichText::new("Download state").strong());
            ui.small(&update_snapshot.download_status);
            if let Some(progress) = update_snapshot.download_progress_fraction {
                ui.add(
                    egui::ProgressBar::new(progress)
                        .desired_width(ui.available_width().min(320.0))
                        .show_percentage(),
                );
            }
            if let Some(path) = update_snapshot.download_path.as_deref() {
                ui.small(format!("Downloaded file: {path}"));
            }
            if let Some(version) = update_snapshot.downloaded_version.as_deref() {
                ui.small(format!("Downloaded version: {version}"));
            }
            if update_snapshot.last_download_epoch > 0 {
                ui.small(format!(
                    "Last download update: {}",
                    format_timestamp_with_relative(update_snapshot.last_download_epoch)
                ));
            }
        });

        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
        let install_plan = crate::gui::app::build_guided_install_plan(
            update_snapshot.latest_release.as_ref(),
            update_snapshot.download_path.as_deref(),
            update_snapshot.verification_status.as_deref(),
        );
        theme::subtle_frame().show(ui, |ui| {
            ui.label(egui::RichText::new("Install state").strong());
            ui.small(&update_snapshot.install_status);
            if !update_snapshot.install_guidance.is_empty() {
                ui.small(&update_snapshot.install_guidance);
            } else {
                ui.small(&install_plan.instructions);
            }
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        update_snapshot.install_ready,
                        egui::Button::new(install_plan.action_label),
                    )
                    .clicked()
                {
                    self.install_downloaded_update();
                }
                if update_snapshot.restart_required_after_install {
                    ui.small("Restart ProjectX after the installer or replacement flow completes.");
                }
            });
            if update_snapshot.last_install_attempt_epoch > 0 {
                ui.small(format!(
                    "Last install attempt: {}",
                    format_timestamp_with_relative(update_snapshot.last_install_attempt_epoch)
                ));
            }
        });

        if let Some(update) = &update_snapshot.latest_release {
            ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));
            theme::card_frame().show(ui, |ui| {
                ui.label(egui::RichText::new("Package verification").strong());
                ui.small(if update.expected_sha256.is_some() {
                    "A matching SHA-256 checksum is available for this release."
                } else {
                    "This release does not expose a matching SHA-256 checksum asset, so in-app verification is unavailable."
                });
                ui.add_space(4.0);
                ui.label(format!("Package: {}", update.asset_name));
                if !update.checksum_status.is_empty() {
                    ui.label(format!("Checksum status: {}", update.checksum_status));
                }
                if let Some(hash) = update.expected_sha256.as_deref() {
                    let preview_len = hash.len().min(16);
                    ui.small(format!("Expected SHA-256: {}...", &hash[..preview_len]));
                }
                if ui
                    .add_enabled(
                        update.expected_sha256.is_some(),
                        egui::Button::new("Verify downloaded update"),
                    )
                    .clicked()
                {
                    self.verify_downloaded_update();
                }
                if let Some(message) = update_snapshot.verification_status.as_deref() {
                    ui.colored_label(verification_color(Some(message)), message);
                }
            });
        }

        self.render_notification_center(
            ui,
            "Recent updater activity",
            &[FeedbackScope::Updater],
            8,
        );
    }

    fn render_settings_advanced(&mut self, ui: &mut egui::Ui, settings_changed: &mut bool) {
        settings_section(
            ui,
            "Advanced",
            "These toggles affect local passive analysis only. ProjectX remains passive-first from the GUI.",
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
            SettingsPanel::Updates,
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

fn settings_section(ui: &mut egui::Ui, title: &str, body: &str) {
    theme::card_frame().show(ui, |ui| {
        ui.label(egui::RichText::new(title).strong());
        ui.small(body);
    });
    ui.add_space(theme::item_gap(1.0));
}

fn settings_pill(ui: &mut egui::Ui, label: &str, value: &str) {
    theme::subtle_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.small(egui::RichText::new(label).strong());
            ui.label(value);
        });
    });
}

fn update_status_color(kind: UpdateStatusKind) -> egui::Color32 {
    match kind {
        UpdateStatusKind::UpToDate => egui::Color32::from_rgb(104, 181, 124),
        UpdateStatusKind::UpdateAvailable => egui::Color32::from_rgb(224, 185, 105),
        UpdateStatusKind::Unknown => egui::Color32::from_rgb(176, 221, 255),
        UpdateStatusKind::Error => egui::Color32::from_rgb(198, 114, 114),
        UpdateStatusKind::Offline => egui::Color32::from_rgb(170, 170, 180),
        UpdateStatusKind::RateLimited => egui::Color32::from_rgb(214, 160, 95),
    }
}

fn verification_color(message: Option<&str>) -> egui::Color32 {
    let Some(message) = message else {
        return egui::Color32::from_rgb(176, 221, 255);
    };
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("verified successfully") {
        egui::Color32::from_rgb(104, 181, 124)
    } else if lowered.contains("failed") || lowered.contains("malformed") {
        egui::Color32::from_rgb(198, 114, 114)
    } else {
        egui::Color32::from_rgb(224, 185, 105)
    }
}
