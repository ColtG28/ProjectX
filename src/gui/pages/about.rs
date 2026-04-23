use eframe::egui;

use crate::gui::app::format_timestamp_with_relative;
use crate::gui::components::summary_chip::stat_chip;
use crate::gui::state::MyApp;
use crate::gui::theme;

impl MyApp {
    pub fn render_about(&mut self, ui: &mut egui::Ui) {
        let update_snapshot = self
            .update_state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default();
        let last_scan = self.latest_scan_epoch();

        ui.heading("About ProjectX");
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = theme::badge_spacing(self.ui_metrics.scale_factor);
            stat_chip(
                ui,
                "Version",
                update_snapshot.current_version.clone(),
                egui::Color32::from_rgb(176, 221, 255),
            );
            stat_chip(
                ui,
                "Updates",
                update_snapshot.status_kind.user_label(),
                egui::Color32::from_rgb(224, 185, 105),
            );
            stat_chip(
                ui,
                "Protection",
                self.protection_status_label(),
                egui::Color32::from_rgb(132, 170, 214),
            );
            stat_chip(
                ui,
                "Watched paths",
                self.settings.watched_paths.len().to_string(),
                egui::Color32::from_rgb(104, 181, 124),
            );
            if let Some(version) = update_snapshot.downloaded_version.as_deref() {
                stat_chip(
                    ui,
                    "Downloaded",
                    version,
                    egui::Color32::from_rgb(224, 185, 105),
                );
            }
        });
        ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));

        self.render_about_summary(ui, &update_snapshot, last_scan);
    }

    fn render_about_summary(
        &self,
        ui: &mut egui::Ui,
        update_snapshot: &crate::gui::state::UpdateCheckState,
        last_scan: Option<u64>,
    ) {
        theme::card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            theme::card_title(ui, "System overview", self.ui_metrics.scale_factor);
            ui.label("ProjectX is a lightweight, high-performance file scanner built for macOS, Windows, and Linux.");
            ui.add_space(theme::card_row_gap(self.ui_metrics.scale_factor));
            ui.label(format!("Update source status: {}", update_snapshot.status));
            ui.label(format!(
                "Protection state: {}",
                self.protection_summary.active_status
            ));
            ui.label(format!(
                "Last scan: {}",
                last_scan
                    .map(format_timestamp_with_relative)
                    .unwrap_or_else(|| "No completed scan recorded yet.".to_string())
            ));
            ui.label(format!(
                "Watched paths configured: {}",
                self.settings.watched_paths.len()
            ));
            if !update_snapshot.download_status.is_empty() {
                ui.label(format!("Download state: {}", update_snapshot.download_status));
            }
            if !update_snapshot.install_status.is_empty() {
                ui.label(format!("Install state: {}", update_snapshot.install_status));
            }
            ui.add_space(theme::card_row_gap(self.ui_metrics.scale_factor));
            ui.small("ProjectX focuses on clear passive analysis, safe quarantine handling, and explainable review workflows.");
        });
    }
}
