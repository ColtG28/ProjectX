use eframe::egui;

use crate::gui::state::MyApp;
use crate::gui::theme;

impl MyApp {
    pub fn render_about(&self, ui: &mut egui::Ui) {
        theme::card_frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            theme::card_title(ui, "System overview", self.ui_metrics.scale_factor);
            ui.label("ProjectX is a lightweight, high-performance file scanner built for macOS, Windows, and Linux.");
            ui.add_space(theme::card_row_gap(self.ui_metrics.scale_factor));
            ui.label(format!(
                "Protection state: {}",
                self.protection_summary.active_status
            ));
            ui.label(format!(
                "Watched paths configured: {}",
                self.settings.watched_paths.len()
            ));
            ui.add_space(theme::card_row_gap(self.ui_metrics.scale_factor));
            ui.small("ProjectX focuses on clear passive analysis, safe quarantine handling, and explainable review workflows.");
        });
    }
}
