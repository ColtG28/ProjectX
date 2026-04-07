use eframe::egui;
use egui::RichText;

use crate::gui::state::MyApp;

impl MyApp {
    pub fn render_about(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Scope");
        ui.separator();
        ui.group(|ui| {
            ui.label(RichText::new("What ProjectX does").strong());
            ui.label("ProjectX is a desktop defensive file scanner focused on passive analysis, triage visibility, quarantine management, and local-first reporting.");
            ui.label("It helps operators review file signals, rule hits, heuristic reasoning, and scan history from a single GUI workspace.");
        });
        ui.add_space(10.0 * self.ui_metrics.scale_factor);
        ui.group(|ui| {
            ui.label(RichText::new("What ProjectX does not do").strong());
            ui.label("ProjectX does not provide offensive capability, persistence, credential access, payload delivery, remote control, or destructive behavior.");
            ui.label("Repository support for sandbox execution and runtime environment modification has been removed from the desktop product direction.");
            ui.label("Real malware samples are not required for routine development or testing.");
        });
        ui.add_space(10.0 * self.ui_metrics.scale_factor);
        ui.group(|ui| {
            ui.label(RichText::new("Current desktop focus").strong());
            ui.label("1. Better visibility into scan data and verdicts");
            ui.label("2. Better workflow for local file triage");
            ui.label("3. Real-time protection with explainable automatic passive scans");
            ui.label(
                "4. Clear, professional quarantine and report handling with explicit confirmation",
            );
            ui.label("5. Privacy-conscious defaults with external lookups off by default");
        });
    }
}
