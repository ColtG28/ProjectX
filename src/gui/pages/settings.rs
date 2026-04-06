use eframe::egui;

use crate::gui::state::MyApp;

impl MyApp {
    pub fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scanner Settings");
        ui.label("Tune passive scan coverage, performance, and privacy defaults.");
        ui.separator();

        ui.group(|ui| {
            ui.label(egui::RichText::new("Scope and performance").strong());
            ui.checkbox(
                &mut self.settings.include_entire_filesystem,
                "Include entire filesystem for 'Scan all files' (can be very slow)",
            );
            ui.checkbox(
                &mut self.settings.check_cached_scans,
                "Reuse prior results when file timestamps have not changed",
            );
            ui.horizontal(|ui| {
                ui.label("Max files per bulk scan");
                ui.add(
                    egui::DragValue::new(&mut self.settings.max_files_per_bulk_scan).speed(500.0),
                );
            });
            self.settings.max_files_per_bulk_scan =
                self.settings.max_files_per_bulk_scan.clamp(1, 50_000);
        });

        ui.add_space(8.0 * self.ui_metrics.scale_factor);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Passive analysis stages").strong());
            ui.label("These toggles control local analysis only. The desktop product no longer includes sandbox execution or runtime environment modification paths.");
            ui.checkbox(&mut self.settings.enable_file_checks, "File profiling and metadata checks");
            ui.checkbox(&mut self.settings.enable_string_extraction, "String extraction");
            ui.checkbox(&mut self.settings.enable_normalization, "Text normalization");
            ui.checkbox(&mut self.settings.enable_decode, "Decode attempts");
            ui.checkbox(&mut self.settings.enable_script_parsing, "Script heuristic parsing");
            ui.checkbox(&mut self.settings.enable_format_analysis, "Format-specific analysis");
            ui.checkbox(&mut self.settings.enable_yara, "Local signature / rule matching");
            ui.checkbox(&mut self.settings.enable_emulation, "Lightweight emulation");
            ui.checkbox(&mut self.settings.enable_runtime_yara, "IOC enrichment from passive outputs");
            ui.checkbox(&mut self.settings.enable_ml_scoring, "Local ML scoring");
        });

        ui.add_space(8.0 * self.ui_metrics.scale_factor);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Privacy and safety defaults").strong());
            ui.label("External lookups are off by default. Execution, detonation, and runtime environment modification are not part of the GUI product flow.");
            ui.label("Any future online enrichment should remain explicitly opt-in and clearly labeled.");
        });

        ui.add_space(8.0 * self.ui_metrics.scale_factor);
        ui.group(|ui| {
            ui.label(egui::RichText::new("Download monitoring").strong());
            ui.checkbox(
                &mut self.settings.enable_download_monitoring,
                "Watch Downloads and scan quarantined snapshots while files are still downloading",
            );
            if self.settings.enable_download_monitoring {
                ui.label("Snapshots are copied into quarantine for passive scanning without interrupting the download stream.");
            }
        });

        ui.separator();
        ui.label(format!(
            "Stored timing samples for ETA learning: {}",
            self.timing_samples.len()
        ));
    }
}
