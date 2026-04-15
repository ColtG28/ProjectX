use eframe::egui;
use egui::RichText;

use crate::gui::state::MyApp;

impl MyApp {
    pub fn render_about(&mut self, ui: &mut egui::Ui) {
        ui.heading("About ProjectX");
        ui.separator();
        ui.group(|ui| {
            ui.label("ProjectX is a streamlined, high-performance file scanning solution designed for the modern multi-platform environment. Built with versatility at its core, it provides a unified experience whether you are auditing directories on Linux, managing assets on macOS, or securing files on Windows.");
            ui.label("It helps operators review file signals, rule hits, heuristic reasoning, and scan history from a single GUI workspace.");
            ui.label("ProjectX is built on Rust, leveraging its safety and performance features to deliver a robust and efficient scanning experience. The GUI is developed using eframe, ensuring a responsive and user-friendly interface across all supported platforms.");
        });
    }
}
