use eframe::egui;
use egui::RichText;

pub fn empty_state(ui: &mut egui::Ui, scale: f32, title: &str, message: &str) {
    ui.group(|ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(10.0 * scale);
            ui.label(RichText::new(title).strong());
            ui.add_space(4.0 * scale);
            ui.label(message);
            ui.add_space(6.0 * scale);
        });
    });
}
