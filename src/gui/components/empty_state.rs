use eframe::egui;
use egui::RichText;

use crate::gui::theme;

pub fn empty_state(ui: &mut egui::Ui, scale: f32, title: &str, message: &str) {
    theme::card_frame().show(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(theme::card_section_gap(scale));
            ui.label(RichText::new(title).strong());
            ui.add_space(theme::card_row_gap(scale));
            ui.label(message);
            ui.add_space(theme::card_header_gap(scale));
        });
    });
}
