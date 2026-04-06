use eframe::egui;
use egui::{Color32, RichText, Stroke};

pub fn stat_chip(ui: &mut egui::Ui, label: &str, value: impl Into<String>, color: Color32) {
    egui::Frame::group(ui.style())
        .fill(Color32::from_rgb(31, 37, 44))
        .stroke(Stroke::new(1.0, Color32::from_rgb(57, 66, 76)))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).color(Color32::from_rgb(190, 196, 201)));
                ui.label(RichText::new(value.into()).strong().color(color).size(21.0));
            });
        });
}
