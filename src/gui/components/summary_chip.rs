use eframe::egui;
use egui::{Color32, RichText};

use crate::gui::theme;

pub fn stat_chip(ui: &mut egui::Ui, label: &str, value: impl Into<String>, color: Color32) {
    theme::card_frame().show(ui, |ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = theme::card_row_gap(1.0);
            ui.label(RichText::new(label).color(Color32::from_rgb(190, 196, 201)));
            ui.label(RichText::new(value.into()).strong().color(color).size(21.0));
        });
    });
}
