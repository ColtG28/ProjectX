use eframe::egui;
use egui::{Color32, FontFamily, FontId, Stroke, TextStyle};

pub fn apply_theme(ctx: &egui::Context, scale: f32) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(Color32::from_rgb(220, 224, 230));
    style.visuals.panel_fill = Color32::from_rgb(23, 28, 34);
    style.visuals.faint_bg_color = Color32::from_rgb(31, 37, 44);
    style.visuals.extreme_bg_color = Color32::from_rgb(16, 20, 25);
    style.visuals.code_bg_color = Color32::from_rgb(24, 31, 39);
    style.visuals.window_fill = Color32::from_rgb(29, 35, 42);
    style.visuals.window_stroke = Stroke::new(1.0, Color32::from_rgb(57, 66, 76));
    style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(36, 43, 51);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(36, 43, 51);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(44, 64, 80);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(59, 95, 124);
    style.visuals.widgets.open.bg_fill = Color32::from_rgb(37, 55, 69);
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(220, 227, 233));
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::from_rgb(241, 247, 252));
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::from_rgb(248, 252, 255));
    style.visuals.selection.bg_fill = Color32::from_rgb(47, 84, 120);
    style.visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(180, 221, 255));
    style.visuals.hyperlink_color = Color32::from_rgb(180, 221, 255);
    style.visuals.widgets.hovered.expansion = 1.0;
    style.visuals.widgets.active.expansion = 0.0;
    style.spacing.item_spacing = egui::vec2(10.0 * scale, 10.0 * scale);
    style.spacing.button_padding = egui::vec2(10.0 * scale, 7.0 * scale);
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new((14.0 * scale).clamp(13.0, 17.0), FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new((14.0 * scale).clamp(13.0, 17.0), FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new((22.0 * scale).clamp(20.0, 28.0), FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new((13.0 * scale).clamp(12.0, 16.0), FontFamily::Monospace),
    );
    ctx.set_style(style);
}
