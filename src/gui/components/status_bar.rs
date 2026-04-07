use eframe::egui::{self, Color32, RichText, Stroke};

use crate::gui::state::{RecordStorageState, SeverityLevel, Verdict};

pub fn verdict_color(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::Clean => Color32::from_rgb(127, 191, 127),
        Verdict::Malicious => Color32::from_rgb(216, 100, 100),
        Verdict::Suspicious => Color32::from_rgb(224, 185, 105),
        Verdict::Error => Color32::from_rgb(170, 170, 180),
    }
}

pub fn severity_color(severity: SeverityLevel) -> Color32 {
    match severity {
        SeverityLevel::Clean => Color32::from_rgb(127, 191, 127),
        SeverityLevel::Low => Color32::from_rgb(110, 170, 214),
        SeverityLevel::Medium => Color32::from_rgb(224, 185, 105),
        SeverityLevel::High => Color32::from_rgb(216, 100, 100),
        SeverityLevel::Error => Color32::from_rgb(170, 170, 180),
    }
}

pub fn badge(ui: &mut egui::Ui, text: &str, fill: Color32) {
    egui::Frame::none()
        .fill(fill.gamma_multiply(0.18))
        .stroke(Stroke::new(1.0, fill.gamma_multiply(0.8)))
        .rounding(4.0)
        .inner_margin(egui::Margin::symmetric(6.0, 3.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(fill).strong().size(11.0));
        });
}

pub fn storage_color(state: RecordStorageState) -> Color32 {
    match state {
        RecordStorageState::InQuarantine => Color32::from_rgb(132, 170, 214),
        RecordStorageState::Restored => Color32::from_rgb(127, 191, 127),
        RecordStorageState::Deleted => Color32::from_rgb(170, 170, 180),
        RecordStorageState::Unknown => Color32::from_rgb(145, 152, 162),
    }
}

pub fn storage_badge(ui: &mut egui::Ui, state: RecordStorageState) {
    badge(ui, state.label(), storage_color(state));
}

pub fn count_badge(ui: &mut egui::Ui, prefix: &str, count: usize, fill: Color32) {
    badge(ui, &format!("{prefix} {count}"), fill);
}

pub fn signal_badge(ui: &mut egui::Ui, source: &str) {
    let (label, color) = match source {
        "heuristic" => ("H", Color32::from_rgb(224, 185, 105)),
        "rule" => ("R", Color32::from_rgb(110, 170, 214)),
        "intelligence" => ("I", Color32::from_rgb(126, 196, 148)),
        "emulation" => ("E", Color32::from_rgb(194, 142, 214)),
        "ml" => ("ML", Color32::from_rgb(132, 205, 168)),
        "cache" => ("C", Color32::from_rgb(140, 150, 160)),
        _ => ("•", Color32::from_rgb(170, 170, 180)),
    };
    badge(ui, label, color);
}
