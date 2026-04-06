use eframe::egui;
use egui::{Color32, RichText};

use crate::gui::app::{format_bytes, format_elapsed_ms, format_timestamp_compact};
use crate::gui::components::status_bar::{
    badge, count_badge, severity_color, signal_badge, storage_badge, verdict_color,
};
use crate::gui::state::ScanRecord;

pub fn render_result_row(
    ui: &mut egui::Ui,
    record: &ScanRecord,
    selected: bool,
    show_checkbox: bool,
    checked: &mut bool,
) -> bool {
    let mut inspect_clicked = false;
    let row_fill = if selected {
        Color32::from_rgb(35, 48, 60)
    } else {
        Color32::from_rgb(26, 31, 37)
    };
    egui::Frame::none()
        .fill(row_fill)
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(52, 60, 70)))
        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if show_checkbox {
                    ui.checkbox(checked, "");
                }
                ui.add_sized(
                    [72.0, 0.0],
                    egui::Label::new(
                        RichText::new(record.verdict.label())
                            .strong()
                            .color(verdict_color(record.verdict)),
                    ),
                );
                ui.add_sized(
                    [160.0, 0.0],
                    egui::Label::new(
                        RichText::new(record.display_name())
                            .strong()
                            .color(Color32::from_rgb(235, 239, 244)),
                    ),
                );
                ui.add_sized(
                    [104.0, 0.0],
                    egui::Label::new(
                        RichText::new(record.quick_type_label())
                            .color(Color32::from_rgb(190, 196, 201)),
                    ),
                );
                ui.add_sized(
                    [74.0, 0.0],
                    egui::Label::new(crate::gui::app::format_bytes(record.file_size_bytes)),
                );
                ui.add_sized(
                    [96.0, 0.0],
                    egui::Label::new(format_timestamp_compact(record.scanned_at_epoch)),
                );
                ui.horizontal(|ui| {
                    badge(ui, record.severity.label(), severity_color(record.severity));
                });
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    for source in record.signal_sources.iter().take(4) {
                        signal_badge(ui, source);
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Inspect").clicked() {
                        inspect_clicked = true;
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&record.path)
                        .monospace()
                        .size(11.0)
                        .color(Color32::from_rgb(160, 168, 178)),
                );
                storage_badge(ui, record.resolved_storage_state());
                if record.warning_count > 0 {
                    count_badge(
                        ui,
                        "W",
                        record.warning_count,
                        Color32::from_rgb(224, 185, 105),
                    );
                }
                if record.error_count > 0 {
                    count_badge(
                        ui,
                        "E",
                        record.error_count,
                        Color32::from_rgb(170, 170, 180),
                    );
                }
                badge(
                    ui,
                    &format_elapsed_ms(record.duration_ms),
                    Color32::from_rgb(115, 132, 150),
                );
                if let Some(risk) = record.risk_score {
                    ui.label(
                        RichText::new(format!("risk {:.2}", risk))
                            .size(11.0)
                            .color(Color32::from_rgb(200, 206, 212)),
                    );
                }
                ui.label(
                    RichText::new(format_bytes(record.file_size_bytes))
                        .size(11.0)
                        .color(Color32::from_rgb(160, 168, 178)),
                );
            });
        });
    inspect_clicked
}
