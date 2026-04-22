use eframe::egui;
use egui::{Color32, RichText};

use crate::gui::app::{format_elapsed_ms, format_timestamp_compact};
use crate::gui::components::status_bar::{
    badge, count_badge, severity_color, signal_badge, storage_badge, verdict_color,
};
use crate::gui::state::ScanRecord;
use crate::gui::theme;

const ROW_RIGHT_GUARD: f32 = 18.0;
const ROW_X_MARGIN: f32 = 6.0;
const COLUMN_GAP: f32 = 4.0;
const FRAME_INNER_X: f32 = 10.0;

#[derive(Debug, Clone, Copy)]
struct ResultRowLayout {
    content_width: f32,
    compact: bool,
    show_checkbox: bool,
    show_type: bool,
    show_size: bool,
    show_time: bool,
    show_signals: bool,
    checkbox_width: f32,
    verdict_width: f32,
    name_width: f32,
    type_width: f32,
    size_width: f32,
    time_width: f32,
    severity_width: f32,
    signals_width: f32,
    inspect_width: f32,
}

impl ResultRowLayout {
    fn new(outer_width: f32, show_checkbox: bool) -> Self {
        let content_width = card_content_width(outer_width);
        let compact = content_width < 360.0;
        let checkbox_width = if show_checkbox { 24.0 } else { 0.0 };
        let verdict_width = 64.0;
        let severity_width = 70.0;
        let inspect_width = 62.0;
        let show_type = content_width >= 620.0;
        let show_size = content_width >= 720.0;
        let show_time = content_width >= 840.0;
        let wants_signals = content_width >= 560.0;
        let type_width = if show_type { 86.0 } else { 0.0 };
        let size_width = if show_size { 62.0 } else { 0.0 };
        let time_width = if show_time { 88.0 } else { 0.0 };

        let column_count = [
            show_checkbox,
            true,
            true,
            show_type,
            show_size,
            show_time,
            true,
            wants_signals,
            true,
        ]
        .into_iter()
        .filter(|visible| *visible)
        .count();
        let gap_width = COLUMN_GAP * column_count.saturating_sub(1) as f32;
        let fixed_width = checkbox_width
            + verdict_width
            + type_width
            + size_width
            + time_width
            + severity_width
            + inspect_width
            + gap_width;
        let remaining = (content_width - fixed_width).max(72.0);
        let name_width = remaining.min(190.0);
        let signals_width = if wants_signals {
            (remaining - name_width).max(0.0)
        } else {
            0.0
        };

        Self {
            content_width,
            compact,
            show_checkbox,
            show_type,
            show_size,
            show_time,
            show_signals: signals_width >= 80.0,
            checkbox_width,
            verdict_width,
            name_width,
            type_width,
            size_width,
            time_width,
            severity_width,
            signals_width,
            inspect_width,
        }
    }

    #[cfg(test)]
    fn nested_status_width(self) -> f32 {
        self.content_width
    }

    #[cfg(test)]
    fn primary_row_width(self) -> f32 {
        let mut widths = vec![
            self.verdict_width,
            self.name_width,
            self.severity_width,
            self.inspect_width,
        ];
        if self.show_checkbox {
            widths.push(self.checkbox_width);
        }
        if self.show_type {
            widths.push(self.type_width);
        }
        if self.show_size {
            widths.push(self.size_width);
        }
        if self.show_time {
            widths.push(self.time_width);
        }
        if self.show_signals {
            widths.push(self.signals_width);
        }

        let gap_width = COLUMN_GAP * widths.len().saturating_sub(1) as f32;
        widths.into_iter().sum::<f32>() + gap_width
    }
}

fn card_content_width(outer_width: f32) -> f32 {
    (outer_width - (FRAME_INNER_X * 2.0)).max(1.0)
}

fn report_row_width(ui: &egui::Ui) -> f32 {
    let clip_width_from_cursor = (ui.clip_rect().right() - ui.cursor().left()).max(1.0);
    (ui.available_width().min(clip_width_from_cursor) - ROW_RIGHT_GUARD).max(1.0)
}

fn render_path_line(ui: &mut egui::Ui, path: &str) {
    ui.add_sized(
        [ui.available_width().max(1.0), 0.0],
        egui::Label::new(
            RichText::new(path)
                .monospace()
                .size(11.0)
                .color(Color32::from_rgb(160, 168, 178)),
        )
        .truncate(true),
    )
    .on_hover_text(path);
}

fn render_metadata_badges(ui: &mut egui::Ui, record: &ScanRecord) {
    ui.horizontal_wrapped(|ui| {
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
    });
}

pub fn render_result_header(ui: &mut egui::Ui, show_checkbox: bool) {
    let row_width = report_row_width(ui);
    let layout = ResultRowLayout::new(row_width, show_checkbox);
    ui.allocate_ui_with_layout(
        egui::vec2(row_width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(row_width);
            ui.set_max_width(row_width);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = COLUMN_GAP;
                ui.add_space(ROW_X_MARGIN);
                if layout.compact {
                    ui.add_sized(
                        [layout.verdict_width, 0.0],
                        egui::Label::new(RichText::new("Verdict").strong()),
                    );
                    ui.add_sized(
                        [layout.name_width, 0.0],
                        egui::Label::new(RichText::new("Name").strong()),
                    );
                    ui.add_sized(
                        [layout.inspect_width, 0.0],
                        egui::Label::new(RichText::new("Action").strong()),
                    );
                    return;
                }

                if layout.show_checkbox {
                    ui.add_sized([layout.checkbox_width, 0.0], egui::Label::new(""));
                }
                ui.add_sized(
                    [layout.verdict_width, 0.0],
                    egui::Label::new(RichText::new("Verdict").strong()),
                );
                ui.add_sized(
                    [layout.name_width, 0.0],
                    egui::Label::new(RichText::new("Name").strong()),
                );
                if layout.show_type {
                    ui.add_sized(
                        [layout.type_width, 0.0],
                        egui::Label::new(RichText::new("Type").strong()),
                    );
                }
                if layout.show_size {
                    ui.add_sized(
                        [layout.size_width, 0.0],
                        egui::Label::new(RichText::new("Size").strong()),
                    );
                }
                if layout.show_time {
                    ui.add_sized(
                        [layout.time_width, 0.0],
                        egui::Label::new(RichText::new("Timestamp").strong()),
                    );
                }
                ui.add_sized(
                    [layout.severity_width, 0.0],
                    egui::Label::new(RichText::new("Severity").strong()),
                );
                if layout.show_signals {
                    ui.add_sized(
                        [layout.signals_width, 0.0],
                        egui::Label::new(RichText::new("Signals").strong()).truncate(true),
                    );
                }
                ui.add_sized(
                    [layout.inspect_width, 0.0],
                    egui::Label::new(RichText::new("Action").strong()),
                );
            });
        },
    );
}

pub fn render_result_row(
    ui: &mut egui::Ui,
    record: &ScanRecord,
    _selected: bool,
    show_checkbox: bool,
    checked: &mut bool,
) -> bool {
    let mut inspect_clicked = false;
    let row_width = report_row_width(ui);
    let layout = ResultRowLayout::new(row_width, show_checkbox);
    ui.allocate_ui_with_layout(
        egui::vec2(row_width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(row_width);
            ui.set_max_width(row_width);
            theme::card_frame().show(ui, |ui| {
                ui.set_min_width(layout.content_width);
                ui.set_max_width(layout.content_width);

                if layout.compact {
                    ui.horizontal_wrapped(|ui| {
                        if show_checkbox {
                            ui.checkbox(checked, "");
                        }
                        ui.add_sized(
                            [layout.verdict_width, 0.0],
                            egui::Label::new(
                                RichText::new(record.verdict.label())
                                    .strong()
                                    .color(verdict_color(record.verdict)),
                            ),
                        );
                        ui.add_sized(
                            [layout.name_width.max(80.0), 0.0],
                            egui::Label::new(
                                RichText::new(record.display_name())
                                    .strong()
                                    .color(Color32::from_rgb(235, 239, 244)),
                            )
                            .truncate(true),
                        )
                        .on_hover_text(record.display_name());
                        if ui.small_button("Inspect").clicked() {
                            inspect_clicked = true;
                        }
                    });
                    render_path_line(ui, &record.path);
                    ui.horizontal_wrapped(|ui| {
                        badge(ui, record.severity.label(), severity_color(record.severity));
                    });
                    render_metadata_badges(ui, record);
                    return;
                }

                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = COLUMN_GAP;
                    if show_checkbox {
                        ui.add_sized(
                            [layout.checkbox_width, 0.0],
                            egui::Checkbox::new(checked, ""),
                        );
                    }
                    ui.add_sized(
                        [layout.verdict_width, 0.0],
                        egui::Label::new(
                            RichText::new(record.verdict.label())
                                .strong()
                                .color(verdict_color(record.verdict)),
                        ),
                    );
                    ui.add_sized(
                        [layout.name_width, 0.0],
                        egui::Label::new(
                            RichText::new(record.display_name())
                                .strong()
                                .color(Color32::from_rgb(235, 239, 244)),
                        )
                        .truncate(true),
                    )
                    .on_hover_text(record.display_name());
                    if layout.show_type {
                        ui.add_sized(
                            [layout.type_width, 0.0],
                            egui::Label::new(
                                RichText::new(record.quick_type_label())
                                    .color(Color32::from_rgb(190, 196, 201)),
                            )
                            .truncate(true),
                        );
                    }
                    if layout.show_size {
                        ui.add_sized(
                            [layout.size_width, 0.0],
                            egui::Label::new(crate::gui::app::format_bytes(record.file_size_bytes)),
                        );
                    }
                    if layout.show_time {
                        ui.add_sized(
                            [layout.time_width, 0.0],
                            egui::Label::new(format_timestamp_compact(record.scanned_at_epoch)),
                        );
                    }
                    ui.allocate_ui_with_layout(
                        egui::vec2(layout.severity_width, 0.0),
                        egui::Layout::left_to_right(egui::Align::Center),
                        |ui| {
                            badge(ui, record.severity.label(), severity_color(record.severity));
                        },
                    );
                    if layout.show_signals {
                        ui.allocate_ui_with_layout(
                            egui::vec2(layout.signals_width, 0.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                let signal_limit = if layout.signals_width >= 220.0 {
                                    4
                                } else if layout.signals_width >= 140.0 {
                                    2
                                } else {
                                    1
                                };
                                for source in record.signal_sources.iter().take(signal_limit) {
                                    signal_badge(ui, source);
                                }
                            },
                        );
                    }
                    if ui
                        .add_sized([layout.inspect_width, 0.0], egui::Button::new("Inspect"))
                        .clicked()
                    {
                        inspect_clicked = true;
                    }
                });
                render_path_line(ui, &record.path);
                render_metadata_badges(ui, record);
            });
        },
    );
    inspect_clicked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_row_layout_stays_within_card_content_width() {
        for show_checkbox in [false, true] {
            for outer_width in [240.0, 320.0, 360.0, 480.0, 720.0, 960.0, 1280.0] {
                let layout = ResultRowLayout::new(outer_width, show_checkbox);
                assert!(
                    card_content_width(outer_width) + (FRAME_INNER_X * 2.0)
                        <= outer_width + f32::EPSILON,
                    "content width should account for frame margin at {outer_width}"
                );
                if !layout.compact {
                    assert!(
                        layout.primary_row_width() <= layout.content_width + f32::EPSILON,
                        "primary row should not exceed card content at {outer_width}"
                    );
                }
            }
        }
    }

    #[test]
    fn result_row_layout_collapses_metadata_on_narrow_widths() {
        let layout = ResultRowLayout::new(500.0, false);
        assert!(!layout.show_type);
        assert!(!layout.show_size);
        assert!(!layout.show_time);
        assert!(!layout.show_signals);
    }

    #[test]
    fn nested_status_area_is_card_local() {
        for outer_width in [220.0, 360.0, 640.0, 1024.0] {
            let layout = ResultRowLayout::new(outer_width, false);
            assert_eq!(layout.nested_status_width(), layout.content_width);
            assert!(layout.nested_status_width() <= card_content_width(outer_width));
        }
    }
}
