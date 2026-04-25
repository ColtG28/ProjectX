use eframe::egui;
use egui::{Color32, RichText};

use crate::gui::app::format_timestamp_compact;
use crate::gui::components::status_bar::{badge, severity_color, verdict_color};
use crate::gui::state::ScanRecord;
use crate::gui::theme;

const ROW_RIGHT_GUARD: f32 = 18.0;
const ROW_X_MARGIN: f32 = FRAME_INNER_X;
const COLUMN_GAP: f32 = 8.0;
const FRAME_INNER_X: f32 = 10.0;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResultCardActions {
    pub inspect: bool,
    pub copy_path: bool,
    pub copy_hash: bool,
    pub reveal_file: bool,
    pub reveal_report: bool,
    pub restore: bool,
    pub delete_quarantined_copy: bool,
    pub keep_in_quarantine: bool,
    pub remove_report: bool,
}

#[derive(Debug, Clone, Copy)]
struct ResultRowLayout {
    content_width: f32,
    compact: bool,
    show_checkbox: bool,
    show_type: bool,
    show_size: bool,
    show_time: bool,
    checkbox_width: f32,
    verdict_width: f32,
    name_width: f32,
    type_width: f32,
    size_width: f32,
    time_width: f32,
    severity_width: f32,
}

impl ResultRowLayout {
    fn new(outer_width: f32, show_checkbox: bool) -> Self {
        let content_width = card_content_width(outer_width);
        let compact = content_width < 430.0;
        let checkbox_width = if show_checkbox { 24.0 } else { 0.0 };
        let verdict_width = 72.0;
        let severity_width = 84.0;
        let show_type = content_width >= 540.0;
        let show_size = content_width >= 660.0;
        let show_time = content_width >= 790.0;
        let type_width = if show_type { 96.0 } else { 0.0 };
        let size_width = if show_size { 72.0 } else { 0.0 };
        let time_width = if show_time { 108.0 } else { 0.0 };

        let column_count = [
            show_checkbox,
            true,
            true,
            show_type,
            show_size,
            show_time,
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
            + gap_width;
        let remaining = (content_width - fixed_width).max(140.0);
        let name_width = remaining.min((content_width * 0.48).clamp(180.0, 320.0));

        Self {
            content_width,
            compact,
            show_checkbox,
            show_type,
            show_size,
            show_time,
            checkbox_width,
            verdict_width,
            name_width,
            type_width,
            size_width,
            time_width,
            severity_width,
        }
    }

    #[cfg(test)]
    fn nested_status_width(self) -> f32 {
        self.content_width
    }

    #[cfg(test)]
    fn primary_row_width(self) -> f32 {
        let mut widths = vec![self.verdict_width, self.name_width, self.severity_width];
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

        let gap_width = COLUMN_GAP * widths.len().saturating_sub(1) as f32;
        widths.into_iter().sum::<f32>() + gap_width
    }

    #[cfg(test)]
    fn visible_header_labels(self) -> Vec<&'static str> {
        if self.compact {
            return Vec::new();
        }

        let mut labels = vec!["Verdict", "Name"];
        if self.show_type {
            labels.push("Type");
        }
        if self.show_size {
            labels.push("Size");
        }
        if self.show_time {
            labels.push("Timestamp");
        }
        labels.push("Severity");
        labels
    }
}

fn card_content_width(outer_width: f32) -> f32 {
    (outer_width - (FRAME_INNER_X * 2.0)).max(1.0)
}

fn report_row_width(ui: &egui::Ui) -> f32 {
    let clip_width_from_cursor = (ui.clip_rect().right() - ui.cursor().left()).max(1.0);
    (ui.available_width().min(clip_width_from_cursor) - ROW_RIGHT_GUARD).max(1.0)
}

fn result_name_hover_text(record: &ScanRecord) -> String {
    if record.display_name() == record.path {
        record.path.clone()
    } else {
        format!("{}\n{}", record.display_name(), record.path)
    }
}

fn render_action_rows(
    ui: &mut egui::Ui,
    _record: &ScanRecord,
    _in_quarantine: bool,
) -> ResultCardActions {
    let mut actions = ResultCardActions::default();

    ui.separator();
    ui.add_space(theme::card_row_gap(1.0));

    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = theme::badge_spacing(1.0);
        actions.inspect = ui.small_button("Inspect").clicked();
        actions.copy_path = ui.small_button("Copy path").clicked();
        actions.restore = ui.small_button("Restore").clicked();
        actions.delete_quarantined_copy = ui.small_button("Delete").clicked();
        actions.remove_report = ui.small_button("Remove report").clicked();
    });
    actions
}

fn header_label(text: &str) -> RichText {
    RichText::new(text)
        .small()
        .strong()
        .color(Color32::from_rgb(170, 178, 188))
}

pub fn render_result_header(ui: &mut egui::Ui, show_checkbox: bool) -> bool {
    let row_width = report_row_width(ui);
    let layout = ResultRowLayout::new(row_width, show_checkbox);
    if layout.compact {
        return false;
    }

    ui.allocate_ui_with_layout(
        egui::vec2(row_width, 0.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_width(row_width);
            ui.set_max_width(row_width);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = COLUMN_GAP;
                ui.add_space(ROW_X_MARGIN);
                if layout.show_checkbox {
                    ui.add_sized([layout.checkbox_width, 0.0], egui::Label::new(""));
                }
                ui.add_sized(
                    [layout.verdict_width, 0.0],
                    egui::Label::new(header_label("Verdict")),
                );
                ui.add_sized(
                    [layout.name_width, 0.0],
                    egui::Label::new(header_label("Name")),
                );
                if layout.show_type {
                    ui.add_sized(
                        [layout.type_width, 0.0],
                        egui::Label::new(header_label("Type")),
                    );
                }
                if layout.show_size {
                    ui.add_sized(
                        [layout.size_width, 0.0],
                        egui::Label::new(header_label("Size")),
                    );
                }
                if layout.show_time {
                    ui.add_sized(
                        [layout.time_width, 0.0],
                        egui::Label::new(header_label("Timestamp")),
                    );
                }
                ui.add_sized(
                    [layout.severity_width, 0.0],
                    egui::Label::new(header_label("Severity")),
                );
            });
        },
    );
    true
}

pub fn render_result_card(
    ui: &mut egui::Ui,
    record: &ScanRecord,
    show_checkbox: bool,
    checked: &mut bool,
    in_quarantine: bool,
) -> ResultCardActions {
    let mut actions = ResultCardActions::default();
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
                ui.spacing_mut().item_spacing.y = theme::card_row_gap(1.0);

                if layout.compact {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = theme::badge_spacing(1.0);
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
                        .on_hover_text(result_name_hover_text(record));
                    });
                    ui.add_space(theme::card_row_gap(1.0));
                    actions = render_action_rows(ui, record, in_quarantine);
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
                    .on_hover_text(result_name_hover_text(record));
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
                });
                ui.add_space(theme::card_row_gap(1.0));
                actions = render_action_rows(ui, record, in_quarantine);
            });
        },
    );
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::state::{RecordStorageState, SeverityLevel, Verdict};

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
    }

    #[test]
    fn nested_status_area_is_card_local() {
        for outer_width in [220.0, 360.0, 640.0, 1024.0] {
            let layout = ResultRowLayout::new(outer_width, false);
            assert_eq!(layout.nested_status_width(), layout.content_width);
            assert!(layout.nested_status_width() <= card_content_width(outer_width));
        }
    }

    #[test]
    fn header_labels_only_include_stable_columns() {
        let compact = ResultRowLayout::new(320.0, false);
        assert!(compact.visible_header_labels().is_empty());

        let wide = ResultRowLayout::new(960.0, false);
        assert_eq!(
            wide.visible_header_labels(),
            vec!["Verdict", "Name", "Type", "Size", "Timestamp", "Severity"]
        );
    }

    #[test]
    fn hidden_path_remains_available_in_name_hover_text() {
        let record = ScanRecord {
            scan_id: "scan-1".to_string(),
            path: "/tmp/archive/dropper.bin".to_string(),
            file_name: "dropper.bin".to_string(),
            extension: Some("bin".to_string()),
            sha256: None,
            sniffed_mime: None,
            detected_format: None,
            quarantine_path: None,
            report_path: None,
            storage_state: RecordStorageState::Unknown,
            quarantine: Default::default(),
            last_modified_epoch: 0,
            scanned_at_epoch: 0,
            started_at_epoch: None,
            finished_at_epoch: None,
            duration_ms: 0,
            file_size_bytes: 0,
            verdict: Verdict::Suspicious,
            severity: SeverityLevel::Medium,
            summary_text: String::new(),
            action_note: String::new(),
            workflow_origin: None,
            risk_score: None,
            safety_score: None,
            signal_sources: Vec::new(),
            detection_reasons: Vec::new(),
            warning_count: 0,
            error_count: 0,
        };

        let hover = result_name_hover_text(&record);
        assert!(hover.contains("dropper.bin"));
        assert!(hover.contains("/tmp/archive/dropper.bin"));
    }
}
