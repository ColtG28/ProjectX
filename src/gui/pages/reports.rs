use eframe::egui;
use egui::Color32;

use crate::gui::app::summarize_record_refs;
use crate::gui::components::summary_chip::stat_chip;
use crate::gui::state::{FeedbackScope, MyApp};
use crate::gui::theme;

impl MyApp {
    pub fn render_reports(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_source("results_page")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.heading("Results");
                ui.separator();
                self.render_feedback_banner(ui, FeedbackScope::FileAction);
                ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));

                let all_indices = self.filtered_record_indices(1_000, self.report_search.trim());
                let filtered_records = all_indices
                    .iter()
                    .map(|&index| &self.records[index])
                    .collect::<Vec<_>>();
                let metrics = summarize_record_refs(&filtered_records);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = theme::badge_spacing(self.ui_metrics.scale_factor);
                    stat_chip(
                        ui,
                        "Visible results",
                        metrics.total.to_string(),
                        Color32::from_rgb(176, 221, 255),
                    );
                    stat_chip(
                        ui,
                        "Malicious",
                        metrics.malicious.to_string(),
                        Color32::from_rgb(216, 100, 100),
                    );
                    stat_chip(
                        ui,
                        "Suspicious",
                        metrics.suspicious.to_string(),
                        Color32::from_rgb(224, 185, 105),
                    );
                    stat_chip(
                        ui,
                        "Errors",
                        metrics.errors.to_string(),
                        Color32::from_rgb(170, 170, 180),
                    );
                    stat_chip(
                        ui,
                        "In quarantine",
                        metrics.in_quarantine.to_string(),
                        Color32::from_rgb(132, 170, 214),
                    );
                });
                ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
                theme::card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    theme::card_title(ui, "Filters", self.ui_metrics.scale_factor);
                    ui.add_sized(
                        [ui.available_width().min(520.0), 0.0],
                        egui::TextEdit::singleline(&mut self.report_search)
                            .hint_text("Search reports..."),
                    );
                    ui.add_space(theme::card_row_gap(self.ui_metrics.scale_factor));
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = theme::badge_spacing(self.ui_metrics.scale_factor);
                        for (label, filter) in [
                            ("All", crate::gui::state::ReportVerdictFilter::All),
                            ("Clean", crate::gui::state::ReportVerdictFilter::Clean),
                            (
                                "Suspicious",
                                crate::gui::state::ReportVerdictFilter::Suspicious,
                            ),
                            (
                                "Malicious",
                                crate::gui::state::ReportVerdictFilter::Malicious,
                            ),
                            ("Errors", crate::gui::state::ReportVerdictFilter::Error),
                        ] {
                            let selected = self.report_verdict_filter == filter
                                && (filter != crate::gui::state::ReportVerdictFilter::All
                                    || self.report_storage_filter
                                        == crate::gui::state::ReportStorageFilter::All);
                            if ui
                                .add(egui::Button::new(label).fill(if selected {
                                    Color32::from_rgb(52, 68, 88)
                                } else {
                                    Color32::from_rgb(31, 37, 44)
                                }))
                                .clicked()
                            {
                                self.report_verdict_filter = filter;
                                self.report_storage_filter =
                                    crate::gui::state::ReportStorageFilter::All;
                            }
                        }
                        let quarantined = self.report_storage_filter
                            == crate::gui::state::ReportStorageFilter::InQuarantine;
                        if ui
                            .add(egui::Button::new("Quarantined").fill(if quarantined {
                                Color32::from_rgb(52, 68, 88)
                            } else {
                                Color32::from_rgb(31, 37, 44)
                            }))
                            .clicked()
                        {
                            self.report_verdict_filter = crate::gui::state::ReportVerdictFilter::All;
                            self.report_storage_filter =
                                crate::gui::state::ReportStorageFilter::InQuarantine;
                        }
                    });
                });

                let indices = all_indices;
                ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
                ui.separator();
                self.render_record_workspace(
                    ui,
                    &indices,
                    "No matching results",
                    "Try clearing filters or run a new scan to populate the results explorer.",
                    "Results focuses on the current working set. Use Operations for long-running audit history and protection events.",
                );
            });
    }
}
