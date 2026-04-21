use std::collections::HashSet;

use eframe::egui;
use egui::Color32;

use crate::gui::app::summarize_record_refs;
use crate::gui::components::{
    summary_chip::stat_chip, workspace_toolbar::render_record_workspace_toolbar,
};
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
                ui.add_space(6.0);
                theme::card_frame().show(ui, |ui| {
                    ui.label(egui::RichText::new("Quick review filters").strong());
                    ui.horizontal_wrapped(|ui| {
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
                        ] {
                            let selected = self.report_verdict_filter == filter;
                            if ui
                                .add(egui::Button::new(label).fill(if selected {
                                    Color32::from_rgb(52, 68, 88)
                                } else {
                                    Color32::from_rgb(31, 37, 44)
                                }))
                                .clicked()
                            {
                                self.report_verdict_filter = filter;
                            }
                        }
                    });
                });
                ui.separator();

                let indices = all_indices;
                let displayed_ids = indices
                    .iter()
                    .map(|&index| self.records[index].record_id())
                    .collect::<HashSet<_>>();
                let selected_visible = self
                    .selected_report_ids
                    .iter()
                    .filter(|id| displayed_ids.contains(*id))
                    .count();
                let toolbar = render_record_workspace_toolbar(
                    ui,
                    &mut self.report_search,
                    "Search reports...",
                    &mut self.report_verdict_filter,
                    &mut self.report_storage_filter,
                    &mut self.report_sort_order,
                    None,
                    indices.len(),
                    Some(selected_visible),
                    Some(
                        filtered_records
                            .iter()
                            .filter(|record| {
                                displayed_ids.contains(&record.record_id())
                                    && self.selected_report_ids.contains(&record.record_id())
                                    && record.resolved_storage_state()
                                        == crate::gui::state::RecordStorageState::InQuarantine
                            })
                            .count(),
                    ),
                    true,
                    false,
                );
                if toolbar.select_all_shown {
                    self.selected_report_ids
                        .extend(displayed_ids.iter().cloned());
                }
                if toolbar.clear_shown {
                    for id in &displayed_ids {
                        self.selected_report_ids.remove(id);
                    }
                }
                if toolbar.delete_selected_reports {
                    self.delete_selected_reports(&displayed_ids);
                }
                if let Some(focused) = self.focused_report_id.as_ref() {
                    ui.small(format!("Pinned detail: {}", focused));
                }
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
