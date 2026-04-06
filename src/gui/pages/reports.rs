use std::collections::HashSet;

use eframe::egui;
use egui::Color32;

use crate::gui::app::summarize_record_refs;
use crate::gui::components::{
    summary_chip::stat_chip, workspace_toolbar::render_record_workspace_toolbar,
};
use crate::gui::state::MyApp;

impl MyApp {
    pub fn render_reports(&mut self, ui: &mut egui::Ui) {
        ui.heading("Results Explorer");
        ui.label(
            "Filter scan history, inspect reasoning, and manage safe report or quarantine actions.",
        );
        ui.separator();

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
            "Search by path, hash, mime, reason, report path, verdict, or storage state",
            &mut self.report_verdict_filter,
            &mut self.report_storage_filter,
            &mut self.report_sort_order,
            None,
            indices.len(),
            Some(selected_visible),
            true,
            "Use Results for active triage. Report removal requires confirmation.",
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
        ui.separator();
        self.render_record_workspace(
            ui,
            &indices,
            "No matching results",
            "Try clearing filters or run a new scan to populate the results explorer.",
            "Results focuses on current triage and report management. Safe file actions remain local and confirm before changing quarantine state.",
        );
    }
}
