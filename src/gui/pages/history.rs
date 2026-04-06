use std::collections::HashSet;

use eframe::egui;
use egui::Color32;

use crate::gui::app::summarize_record_refs;
use crate::gui::components::{
    summary_chip::stat_chip, workspace_toolbar::render_record_workspace_toolbar,
};
use crate::gui::state::{MyApp, RecordStorageState, Verdict};

impl MyApp {
    pub fn render_history(&mut self, ui: &mut egui::Ui) {
        ui.heading("History & Quarantine");
        ui.label(
            "Browse prior scans, focus on quarantined items, and inspect operational outcomes.",
        );
        ui.separator();

        let mut indices = self.filtered_record_indices(2_000, self.history_search.trim());
        if self.history_quarantine_only {
            indices.retain(|&index| {
                self.records[index].resolved_storage_state() == RecordStorageState::InQuarantine
            });
        }
        let records = indices
            .iter()
            .map(|&index| &self.records[index])
            .collect::<Vec<_>>();
        let metrics = summarize_record_refs(&records);
        let suspicious_or_high = records
            .iter()
            .filter(|record| matches!(record.verdict, Verdict::Malicious | Verdict::Suspicious))
            .count();

        ui.horizontal_wrapped(|ui| {
            stat_chip(
                ui,
                "History items",
                metrics.total.to_string(),
                Color32::from_rgb(176, 221, 255),
            );
            stat_chip(
                ui,
                "Quarantined",
                metrics.in_quarantine.to_string(),
                Color32::from_rgb(132, 170, 214),
            );
            stat_chip(
                ui,
                "Suspicious / high",
                suspicious_or_high.to_string(),
                Color32::from_rgb(224, 185, 105),
            );
            stat_chip(
                ui,
                "Warnings",
                metrics.warning_total.to_string(),
                Color32::from_rgb(224, 185, 105),
            );
            stat_chip(
                ui,
                "Errors",
                metrics.error_total.to_string(),
                Color32::from_rgb(170, 170, 180),
            );
        });
        ui.separator();

        let displayed_ids = indices
            .iter()
            .map(|&index| self.records[index].record_id())
            .collect::<HashSet<_>>();
        let toolbar = render_record_workspace_toolbar(
            ui,
            &mut self.history_search,
            "Search history by path, hash, type, severity, or reason",
            &mut self.report_verdict_filter,
            &mut self.report_storage_filter,
            &mut self.report_sort_order,
            Some(&mut self.history_quarantine_only),
            indices.len(),
            None,
            false,
            "History mirrors the Results explorer while focusing on retained records and quarantine state.",
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
        ui.separator();
        self.render_record_workspace(
            ui,
            &indices,
            "No matching history items",
            "Run a scan or clear the quarantine-only toggle to see more operational history.",
            "History is optimized for operational review. Restore and delete remain limited to quarantined files and always require confirmation.",
        );
    }
}
