use std::collections::HashSet;

use eframe::egui;
use egui::Color32;

use crate::gui::app::summarize_record_refs;
use crate::gui::components::{
    summary_chip::stat_chip, workspace_toolbar::render_record_workspace_toolbar,
};
use crate::gui::state::{FeedbackScope, MyApp, RecordStorageState, Verdict};
use crate::gui::theme;

impl MyApp {
    pub fn render_history(&mut self, ui: &mut egui::Ui) {
        ui.heading("Operations & Quarantine");
        ui.label(
            "Browse prior scans, focus on quarantined items, and inspect operational or protection-driven outcomes.",
        );
        ui.separator();
        self.render_feedback_banner(ui, FeedbackScope::FileAction);
        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));

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
        ui.add_space(theme::item_gap(self.ui_metrics.scale_factor));
        theme::card_frame().show(ui, |ui| {
            ui.label(egui::RichText::new("Review lanes").strong());
            ui.horizontal_wrapped(|ui| {
                ui.small("History keeps longer-lived scan results.");
                ui.small("Protection activity tracks queued, deferred, throttled, and completed event flow.");
                ui.small("File actions remain separate so restore, delete, and report removal stay easy to audit.");
            });
        });
        ui.separator();

        if !self.protection_events.is_empty() {
            ui.group(|ui| {
                ui.label(egui::RichText::new("Protection activity").strong());
                ui.label(
                    "Settings controls what gets watched, Scan shows live state, and Operations keeps the reviewable protection timeline.",
                );
                ui.horizontal_wrapped(|ui| {
                    stat_chip(
                        ui,
                        "Queue health",
                        self.protection_summary.queue_health.clone(),
                        Color32::from_rgb(176, 221, 255),
                    );
                    stat_chip(
                        ui,
                        "Monitor",
                        format!(
                            "{} ({})",
                            self.protection_summary.monitor_mode,
                            self.protection_summary.monitor_state
                        ),
                        Color32::from_rgb(132, 170, 214),
                    );
                    stat_chip(
                        ui,
                        "Backlog",
                        self.protection_summary.backlog_count.to_string(),
                        Color32::from_rgb(224, 185, 105),
                    );
                    stat_chip(
                        ui,
                        "Deferred",
                        self.protection_summary.deferred_event_count.to_string(),
                        Color32::from_rgb(224, 185, 105),
                    );
                    stat_chip(
                        ui,
                        "Skipped",
                        self.protection_summary.skipped_event_count.to_string(),
                        Color32::from_rgb(170, 170, 180),
                    );
                });
                if !self.protection_summary.queue_health_detail.is_empty() {
                    ui.label(&self.protection_summary.queue_health_detail);
                }
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label("Search");
                    ui.add_sized(
                        [ui.available_width().min(260.0), 0.0],
                        egui::TextEdit::singleline(&mut self.protection_event_search)
                            .hint_text("Path, note, origin, or event type"),
                    );
                    egui::ComboBox::from_id_source("protection_kind_filter")
                        .selected_text(self.protection_kind_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                crate::gui::state::ProtectionEventKindFilter::All,
                                crate::gui::state::ProtectionEventKindFilter::Queued,
                                crate::gui::state::ProtectionEventKindFilter::Deferred,
                                crate::gui::state::ProtectionEventKindFilter::Completed,
                                crate::gui::state::ProtectionEventKindFilter::Throttled,
                                crate::gui::state::ProtectionEventKindFilter::Skipped,
                                crate::gui::state::ProtectionEventKindFilter::Error,
                            ] {
                                ui.selectable_value(
                                    &mut self.protection_kind_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    egui::ComboBox::from_id_source("protection_file_filter")
                        .selected_text(self.protection_file_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                crate::gui::state::ProtectionFileClassFilter::All,
                                crate::gui::state::ProtectionFileClassFilter::Executable,
                                crate::gui::state::ProtectionFileClassFilter::Script,
                                crate::gui::state::ProtectionFileClassFilter::Archive,
                                crate::gui::state::ProtectionFileClassFilter::Document,
                                crate::gui::state::ProtectionFileClassFilter::TempCache,
                                crate::gui::state::ProtectionFileClassFilter::Other,
                            ] {
                                ui.selectable_value(
                                    &mut self.protection_file_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    egui::ComboBox::from_id_source("protection_priority_filter")
                        .selected_text(self.protection_priority_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                crate::gui::state::ProtectionPriorityFilter::All,
                                crate::gui::state::ProtectionPriorityFilter::High,
                                crate::gui::state::ProtectionPriorityFilter::Normal,
                                crate::gui::state::ProtectionPriorityFilter::Low,
                            ] {
                                ui.selectable_value(
                                    &mut self.protection_priority_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    egui::ComboBox::from_id_source("protection_origin_filter")
                        .selected_text(self.protection_origin_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                crate::gui::state::ProtectionOriginFilter::All,
                                crate::gui::state::ProtectionOriginFilter::RealTimeProtection,
                                crate::gui::state::ProtectionOriginFilter::DownloadMonitoring,
                                crate::gui::state::ProtectionOriginFilter::Manual,
                            ] {
                                ui.selectable_value(
                                    &mut self.protection_origin_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    egui::ComboBox::from_id_source("protection_verdict_filter")
                        .selected_text(self.protection_verdict_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                crate::gui::state::ProtectionVerdictFilter::All,
                                crate::gui::state::ProtectionVerdictFilter::Clean,
                                crate::gui::state::ProtectionVerdictFilter::Suspicious,
                                crate::gui::state::ProtectionVerdictFilter::Malicious,
                                crate::gui::state::ProtectionVerdictFilter::Error,
                                crate::gui::state::ProtectionVerdictFilter::None,
                            ] {
                                ui.selectable_value(
                                    &mut self.protection_verdict_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    egui::ComboBox::from_id_source("protection_action_filter")
                        .selected_text(self.protection_action_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                crate::gui::state::ProtectionActionFilter::All,
                                crate::gui::state::ProtectionActionFilter::Quarantined,
                                crate::gui::state::ProtectionActionFilter::Restored,
                                crate::gui::state::ProtectionActionFilter::Deleted,
                                crate::gui::state::ProtectionActionFilter::Unknown,
                                crate::gui::state::ProtectionActionFilter::None,
                            ] {
                                ui.selectable_value(
                                    &mut self.protection_action_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    if ui.button("Clear filters").clicked() {
                        self.protection_event_search.clear();
                        self.protection_kind_filter =
                            crate::gui::state::ProtectionEventKindFilter::All;
                        self.protection_file_filter =
                            crate::gui::state::ProtectionFileClassFilter::All;
                        self.protection_priority_filter =
                            crate::gui::state::ProtectionPriorityFilter::All;
                        self.protection_origin_filter =
                            crate::gui::state::ProtectionOriginFilter::All;
                        self.protection_verdict_filter =
                            crate::gui::state::ProtectionVerdictFilter::All;
                        self.protection_action_filter =
                            crate::gui::state::ProtectionActionFilter::All;
                    }
                });

                let protection_indices = self.filtered_protection_event_indices(100);
                if protection_indices.is_empty() {
                    ui.label("No protection events match the current filters.");
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(240.0)
                        .show(ui, |ui| {
                            for index in protection_indices {
                                let event = &self.protection_events[index];
                                ui.group(|ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(format!(
                                            "{} | {} | {} | {}",
                                            event.kind,
                                            crate::gui::app::format_timestamp_compact(
                                                event.timestamp_epoch
                                            ),
                                            event.workflow_source,
                                            event.file_class.label()
                                        ));
                                        ui.label(format!(
                                            "{} priority | {}",
                                            event.priority.label(),
                                            event.change_class.label()
                                        ));
                                    });
                                    if !event.event_source.is_empty() {
                                        ui.label(format!("Event source: {}", event.event_source));
                                    }
                                    ui.monospace(&event.path);
                                    ui.label(&event.note);
                                    ui.label(format!(
                                        "{}{}{}",
                                        if event.grouped_change_count > 1
                                            || event.burst_window_seconds > 0
                                        {
                                            format!(
                                                "Grouped {} change(s) across {}s",
                                                event.grouped_change_count,
                                                event.burst_window_seconds
                                            )
                                        } else {
                                            "Single observed change".to_string()
                                        },
                                        event
                                            .verdict
                                            .as_deref()
                                            .map(|verdict| format!(" | result {verdict}"))
                                            .unwrap_or_default(),
                                        event
                                            .storage_state
                                            .as_deref()
                                            .map(|state| format!(" | action {state}"))
                                            .unwrap_or_default()
                                    ));
                                });
                            }
                        });
                }
            });
            ui.separator();
        }

        self.render_notification_center(
            ui,
            "Recent operational activity",
            &[
                FeedbackScope::FileAction,
                FeedbackScope::Protection,
                FeedbackScope::Updater,
            ],
            6,
        );
        ui.add_space(theme::section_gap(self.ui_metrics.scale_factor));

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
            "Operations keeps the long-running audit view while Results stays focused on active triage.",
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
            "Operations is optimized for audit review, quarantine handling, and automatic protection outcomes. Restore and delete remain limited to quarantined files and always require confirmation.",
        );
    }
}
