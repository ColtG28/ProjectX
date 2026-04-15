use eframe::egui;
use egui::RichText;

use std::collections::BTreeMap;

use crate::gui::app::{format_elapsed_ms, format_timestamp_with_relative};
use crate::gui::components::status_bar::{
    badge, count_badge, severity_color, signal_badge, storage_badge, verdict_color,
};
use crate::gui::state::{ProtectionEvent, ScanRecord};
use crate::gui::theme;
use crate::r#static::report::source_label;

pub fn render_result_detail(
    ui: &mut egui::Ui,
    scale: f32,
    record: &ScanRecord,
    protection_event: Option<&ProtectionEvent>,
) {
    ui.heading("Detection Detail");
    ui.label("Pinned result summary, strongest signals, and safe follow-up context.");
    ui.separator();

    detail_section(ui, "Summary", |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(record.verdict.label())
                    .strong()
                    .color(verdict_color(record.verdict)),
            );
            badge(ui, record.severity.label(), severity_color(record.severity));
            for source in &record.signal_sources {
                signal_badge(ui, source);
            }
            storage_badge(ui, record.resolved_storage_state());
            if record.warning_count > 0 {
                count_badge(
                    ui,
                    "Warnings",
                    record.warning_count,
                    egui::Color32::from_rgb(224, 185, 105),
                );
            }
            if record.error_count > 0 {
                count_badge(
                    ui,
                    "Errors",
                    record.error_count,
                    egui::Color32::from_rgb(170, 170, 180),
                );
            }
        });
        ui.label(format!(
            "File size: {}",
            crate::gui::app::format_bytes(record.file_size_bytes)
        ));
        ui.label(format!(
            "Scanned at: {}",
            format_timestamp_with_relative(record.scanned_at_epoch)
        ));
        ui.label(format!(
            "Scan duration: {}",
            format_elapsed_ms(record.duration_ms)
        ));
        if let Some(mime) = record.sniffed_mime.as_deref() {
            ui.label(format!("MIME: {mime}"));
        }
        if let Some(format_name) = record.detected_format.as_deref() {
            ui.label(format!("Detected format: {format_name}"));
        }
        if let Some(origin) = record.workflow_origin.as_deref() {
            ui.label(format!("Workflow: {origin}"));
        }
        if let Some(event) = protection_event {
            ui.label(format!(
                "Protection event: {} | {} | {} | {} priority",
                event.kind,
                event.change_class.label(),
                event.file_class.label(),
                event.priority.label()
            ));
            ui.label(format!(
                "Protection path: {}",
                if event.workflow_source.is_empty() {
                    "Automatic scan".to_string()
                } else {
                    event.workflow_source.clone()
                }
            ));
            if event.grouped_change_count > 1 || event.burst_window_seconds > 0 {
                ui.label(format!(
                    "Grouped {} change(s) across {}s before this scan.",
                    event.grouped_change_count, event.burst_window_seconds
                ));
            }
            if let Some(verdict) = event.verdict.as_deref() {
                ui.label(format!("Protection result: {verdict}"));
            }
            if let Some(action) = event.storage_state.as_deref() {
                ui.label(format!("Protection action: {action}"));
            }
            if !event.event_source.is_empty() {
                ui.label(format!("Event source: {}", event.event_source));
            }
        }
        if let Some(risk) = record.risk_score {
            ui.label(format!("Risk score: {risk:.2}"));
        }
        if let Some(safety) = record.safety_score {
            ui.label(format!("Safety score: {safety:.2}"));
        }
        if record
            .signal_sources
            .iter()
            .any(|source| source == "intelligence")
        {
            ui.label("Local intelligence influenced confidence for this result.");
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Identity", |ui| {
        ui.label(format!("Name: {}", record.display_name()));
        ui.monospace(&record.path);
        if let Some(hash) = record.sha256.as_deref() {
            ui.label("SHA-256");
            ui.monospace(hash);
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Why it was flagged", |ui| {
        if record.detection_reasons.is_empty() {
            ui.label("No structured detection reasons were recorded.");
        } else {
            let mut grouped = BTreeMap::<&str, Vec<_>>::new();
            for reason in &record.detection_reasons {
                grouped.entry(&reason.source).or_default().push(reason);
            }
            let mut strongest = record
                .detection_reasons
                .iter()
                .filter(|reason| reason.weight >= 0.7)
                .collect::<Vec<_>>();
            strongest.sort_by(|left, right| right.weight.total_cmp(&left.weight));
            if !strongest.is_empty() {
                ui.label(RichText::new("Highest-confidence signals").strong());
                for reason in strongest.into_iter().take(3) {
                    signal_reason_card(ui, reason, true);
                }
                ui.add_space(6.0 * scale);
            }
            for (source, reasons) in grouped {
                ui.add_space(4.0 * scale);
                ui.label(RichText::new(source_label(source)).strong());
                for reason in reasons {
                    signal_reason_card(ui, reason, reason.weight >= 0.7);
                }
            }
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Reasoning and actions", |ui| {
        if !record.summary_text.is_empty() {
            ui.label(&record.summary_text);
        } else {
            ui.label("No summary note recorded.");
        }
        if let Some(event) = protection_event {
            ui.add_space(4.0 * scale);
            ui.label(RichText::new("Protection event").strong());
            ui.label(&event.note);
            ui.label(format!(
                "Origin: {} | Event type: {}{}",
                event.workflow_source,
                event.kind,
                if event.event_source.is_empty() {
                    String::new()
                } else {
                    format!(" | Source: {}", event.event_source)
                }
            ));
        }
        if !record.action_note.is_empty() {
            ui.add_space(4.0 * scale);
            ui.label(RichText::new("Action history").strong());
            ui.label(&record.action_note);
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Provenance and storage", |ui| {
        ui.monospace(&record.path);
        ui.label("Viewing or copying metadata does not modify local files.");
        if let Some(path) = record.quarantine_path.as_deref() {
            ui.label("Quarantine");
            ui.monospace(path);
            ui.label("Restore and delete actions modify local disk state and always require confirmation.");
        }
        if let Some(path) = record.report_path.as_deref() {
            ui.label("Report");
            ui.monospace(path);
            ui.label("Removing a report deletes stored report data only.");
        }
    });
}

fn detail_section(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    theme::card_frame().show(ui, |ui| {
        ui.label(RichText::new(title).strong());
        add_contents(ui);
    });
}

fn signal_reason_card(
    ui: &mut egui::Ui,
    reason: &crate::gui::state::DetectionReason,
    highlight: bool,
) {
    let fill = if highlight {
        egui::Color32::from_rgb(45, 36, 21)
    } else {
        egui::Color32::from_rgb(31, 37, 44)
    };
    let stroke = if highlight {
        egui::Color32::from_rgb(186, 145, 62)
    } else {
        egui::Color32::from_rgb(57, 66, 76)
    };
    egui::Frame::none()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke))
        .rounding(6.0)
        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(if reason.name.is_empty() {
                        &reason.reason_type
                    } else {
                        &reason.name
                    })
                    .strong(),
                );
                ui.small(if highlight {
                    "High confidence"
                } else if reason.weight >= 0.4 {
                    "Supporting signal"
                } else {
                    "Weak signal"
                });
            });
            let description = if reason.description.is_empty() {
                &reason.reason_type
            } else {
                &reason.description
            };
            ui.label(description);
            ui.small(format!("weight {:.2}", reason.weight));
        });
}
