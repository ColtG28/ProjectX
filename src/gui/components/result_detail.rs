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
    wrapped_text(
        ui,
        "Pinned result summary, strongest signals, and safe follow-up context.",
    );
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
            wrapped_text(
                ui,
                format!(
                    "Protection event: {} | {} | {} | {} priority",
                    event.kind,
                    event.change_class.label(),
                    event.file_class.label(),
                    event.priority.label()
                ),
            );
            wrapped_text(
                ui,
                format!(
                    "Protection path: {}",
                    if event.workflow_source.is_empty() {
                        "Automatic scan".to_string()
                    } else {
                        event.workflow_source.clone()
                    }
                ),
            );
            if event.grouped_change_count > 1 || event.burst_window_seconds > 0 {
                wrapped_text(
                    ui,
                    format!(
                        "Grouped {} change(s) across {}s before this scan.",
                        event.grouped_change_count, event.burst_window_seconds
                    ),
                );
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
        if let Some(primary_reason) = primary_reason_summary(record) {
            wrapped_text(ui, format!("Primary reason: {primary_reason}"));
        }
        wrapped_text(
            ui,
            format!("Signal profile: {}", signal_profile_label(record)),
        );
        if record
            .signal_sources
            .iter()
            .any(|source| source == "intelligence")
        {
            wrapped_text(
                ui,
                "Local intelligence influenced confidence for this result.",
            );
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Identity", |ui| {
        wrapped_text(ui, format!("Name: {}", record.display_name()));
        clipped_monospace(ui, &record.path);
        if let Some(hash) = record.sha256.as_deref() {
            ui.label("SHA-256");
            clipped_monospace(ui, hash);
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Why it was flagged", |ui| {
        if record.detection_reasons.is_empty() {
            wrapped_text(ui, "No structured detection reasons were recorded.");
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
            wrapped_text(ui, &record.summary_text);
        } else {
            wrapped_text(ui, "No summary note recorded.");
        }
        if let Some(event) = protection_event {
            ui.add_space(4.0 * scale);
            ui.label(RichText::new("Protection event").strong());
            wrapped_text(ui, &event.note);
            wrapped_text(
                ui,
                format!(
                    "Origin: {} | Event type: {}{}",
                    event.workflow_source,
                    event.kind,
                    if event.event_source.is_empty() {
                        String::new()
                    } else {
                        format!(" | Source: {}", event.event_source)
                    }
                ),
            );
        }
        if !record.action_note.is_empty() {
            ui.add_space(4.0 * scale);
            ui.label(RichText::new("Action history").strong());
            wrapped_text(ui, &record.action_note);
        }
    });

    ui.add_space(8.0 * scale);
    detail_section(ui, "Provenance and storage", |ui| {
        clipped_monospace(ui, &record.path);
        ui.label(format!(
            "Disposition: {}",
            record.resolved_storage_state().label()
        ));
        wrapped_text(
            ui,
            "Viewing or copying metadata does not modify local files.",
        );
        if !record.action_note.is_empty() {
            ui.add_space(4.0 * scale);
            wrapped_text(ui, &record.action_note);
        }
        if let Some(path) = record.quarantine_path.as_deref() {
            ui.label("Quarantine");
            clipped_monospace(ui, path);
            wrapped_text(
                ui,
                "Restore and delete actions modify local disk state and always require confirmation.",
            );
        } else {
            wrapped_text(
                ui,
                "No retained quarantine copy is associated with this result.",
            );
        }
        if let Some(path) = record.report_path.as_deref() {
            ui.label("Report");
            clipped_monospace(ui, path);
            wrapped_text(ui, "Removing a report deletes stored report data only.");
        }
    });
}

fn detail_section(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_max_width(ui.available_width());
        ui.label(RichText::new(title).strong());
        add_contents(ui);
    });
}

fn clipped_monospace(ui: &mut egui::Ui, text: &str) {
    ui.add_sized(
        [ui.available_width(), 0.0],
        egui::Label::new(RichText::new(text).monospace()).truncate(true),
    )
    .on_hover_text(text);
}

fn wrapped_text(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>) {
    ui.add(egui::Label::new(text).wrap(true));
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
            wrapped_text(ui, description);
            ui.small(format!("weight {:.2}", reason.weight));
        });
}

fn primary_reason_summary(record: &ScanRecord) -> Option<String> {
    let mut reasons = record.detection_reasons.iter().collect::<Vec<_>>();
    reasons.sort_by(|left, right| right.weight.total_cmp(&left.weight));
    reasons.first().map(|reason| {
        if !reason.name.trim().is_empty() {
            reason.name.clone()
        } else if !reason.reason_type.trim().is_empty() {
            reason.reason_type.clone()
        } else {
            "Unknown reason".to_string()
        }
    })
}

fn signal_profile_label(record: &ScanRecord) -> String {
    if record.detection_reasons.is_empty() {
        return "No structured detection reasons recorded".to_string();
    }

    let sources = record
        .detection_reasons
        .iter()
        .map(|reason| {
            if reason.source.is_empty() {
                "unknown"
            } else {
                reason.source.as_str()
            }
        })
        .collect::<std::collections::BTreeSet<_>>();
    let strongest = record
        .detection_reasons
        .iter()
        .map(|reason| reason.weight)
        .fold(0.0, f64::max);
    let trust_context = if record
        .signal_sources
        .iter()
        .any(|source| source == "intelligence")
    {
        " with trust/provenance context"
    } else {
        ""
    };

    if sources.len() <= 1 && strongest < 0.9 {
        format!("Single-source weak signal{trust_context}")
    } else if sources.len() >= 2 || strongest >= 1.1 {
        format!("Corroborated detection path{trust_context}")
    } else {
        format!("Supporting signal path{trust_context}")
    }
}
