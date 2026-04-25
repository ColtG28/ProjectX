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

pub fn copy_result_detail_text(
    record: &ScanRecord,
    protection_event: Option<&ProtectionEvent>,
) -> String {
    let mut lines = vec![
        "Summary".to_string(),
        format!("Verdict: {}", record.verdict.label()),
        format!("Severity: {}", record.severity.label()),
        format!("Disposition: {}", record.resolved_storage_state().label()),
        format!(
            "File size: {}",
            crate::gui::app::format_bytes(record.file_size_bytes)
        ),
        format!(
            "Scanned at: {}",
            format_timestamp_with_relative(record.scanned_at_epoch)
        ),
        format!("Scan duration: {}", format_elapsed_ms(record.duration_ms)),
    ];

    if !record.signal_sources.is_empty() {
        lines.push(format!(
            "Signal sources: {}",
            record.signal_sources.join(", ")
        ));
    }
    if let Some(mime) = record.sniffed_mime.as_deref() {
        lines.push(format!("MIME: {mime}"));
    }
    if let Some(format_name) = record.detected_format.as_deref() {
        lines.push(format!("Detected format: {format_name}"));
    }
    if let Some(origin) = record.workflow_origin.as_deref() {
        lines.push(format!("Workflow: {origin}"));
    }
    if let Some(event) = protection_event {
        lines.push(format!(
            "Protection event: {} | {} | {} | {} priority",
            event.kind,
            event.change_class.label(),
            event.file_class.label(),
            event.priority.label()
        ));
        lines.push(format!(
            "Protection path: {}",
            if event.workflow_source.is_empty() {
                "Automatic scan".to_string()
            } else {
                event.workflow_source.clone()
            }
        ));
        if event.grouped_change_count > 1 || event.burst_window_seconds > 0 {
            lines.push(format!(
                "Grouped {} change(s) across {}s before this scan.",
                event.grouped_change_count, event.burst_window_seconds
            ));
        }
        if let Some(verdict) = event.verdict.as_deref() {
            lines.push(format!("Protection result: {verdict}"));
        }
        if let Some(action) = event.storage_state.as_deref() {
            lines.push(format!("Protection action: {action}"));
        }
        if !event.event_source.is_empty() {
            lines.push(format!("Event source: {}", event.event_source));
        }
    }
    if let Some(risk) = record.risk_score {
        lines.push(format!("Risk score: {risk:.2}"));
    }
    if let Some(safety) = record.safety_score {
        lines.push(format!("Safety score: {safety:.2}"));
    }
    if let Some(primary_reason) = primary_reason_summary(record) {
        lines.push(format!(
            "{}: {primary_reason}",
            primary_reason_label(record)
        ));
    }
    lines.push(format!("Signal profile: {}", signal_profile_label(record)));
    if let Some(note) = signal_outcome_note(record) {
        lines.push(note);
    }
    if record
        .signal_sources
        .iter()
        .any(|source| source == "intelligence")
    {
        lines.push("Local intelligence influenced confidence for this result.".to_string());
    }

    lines.push(String::new());
    lines.push(reason_section_title(record).to_string());
    if record.detection_reasons.is_empty() {
        lines.push(reason_section_empty_state(record).to_string());
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
            lines.push(reason_highlight_title(record).to_string());
            for reason in strongest.into_iter().take(3) {
                lines.push(format_reason_line(record, reason, true));
            }
        }
        for (source, reasons) in grouped {
            lines.push(source_label(source).to_string());
            for reason in reasons {
                lines.push(format_reason_line(record, reason, reason.weight >= 0.7));
            }
        }
    }

    lines.push(String::new());
    lines.push("Reasoning and actions".to_string());
    if !record.summary_text.is_empty() {
        lines.push(record.summary_text.clone());
    } else {
        lines.push("No summary note recorded.".to_string());
    }
    if let Some(event) = protection_event {
        lines.push("Protection event".to_string());
        lines.push(event.note.clone());
        lines.push(format!(
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
        lines.push("Action history".to_string());
        lines.push(record.action_note.clone());
    }

    lines.push(String::new());
    lines.push("Provenance and storage".to_string());
    lines.push(format!("Path: {}", record.path));
    if let Some(hash) = record.sha256.as_deref() {
        lines.push(format!("SHA-256: {hash}"));
    }
    lines.push(format!(
        "Viewing or copying metadata does not modify local files."
    ));
    if let Some(path) = record.quarantine_path.as_deref() {
        lines.push(format!("Quarantine: {path}"));
        lines.push(
            "Restore and delete actions modify local disk state and always require confirmation."
                .to_string(),
        );
    } else {
        lines.push("No retained quarantine copy is associated with this result.".to_string());
    }
    if let Some(path) = record.report_path.as_deref() {
        lines.push(format!("Report: {path}"));
        lines.push("Removing a report deletes stored report data only.".to_string());
    }

    lines.join("\n")
}

pub fn render_result_detail(
    ui: &mut egui::Ui,
    scale: f32,
    record: &ScanRecord,
    protection_event: Option<&ProtectionEvent>,
) {
    detail_section(ui, "Summary", scale, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = theme::badge_spacing(scale);
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
            wrapped_text(
                ui,
                format!("{}: {primary_reason}", primary_reason_label(record)),
            );
        }
        wrapped_text(
            ui,
            format!("Signal profile: {}", signal_profile_label(record)),
        );
        if let Some(note) = signal_outcome_note(record) {
            wrapped_text(ui, note);
        }
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

    ui.add_space(theme::card_section_gap(scale));
    detail_section(ui, reason_section_title(record), scale, |ui| {
        if record.detection_reasons.is_empty() {
            wrapped_text(ui, reason_section_empty_state(record));
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
                theme::section_title(ui, reason_highlight_title(record), scale);
                for reason in strongest.into_iter().take(3) {
                    signal_reason_card(ui, record, reason, true);
                }
                ui.add_space(theme::card_row_gap(scale));
            }
            for (source, reasons) in grouped {
                ui.add_space(theme::card_row_gap(scale));
                theme::section_title(ui, source_label(source), scale);
                for reason in reasons {
                    signal_reason_card(ui, record, reason, reason.weight >= 0.7);
                }
            }
        }
    });

    ui.add_space(theme::card_section_gap(scale));
    detail_section(ui, "Reasoning and actions", scale, |ui| {
        if !record.summary_text.is_empty() {
            wrapped_text(ui, &record.summary_text);
        } else {
            wrapped_text(ui, "No summary note recorded.");
        }
        if let Some(event) = protection_event {
            ui.add_space(theme::card_row_gap(scale));
            theme::section_title(ui, "Protection event", scale);
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
            ui.add_space(theme::card_row_gap(scale));
            theme::section_title(ui, "Action history", scale);
            wrapped_text(ui, &record.action_note);
        }
    });

    ui.add_space(theme::card_section_gap(scale));
    detail_section(ui, "Provenance and storage", scale, |ui| {
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
            ui.add_space(theme::card_row_gap(scale));
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

fn detail_section(
    ui: &mut egui::Ui,
    title: &str,
    scale: f32,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.set_max_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = theme::card_row_gap(scale);
        theme::card_title(ui, title, scale);
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
    record: &ScanRecord,
    reason: &crate::gui::state::DetectionReason,
    highlight: bool,
) {
    let fill = if highlight {
        egui::Color32::from_rgb(45, 36, 21)
    } else {
        theme::SUBTLE_FILL
    };
    let stroke = if highlight {
        egui::Color32::from_rgb(186, 145, 62)
    } else {
        theme::SUBTLE_STROKE
    };
    egui::Frame::none()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke))
        .rounding(6.0)
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = theme::card_row_gap(1.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = theme::badge_spacing(1.0);
                ui.label(
                    RichText::new(if reason.name.is_empty() {
                        &reason.reason_type
                    } else {
                        &reason.name
                    })
                    .strong(),
                );
                ui.small(reason_impact_label(record, reason, highlight));
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

fn format_reason_line(
    record: &ScanRecord,
    reason: &crate::gui::state::DetectionReason,
    highlight: bool,
) -> String {
    let label = if reason.name.is_empty() {
        &reason.reason_type
    } else {
        &reason.name
    };
    let description = if reason.description.is_empty() {
        &reason.reason_type
    } else {
        &reason.description
    };

    format!(
        "- {label} | {} | weight {:.2} | {description}",
        reason_impact_label(record, reason, highlight),
        reason.weight
    )
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

fn is_flagged_result(record: &ScanRecord) -> bool {
    matches!(
        record.verdict,
        crate::gui::state::Verdict::Suspicious | crate::gui::state::Verdict::Malicious
    )
}

fn primary_reason_label(record: &ScanRecord) -> &'static str {
    if is_flagged_result(record) {
        "Primary reason"
    } else {
        "Observed signal"
    }
}

fn reason_section_title(record: &ScanRecord) -> &'static str {
    if is_flagged_result(record) {
        "Why it was flagged"
    } else {
        "Signals observed"
    }
}

fn reason_highlight_title(record: &ScanRecord) -> &'static str {
    if is_flagged_result(record) {
        "Highest-confidence signals"
    } else {
        "Most notable observed signals"
    }
}

fn reason_section_empty_state(record: &ScanRecord) -> &'static str {
    if is_flagged_result(record) {
        "No structured detection reasons were recorded."
    } else {
        "No concerning signals were recorded."
    }
}

fn signal_outcome_note(record: &ScanRecord) -> Option<String> {
    if record.verdict == crate::gui::state::Verdict::Clean && !record.detection_reasons.is_empty() {
        Some(
            "Not flagged. Passive analysis observed this signal, but the score stayed low and no suspicious verdict was produced."
                .to_string(),
        )
    } else {
        None
    }
}

fn reason_impact_label(
    record: &ScanRecord,
    reason: &crate::gui::state::DetectionReason,
    highlight: bool,
) -> &'static str {
    if record.verdict == crate::gui::state::Verdict::Clean {
        if highlight || reason.weight >= 1.0 {
            "Observed but suppressed"
        } else if reason.weight >= 0.4 {
            "Low-risk observation"
        } else {
            "Did not affect final verdict significantly"
        }
    } else if highlight {
        "High confidence"
    } else if reason.weight >= 0.4 {
        "Supporting signal"
    } else {
        "Weak signal"
    }
}

fn signal_profile_label(record: &ScanRecord) -> String {
    if record.detection_reasons.is_empty() {
        return if record.verdict == crate::gui::state::Verdict::Clean {
            "No concerning signals".to_string()
        } else {
            "No structured detection reasons recorded".to_string()
        };
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
    let signal_count = record.detection_reasons.len();
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
    let risk = record.risk_score.unwrap_or(0.0);

    if is_common_macho_runtime_profile(record) {
        return format!("Common runtime behavior{trust_context}");
    }

    if record.verdict == crate::gui::state::Verdict::Clean {
        if risk <= 0.25 || signal_count > 1 || sources.len() > 1 || strongest < 0.7 {
            format!("Low-risk observed signal{trust_context}")
        } else {
            format!("Single-source weak signal{trust_context}")
        }
    } else if sources.len() >= 2 || signal_count >= 2 {
        format!("Corroborated suspicious signal{trust_context}")
    } else if strongest < 0.9 {
        format!("Single-source weak signal{trust_context}")
    } else {
        format!("Single-source suspicious signal{trust_context}")
    }
}

fn is_common_macho_runtime_profile(record: &ScanRecord) -> bool {
    let mut has_macho_runtime = false;
    let mut has_suspicious_other = false;

    for reason in &record.detection_reasons {
        let normalized = reason.name.to_ascii_lowercase();
        let description = reason.description.to_ascii_lowercase();
        let is_macho_runtime = normalized.contains("macho dynamic loader chain")
            || normalized.contains("macho exec network chain")
            || description.contains("dynamic loader runtime behavior")
            || description.contains("execution and network runtime behavior")
            || (description.contains("mach-o")
                && (description.contains("runtime")
                    || description.contains("linked libraries")
                    || description.contains("network communication markers")));

        if is_macho_runtime {
            has_macho_runtime = true;
        } else if reason.weight > 0.0 && reason.source != "intelligence" {
            has_suspicious_other = true;
        }
    }

    has_macho_runtime && !has_suspicious_other
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::state::{RecordStorageState, SeverityLevel, Verdict};

    fn sample_record() -> ScanRecord {
        ScanRecord {
            scan_id: "scan-1".to_string(),
            path: "/tmp/suspicious.bin".to_string(),
            file_name: "suspicious.bin".to_string(),
            extension: Some("bin".to_string()),
            sha256: Some("a".repeat(64)),
            sniffed_mime: Some("application/octet-stream".to_string()),
            detected_format: Some("PE32".to_string()),
            quarantine_path: Some("/tmp/quarantine/suspicious.bin".to_string()),
            report_path: Some("/tmp/reports/suspicious.json".to_string()),
            storage_state: RecordStorageState::InQuarantine,
            quarantine: Default::default(),
            last_modified_epoch: 0,
            scanned_at_epoch: 1_700_000_000,
            started_at_epoch: None,
            finished_at_epoch: None,
            duration_ms: 1250,
            file_size_bytes: 2048,
            verdict: Verdict::Suspicious,
            severity: SeverityLevel::Medium,
            summary_text: "Structured summary".to_string(),
            action_note: "Analyst left the file in quarantine.".to_string(),
            workflow_origin: Some("Manual scan".to_string()),
            risk_score: Some(0.82),
            safety_score: Some(0.18),
            signal_sources: vec!["heuristic".to_string(), "intelligence".to_string()],
            detection_reasons: vec![crate::gui::state::DetectionReason {
                reason_type: "rule".to_string(),
                source: "rule".to_string(),
                name: "Known bad marker".to_string(),
                description: "Matched a suspicious rule".to_string(),
                weight: 0.91,
            }],
            warning_count: 1,
            error_count: 0,
        }
    }

    fn clean_observed_signal_record() -> ScanRecord {
        let mut record = sample_record();
        record.path = "/tmp/ext/_locales/cs/messages.json".to_string();
        record.file_name = "messages.json".to_string();
        record.extension = Some("json".to_string());
        record.sniffed_mime = Some("application/json".to_string());
        record.detected_format = Some("Extension Locale JSON".to_string());
        record.quarantine_path = None;
        record.storage_state = RecordStorageState::Restored;
        record.verdict = Verdict::Clean;
        record.severity = SeverityLevel::Clean;
        record.summary_text =
            "Passive analysis observed a low-risk signal, but no suspicious verdict was produced."
                .to_string();
        record.action_note =
            "Temporarily staged in ProjectX quarantine for safe analysis, then restored to the original path after scanning finished."
                .to_string();
        record.risk_score = Some(0.0);
        record.safety_score = Some(10.0);
        record.signal_sources = vec!["heuristic".to_string()];
        record.detection_reasons = vec![crate::gui::state::DetectionReason {
            reason_type: "heuristic".to_string(),
            source: "heuristic".to_string(),
            name: "Decoded Active Content".to_string(),
            description: "Observed a decoded script-like string in an otherwise clean JSON file."
                .to_string(),
            weight: 1.50,
        }];
        record.warning_count = 1;
        record
    }

    fn clean_macho_runtime_app_record() -> ScanRecord {
        let mut record = sample_record();
        record.path = "/Applications/ProjectX.app/Contents/MacOS/ProjectX".to_string();
        record.file_name = "ProjectX".to_string();
        record.detected_format = Some("Mach-O".to_string());
        record.quarantine_path = None;
        record.storage_state = RecordStorageState::Restored;
        record.verdict = Verdict::Clean;
        record.severity = SeverityLevel::Clean;
        record.risk_score = Some(0.8);
        record.safety_score = Some(9.2);
        record.signal_sources = vec!["format".to_string(), "intelligence".to_string()];
        record.detection_reasons = vec![
            crate::gui::state::DetectionReason {
                reason_type: "format".to_string(),
                source: "format".to_string(),
                name: "Macho Dynamic Loader Chain".to_string(),
                description: "Observed Mach-O dynamic loader runtime behavior".to_string(),
                weight: 2.4,
            },
            crate::gui::state::DetectionReason {
                reason_type: "format".to_string(),
                source: "format".to_string(),
                name: "Macho Exec Network Chain".to_string(),
                description: "Observed Mach-O execution and network runtime behavior".to_string(),
                weight: 2.1,
            },
            crate::gui::state::DetectionReason {
                reason_type: "intelligence".to_string(),
                source: "intelligence".to_string(),
                name: "Trust Benign Tooling Context".to_string(),
                description:
                    "Runtime path context recognized an installed macOS app bundle [medium_trust]"
                        .to_string(),
                weight: 0.0,
            },
        ];
        record
    }

    #[test]
    fn copied_detail_text_includes_main_sections() {
        let text = copy_result_detail_text(&sample_record(), None);
        assert!(!text.contains("Detailed Report"));
        assert!(text.contains("Summary"));
        assert!(text.contains("Why it was flagged"));
        assert!(text.contains("Reasoning and actions"));
        assert!(text.contains("Provenance and storage"));
        assert!(text.contains("Path: /tmp/suspicious.bin"));
    }

    #[test]
    fn clean_result_uses_observed_signal_language() {
        let text = copy_result_detail_text(&clean_observed_signal_record(), None);
        assert!(text.contains("Signals observed"));
        assert!(!text.contains("Why it was flagged"));
        assert!(text.contains("Observed signal: Decoded Active Content"));
        assert!(text.contains("Not flagged."));
        assert!(text.contains("Detected format: Extension Locale JSON"));
    }

    #[test]
    fn clean_result_uses_low_risk_signal_profile() {
        let text = copy_result_detail_text(&clean_observed_signal_record(), None);
        assert!(text.contains("Signal profile: Low-risk observed signal"));
        assert!(!text.contains("Corroborated suspicious signal"));
        assert!(!text.contains("Corroborated detection path"));
        assert!(text.contains("Observed but suppressed"));
        assert!(!text.contains("High confidence"));
    }

    #[test]
    fn macho_runtime_pair_uses_common_runtime_signal_profile() {
        let text = copy_result_detail_text(&clean_macho_runtime_app_record(), None);
        assert!(
            text.contains("Signal profile: Common runtime behavior with trust/provenance context")
        );
        assert!(!text.contains("Corroborated suspicious signal"));
    }

    #[test]
    fn clean_result_uses_temporary_staging_wording() {
        let text = copy_result_detail_text(&clean_observed_signal_record(), None);
        assert!(text.contains("Temporarily staged in ProjectX quarantine for safe analysis"));
        assert!(!text.contains("Moved into ProjectX quarantine for analysis"));
    }

    #[test]
    fn suspicious_result_keeps_flagged_language() {
        let text = copy_result_detail_text(&sample_record(), None);
        assert!(text.contains("Why it was flagged"));
        assert!(text.contains("Primary reason: Known bad marker"));
    }
}
