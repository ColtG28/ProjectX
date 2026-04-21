use eframe::egui;

use crate::gui::state::{ReportSortOrder, ReportStorageFilter, ReportVerdictFilter};

#[derive(Debug, Default, Clone, Copy)]
pub struct WorkspaceToolbarResponse {
    pub select_all_shown: bool,
    pub clear_shown: bool,
    pub restore_selected_quarantined: bool,
    pub delete_selected_reports: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn render_record_workspace_toolbar(
    ui: &mut egui::Ui,
    search: &mut String,
    placeholder: &str,
    verdict_filter: &mut ReportVerdictFilter,
    storage_filter: &mut ReportStorageFilter,
    sort_order: &mut ReportSortOrder,
    quarantine_only: Option<&mut bool>,
    shown_count: usize,
    selected_visible: Option<usize>,
    selected_quarantined_visible: Option<usize>,
    allow_bulk_delete: bool,
    allow_bulk_restore: bool,
) -> WorkspaceToolbarResponse {
    let mut response = WorkspaceToolbarResponse::default();

    ui.group(|ui| {
        ui.add_sized(
            [ui.available_width().min(460.0), 0.0],
            egui::TextEdit::singleline(search).hint_text(placeholder),
        );
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label("Verdict");
            egui::ComboBox::from_id_source(ui.id().with("verdict_filter"))
                .selected_text(verdict_filter.label())
                .show_ui(ui, |ui| {
                    for filter in [
                        ReportVerdictFilter::All,
                        ReportVerdictFilter::Clean,
                        ReportVerdictFilter::Malicious,
                        ReportVerdictFilter::Suspicious,
                        ReportVerdictFilter::Error,
                    ] {
                        ui.selectable_value(verdict_filter, filter, filter.label());
                    }
                });
            ui.label("Storage");
            egui::ComboBox::from_id_source(ui.id().with("storage_filter"))
                .selected_text(storage_filter.label())
                .show_ui(ui, |ui| {
                    for filter in [
                        ReportStorageFilter::All,
                        ReportStorageFilter::InQuarantine,
                        ReportStorageFilter::Restored,
                        ReportStorageFilter::Deleted,
                        ReportStorageFilter::Unknown,
                    ] {
                        ui.selectable_value(storage_filter, filter, filter.label());
                    }
                });
            ui.label("Sort");
            egui::ComboBox::from_id_source(ui.id().with("sort_order"))
                .selected_text(sort_order.label())
                .show_ui(ui, |ui| {
                    for sort in [
                        ReportSortOrder::NewestFirst,
                        ReportSortOrder::OldestFirst,
                        ReportSortOrder::SeverityFirst,
                        ReportSortOrder::Name,
                    ] {
                        ui.selectable_value(sort_order, sort, sort.label());
                    }
                });
            if let Some(quarantine_only) = quarantine_only {
                ui.checkbox(quarantine_only, "Quarantined only");
            }
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("Showing {} item(s)", shown_count));
            if let Some(selected_visible) = selected_visible {
                ui.label(format!("Selected visible: {}", selected_visible));
                if ui.button("Select all").clicked() {
                    response.select_all_shown = true;
                }
                if ui.button("Clear selection").clicked() {
                    response.clear_shown = true;
                }
                if ui
                    .add_enabled(
                        allow_bulk_restore && selected_quarantined_visible.unwrap_or(0) > 0,
                        egui::Button::new("Restore selected quarantined"),
                    )
                    .clicked()
                {
                    response.restore_selected_quarantined = true;
                }
                if ui
                    .add_enabled(
                        allow_bulk_delete && selected_visible > 0,
                        egui::Button::new("Delete selected reports"),
                    )
                    .clicked()
                {
                    response.delete_selected_reports = true;
                }
            }
        });
        ui.add_space(2.0);
    });

    response
}
