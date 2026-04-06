use eframe::egui;

use crate::gui::state::{ReportSortOrder, ReportStorageFilter, ReportVerdictFilter};

#[derive(Debug, Default, Clone, Copy)]
pub struct WorkspaceToolbarResponse {
    pub select_all_shown: bool,
    pub clear_shown: bool,
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
    allow_bulk_delete: bool,
    note: &str,
) -> WorkspaceToolbarResponse {
    let mut response = WorkspaceToolbarResponse::default();

    ui.add_sized(
        [ui.available_width().min(420.0), 0.0],
        egui::TextEdit::singleline(search).hint_text(placeholder),
    );
    ui.horizontal_wrapped(|ui| {
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
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("Showing {} result(s)", shown_count));
        if let Some(selected_visible) = selected_visible {
            ui.label(format!("Selected visible: {}", selected_visible));
            if ui.button("Select all shown").clicked() {
                response.select_all_shown = true;
            }
            if ui.button("Clear shown").clicked() {
                response.clear_shown = true;
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
        ui.label(note);
    });

    response
}
