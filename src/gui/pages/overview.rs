use eframe::egui;
use egui::{Color32, Layout};

use crate::gui::app::{
    draw_pie_chart, draw_segment_bar, now_epoch, render_chart_legend, summarize_record_refs,
};
use crate::gui::components::summary_chip::stat_chip;
use crate::gui::state::{MyApp, TimePeriod};
use crate::gui::theme;

impl MyApp {
    pub fn render_analytics(&mut self, ui: &mut egui::Ui) {
        ui.heading("Security Overview");
        ui.separator();

        let now = now_epoch();
        let cutoff = self.period.cutoff_epoch(now);
        let filtered = self
            .records
            .iter()
            .filter(|record| record.scanned_at_epoch >= cutoff)
            .collect::<Vec<_>>();
        let metrics = summarize_record_refs(&filtered);

        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = theme::badge_spacing(self.ui_metrics.scale_factor);
            stat_chip(
                ui,
                "Files scanned",
                metrics.total.to_string(),
                Color32::from_rgb(176, 221, 255),
            );
            stat_chip(
                ui,
                "Clean",
                metrics.clean.to_string(),
                Color32::from_rgb(127, 191, 127),
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
                "Warnings",
                metrics.warning_total.to_string(),
                Color32::from_rgb(224, 185, 105),
            );
        });

        ui.separator();
        ui.columns(2, |columns| {
            theme::card_frame().show(&mut columns[0], |ui| {
                ui.set_width(ui.available_width());
                theme::card_title(ui, "Verdict distribution", self.ui_metrics.scale_factor);
                let segments = [
                    ("Clean", metrics.clean, Color32::from_rgb(127, 191, 127)),
                    (
                        "Malicious",
                        metrics.malicious,
                        Color32::from_rgb(216, 100, 100),
                    ),
                    (
                        "Suspicious",
                        metrics.suspicious,
                        Color32::from_rgb(224, 185, 105),
                    ),
                    ("Errors", metrics.errors, Color32::from_rgb(170, 170, 180)),
                ];
                draw_pie_chart(ui, "verdict_pie", &segments);
                ui.add_space(theme::card_section_gap(self.ui_metrics.scale_factor));
                render_chart_legend(ui, &segments);
            });
            theme::card_frame().show(&mut columns[1], |ui| {
                ui.set_width(ui.available_width());
                theme::card_title(ui, "Storage and severity", self.ui_metrics.scale_factor);
                let segments = [
                    (
                        "In quarantine",
                        metrics.in_quarantine,
                        Color32::from_rgb(132, 170, 214),
                    ),
                    (
                        "Restored",
                        metrics.restored,
                        Color32::from_rgb(127, 191, 127),
                    ),
                    ("Deleted", metrics.deleted, Color32::from_rgb(160, 160, 165)),
                ];
                draw_segment_bar(ui, &segments);
                ui.add_space(theme::card_section_gap(self.ui_metrics.scale_factor));
                render_chart_legend(ui, &segments);
                ui.with_layout(Layout::right_to_left(egui::Align::Min), |ui| {
                    egui::ComboBox::from_id_source("analytics_period")
                        .selected_text(self.period.label())
                        .show_ui(ui, |ui| {
                            for period in [
                                TimePeriod::Last24Hours,
                                TimePeriod::Last7Days,
                                TimePeriod::Last30Days,
                                TimePeriod::AllTime,
                            ] {
                                ui.selectable_value(&mut self.period, period, period.label());
                            }
                        });
                });
            });
        });
        ui.separator();
    }
}
