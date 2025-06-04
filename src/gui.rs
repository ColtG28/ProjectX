use eframe::*;
use egui::{CentralPanel, Ui};

struct MyApp {}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        CentralPanel::default().show(ctx, |ui: &mut Ui| {
            ui.label("Hello, World!");
        });
    }
}

pub fn gui() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();

    eframe::run_native(
        "ProjectX Security System",
        native_options,
        Box::new(|_cc: &CreationContext<'_>| Ok(Box::new(MyApp {}))),
    )
}