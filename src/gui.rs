use eframe::*;
use egui:: CentralPanel;

struct MyApp{}

impl eframe:: App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        CentralPanel::default().show(ctx, add_contents: |ui: &mut Ui| {
            ui. label(text: "Hello, World!");
        });
    }
}

pub fn gui() -> eframe::Result<(), eframe::Error> {
    run_native(
        app_name: "My App",
        NativeOptions::default(),
        app_creator: Box::new(|_cc: &CreationContext<'_>| {
            Box::new(MyApp {})
        }),
    )
}