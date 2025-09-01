use eframe::egui;
use eframe::egui::{CentralPanel};

pub fn gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "My egui App",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::default()))),
    )
}

struct MyApp {
    my_string: String,
    my_f32: f32,
    my_boolean: bool,
    my_enum: Enum,
    my_image: egui::TextureId,
}

#[derive(PartialEq)]
enum Enum {
    First,
    Second,
    Third,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            my_string: "Hello".to_owned(),
            my_f32: 42.0,
            my_boolean: false,
            my_enum: Enum::First,
            // For demo purposes, just use a placeholder texture id.
            // In a real app, you’d load an image into a texture.
            my_image: egui::TextureId::Managed(0),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ui.add(egui::Label::new("Hello World!"));
            ui.label("A shorter and more convenient way to add a label.");
            if ui.button("Click me").clicked() {
                // take some action here
                self.my_boolean = !self.my_boolean;
            }

            ui.label("This is a label");
            ui.hyperlink("https://github.com/emilk/egui");
            ui.text_edit_singleline(&mut self.my_string);

            if ui.button("Click me again").clicked() {}

            ui.add(egui::Slider::new(&mut self.my_f32, 0.0..=100.0));
            ui.add(egui::DragValue::new(&mut self.my_f32));

            ui.checkbox(&mut self.my_boolean, "Checkbox");

            ui.horizontal(|ui| {
                ui.radio_value(&mut self.my_enum, Enum::First, "First");
                ui.radio_value(&mut self.my_enum, Enum::Second, "Second");
                ui.radio_value(&mut self.my_enum, Enum::Third, "Third");
            });

            ui.separator();

            ui.image((self.my_image, egui::Vec2::new(640.0, 280.0)));

            ui.collapsing("Click to see what is hidden!", |ui| {
                ui.label("Not much, as it turns out");
            });
        });
    }
}
