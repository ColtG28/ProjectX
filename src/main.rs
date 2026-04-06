fn main() {
    dotenvy::dotenv().ok();

    if let Err(error) = projectx::r#static::init_quarantine() {
        eprintln!("Failed to initialize ProjectX storage: {error}");
        return;
    }

    if let Err(error) = projectx::gui::gui() {
        eprintln!("Failed to launch ProjectX GUI: {error}");
    }
}
