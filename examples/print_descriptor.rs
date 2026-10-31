//! Emit settings-only metadata for an operator-reviewed bootstrap configuration.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(&amaterasu_display_settings::descriptor::descriptor())?
    );
    Ok(())
}
