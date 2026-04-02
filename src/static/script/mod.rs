pub mod batch;
pub mod charcode;
pub mod concat_eval;
pub mod detect;
pub mod javascript;
pub mod patterns;
pub mod powershell;
pub mod vba;

use super::context::ScanContext;
use super::types::Finding;

pub fn run(ctx: &mut ScanContext) {
    if !ctx.config.features.enable_script_parsing {
        return;
    }

    let values = ctx
        .text_values()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    for value in &values {
        match detect::kind(value) {
            ScriptKind::PowerShell => {
                if powershell::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "PSH_SUSPICIOUS",
                        "Suspicious PowerShell pattern detected",
                        2.0,
                    ));
                }
            }
            ScriptKind::JavaScript => {
                if javascript::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "JS_SUSPICIOUS",
                        "Suspicious JavaScript pattern detected",
                        1.5,
                    ));
                }
            }
            ScriptKind::Vba => {
                if vba::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "VBA_SUSPICIOUS",
                        "Suspicious VBA pattern detected",
                        1.5,
                    ));
                }
            }
            ScriptKind::Batch => {
                if batch::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "BAT_SUSPICIOUS",
                        "Suspicious batch pattern detected",
                        1.0,
                    ));
                }
            }
            ScriptKind::Unknown => {}
        }
    }

    if values
        .iter()
        .any(|value| charcode::contains_charcode_pattern(value))
    {
        ctx.push_finding(Finding::new(
            "SCRIPT_CHARCODE_OBFUSCATION",
            "Character-code based script obfuscation detected",
            1.0,
        ));
    }

    if values
        .iter()
        .any(|value| concat_eval::contains_concat_eval(value))
    {
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "String-concatenated eval pattern detected",
            1.5,
        ));
    }
}

pub use detect::ScriptKind;
