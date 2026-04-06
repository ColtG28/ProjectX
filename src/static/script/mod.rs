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

    let mut values = ctx
        .text_values()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Some(full_text) = whole_text_candidate(&ctx.bytes) {
        if !values.iter().any(|value| value == &full_text) {
            values.push(full_text);
        }
    }
    for value in &values {
        match detect::kind(value) {
            ScriptKind::PowerShell => {
                if powershell::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "PSH_SUSPICIOUS",
                        "PowerShell content includes obfuscation or download-style behavior patterns",
                        2.0,
                    ));
                }
                let strong = powershell::strong_indicators(value);
                if !strong.is_empty() {
                    ctx.push_finding(Finding::new(
                        "PSH_DOWNLOADER_CHAIN",
                        format!(
                            "PowerShell content combines encoded or automation markers into a likely downloader or launcher sequence: {}",
                            strong.join(", ")
                        ),
                        2.4,
                    ));
                }
            }
            ScriptKind::JavaScript => {
                if javascript::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "JS_SUSPICIOUS",
                        "JavaScript content includes obfuscation or browser automation patterns",
                        1.5,
                    ));
                }
                let strong = javascript::strong_indicators(value);
                if !strong.is_empty() {
                    ctx.push_finding(Finding::new(
                        "JS_DOWNLOADER_CHAIN",
                        format!(
                            "JavaScript content combines launcher or downloader markers into a likely staged script chain: {}",
                            strong.join(", ")
                        ),
                        2.3,
                    ));
                }
            }
            ScriptKind::Vba => {
                if vba::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "VBA_SUSPICIOUS",
                        "VBA content includes auto-run or file/network automation patterns",
                        1.5,
                    ));
                }
                let strong = vba::strong_indicators(value);
                if !strong.is_empty() {
                    ctx.push_finding(Finding::new(
                        "VBA_AUTORUN_DOWNLOAD_CHAIN",
                        format!(
                            "VBA content combines auto-run behavior with network or launcher automation: {}",
                            strong.join(", ")
                        ),
                        2.4,
                    ));
                }
            }
            ScriptKind::Batch => {
                if batch::is_suspicious(value) {
                    ctx.push_finding(Finding::new(
                        "BAT_SUSPICIOUS",
                        "Batch script includes chaining or command-launch patterns often used in droppers",
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
            "Script reconstructs text from character codes, which often hides intent",
            1.0,
        ));
    }

    if values
        .iter()
        .any(|value| concat_eval::contains_concat_eval(value))
    {
        ctx.push_finding(Finding::new(
            "SCRIPT_CONCAT_EVAL",
            "Script builds code from string fragments before evaluating it",
            1.5,
        ));
    }
}

pub use detect::ScriptKind;

fn whole_text_candidate(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).to_string();
    let trimmed = text.trim();
    if trimmed.len() < 8 {
        return None;
    }

    let chars = trimmed.chars().count().max(1);
    let printable = trimmed
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\r' | '\t'))
        .count();

    (printable * 100 / chars >= 85).then(|| trimmed.to_string())
}
