pub mod base64;
pub mod detect;
pub mod gzip;
pub mod hex;
pub mod html;
pub mod rot13;
pub mod url;
pub mod xor;
pub mod zlib;

use super::context::ScanContext;
use super::script::patterns;
use super::strings::dedupe;
use super::types::Finding;

pub fn run(ctx: &mut ScanContext) {
    let mut decoded = Vec::new();
    let inputs = ctx.text_values();
    let decode_limit = ctx.config.limits.max_decoded_strings;

    for value in inputs.iter().take(ctx.config.limits.max_string_values) {
        if detect::should_try(value) {
            decoded.extend(base64::try_decode(value));
            decoded.extend(hex::try_decode(value));
            decoded.extend(url::try_decode(value));
            decoded.extend(html::decode_entities(value));
            let rot13 = rot13::decode(value);
            if rot13 != *value && looks_meaningful(&rot13) {
                decoded.push(rot13);
            }
        }
        if decoded.len() >= decode_limit {
            decoded.truncate(decode_limit);
            ctx.log_event(
                "decode",
                format!("Decoded output capped at {} values", decode_limit),
            );
            break;
        }
    }

    let mut first_pass = dedupe::stable_dedupe(
        decoded
            .into_iter()
            .filter(|value| looks_meaningful(value))
            .collect(),
    );
    if first_pass.len() > decode_limit {
        first_pass.truncate(decode_limit);
    }
    if first_pass.is_empty() {
        return;
    }

    let mut expanded = first_pass.clone();
    for value in first_pass.iter().take(64) {
        if detect::should_try(value) {
            expanded.extend(base64::try_decode(value));
            expanded.extend(hex::try_decode(value));
            expanded.extend(url::try_decode(value));
            expanded.extend(html::decode_entities(value));
        }
        if expanded.len() >= decode_limit {
            expanded.truncate(decode_limit);
            break;
        }
    }

    let mut decoded = dedupe::stable_dedupe(
        expanded
            .into_iter()
            .filter(|value| looks_meaningful(value))
            .collect(),
    );
    if decoded.len() > decode_limit {
        decoded.truncate(decode_limit);
    }

    if decoded
        .iter()
        .any(|value| contains_suspicious_marker(value))
    {
        ctx.push_finding(Finding::new(
            "DECODED_ACTIVE_CONTENT",
            "Decoded content reveals network access or script-launch patterns that were previously hidden",
            1.5,
        ));
    }
    if decoded
        .iter()
        .any(|value| contains_follow_on_behavior(value))
    {
        ctx.push_finding(Finding::new(
            "DECODED_FOLLOW_ON_BEHAVIOR",
            "Decoded content reveals a correlated download or launch sequence that was previously hidden",
            2.2,
        ));
    }

    ctx.decoded_strings = decoded;
    ctx.push_view(super::views::decoded::build(&ctx.decoded_strings));
}

fn looks_meaningful(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 4 {
        return false;
    }

    let chars = trimmed.chars().count().max(1);
    let printable = trimmed
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\r' | '\t'))
        .count();

    printable * 100 / chars >= 90 && trimmed.chars().any(|c| c.is_ascii_alphabetic())
}

fn contains_suspicious_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    patterns::suspicious_markers()
        .iter()
        .any(|marker| lower.contains(marker))
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("cmd.exe")
}

fn contains_follow_on_behavior(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let has_network = lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("downloadstring")
        || lower.contains("downloadfile")
        || lower.contains("invoke-webrequest");
    let has_launch = lower.contains("invoke-expression")
        || lower.contains("iex")
        || lower.contains("cmd.exe")
        || lower.contains("start-process")
        || lower.contains("wscript.shell")
        || lower.contains("rundll32")
        || lower.contains("mshta");
    has_network && has_launch
}
