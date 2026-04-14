use std::time::Instant;

use crate::emulation::{consume_budget, EmulationConfig, EmulationState};
use crate::r#static::types::Finding;

pub(crate) fn detect_decryption_loops(
    inputs: &[String],
    state: &mut EmulationState,
    config: EmulationConfig,
    started: Instant,
) {
    for input in inputs {
        if !consume_budget(state, config, started) {
            break;
        }

        let lower = input.to_ascii_lowercase();
        let has_loop = lower.contains("for(")
            || lower.contains("for (")
            || lower.contains("while(")
            || lower.contains("while (");
        let has_decryption_ops = lower.contains("xor")
            || lower.contains("^")
            || lower.contains("fromcharcode")
            || lower.contains("chr(")
            || lower.contains("rotate")
            || lower.contains("rol(")
            || lower.contains("ror(");

        if has_loop && has_decryption_ops {
            state.findings.push(Finding::new(
                "EMULATION_DECRYPT_LOOP",
                "Analysis found a loop that appears to decode or transform hidden strings",
                1.5,
            ));
        }

        if let Some(decoded) = recover_simple_xor_literal(input) {
            crate::emulation::push_output(state, "strings.xor", decoded, "xor-decoded");
        }
    }
}

fn recover_simple_xor_literal(input: &str) -> Option<String> {
    let lower = input.to_ascii_lowercase();
    if !(lower.contains("xor") || lower.contains('^')) {
        return None;
    }

    let bytes = input
        .split([',', ' ', '[', ']', '(', ')'])
        .filter_map(|part| {
            let token = part.trim().trim_end_matches(',');
            if token.starts_with("0x") {
                u8::from_str_radix(token.trim_start_matches("0x"), 16).ok()
            } else {
                token.parse::<u8>().ok()
            }
        })
        .collect::<Vec<_>>();
    if bytes.len() < 4 {
        return None;
    }

    for key in 1u8..=255 {
        let candidate = bytes.iter().map(|byte| byte ^ key).collect::<Vec<_>>();
        if candidate
            .iter()
            .all(|byte| byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            let text = String::from_utf8_lossy(&candidate).to_string();
            if text.chars().any(|ch| ch.is_ascii_alphabetic()) {
                return Some(text);
            }
        }
    }

    None
}

