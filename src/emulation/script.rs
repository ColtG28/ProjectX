use std::time::Instant;

use regex::Regex;

use crate::emulation::{
    consume_budget, maybe_push_multiple_outputs, push_output, EmulationConfig, EmulationState,
};
use crate::r#static::decode::base64;
use crate::r#static::types::Finding;

pub(crate) fn emulate_powershell(
    inputs: &[String],
    state: &mut EmulationState,
    config: EmulationConfig,
    started: Instant,
) {
    let encoded_command_re =
        Regex::new(r"(?i)(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})").expect("regex");
    let from_base64_re =
        Regex::new(r#"(?i)frombase64string\s*\(\s*["']([A-Za-z0-9+/=]{12,})["']\s*\)"#)
            .expect("regex");
    let utf16_base64_re = Regex::new(r#"(?i)["']([A-Za-z0-9+/=]{24,})["']"#).expect("regex");

    for input in inputs {
        if !consume_budget(state, config, started) {
            break;
        }

        for capture in encoded_command_re.captures_iter(input) {
            let encoded = capture
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            for decoded in base64::try_decode(encoded) {
                if decoded.trim().is_empty() {
                    continue;
                }
                push_output(state, "powershell.decoded", decoded.clone(), "powershell");
                if suspicious_script_content(&decoded) {
                    state.findings.push(Finding::new(
                        "EMULATION_PS_DECODED",
                        "PowerShell emulation recovered suspicious decoded script content",
                        1.5,
                    ));
                }
            }
        }

        for capture in from_base64_re.captures_iter(input) {
            let encoded = capture
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let outputs = base64::try_decode(encoded);
            for decoded in &outputs {
                if suspicious_script_content(decoded) {
                    state.findings.push(Finding::new(
                        "EMULATION_PS_FROMBASE64",
                        "PowerShell emulation recovered suspicious FromBase64String content",
                        1.5,
                    ));
                }
            }
            maybe_push_multiple_outputs(
                state,
                "powershell.frombase64string",
                outputs,
                "powershell",
                config,
            );
        }

        for capture in utf16_base64_re.captures_iter(input).take(4) {
            let encoded = capture
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            let outputs = base64::try_decode(encoded)
                .into_iter()
                .filter_map(|decoded| maybe_decode_utf16le(&decoded))
                .collect::<Vec<_>>();
            if !outputs.is_empty() {
                maybe_push_multiple_outputs(
                    state,
                    "powershell.utf16",
                    outputs.clone(),
                    "powershell",
                    config,
                );
                if outputs
                    .iter()
                    .any(|decoded| suspicious_script_content(decoded))
                {
                    state.findings.push(Finding::new(
                        "EMULATION_PS_UTF16",
                        "PowerShell emulation recovered suspicious UTF-16LE encoded script content",
                        1.5,
                    ));
                }
            }
        }
    }
}

pub(crate) fn emulate_javascript(
    inputs: &[String],
    state: &mut EmulationState,
    config: EmulationConfig,
    started: Instant,
) {
    let charcode_re = Regex::new(r"String\.fromCharCode\(([\d,\s]+)\)").expect("regex");
    let atob_re = Regex::new(r#"atob\(["']([A-Za-z0-9+/=]{12,})["']\)"#).expect("regex");
    let join_re = Regex::new(
        r#"\[\s*["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])*\s*\]\.join\(["']?([^"']*)["']?\)"#,
    )
    .expect("regex");
    let concat_re = Regex::new(r#"["']([^"']+)["']\s*\+\s*["']([^"']+)["']"#).expect("regex");
    let unescape_re =
        Regex::new(r#"unescape\(["']((?:%[0-9A-Fa-f]{2}){4,})["']\)"#).expect("regex");

    for input in inputs {
        if !consume_budget(state, config, started) {
            break;
        }

        for capture in charcode_re.captures_iter(input) {
            let values = capture
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default()
                .split(',')
                .filter_map(|part| part.trim().parse::<u32>().ok())
                .filter_map(char::from_u32)
                .collect::<String>();
            if values.len() >= 4 {
                push_output(state, "javascript.charcode", values.clone(), "javascript");
                if suspicious_script_content(&values) {
                    state.findings.push(Finding::new(
                        "EMULATION_JS_CHARCODE",
                        "JavaScript emulation reconstructed suspicious String.fromCharCode content",
                        1.5,
                    ));
                }
            }
        }

        for capture in atob_re.captures_iter(input) {
            let encoded = capture
                .get(1)
                .map(|value| value.as_str())
                .unwrap_or_default();
            for decoded in base64::try_decode(encoded) {
                push_output(state, "javascript.atob", decoded.clone(), "javascript");
            }
        }

        for capture in join_re.captures_iter(input) {
            let joined = capture
                .iter()
                .skip(1)
                .flatten()
                .map(|m| m.as_str())
                .collect::<Vec<_>>();
            if joined.len() >= 2 {
                let separator = joined.last().copied().unwrap_or_default();
                let items = &joined[..joined.len() - 1];
                let rebuilt = items.join(separator);
                if rebuilt.len() >= 4 {
                    push_output(state, "javascript.join", rebuilt.clone(), "javascript");
                }
            }
        }

        for capture in concat_re.captures_iter(input) {
            let rebuilt = format!(
                "{}{}",
                capture.get(1).map(|m| m.as_str()).unwrap_or_default(),
                capture.get(2).map(|m| m.as_str()).unwrap_or_default()
            );
            if rebuilt.len() >= 4 {
                push_output(state, "javascript.concat", rebuilt.clone(), "javascript");
            }
        }

        for capture in unescape_re.captures_iter(input) {
            let escaped = capture.get(1).map(|m| m.as_str()).unwrap_or_default();
            let rebuilt = decode_percent_bytes(escaped);
            if rebuilt.len() >= 4 {
                push_output(state, "javascript.unescape", rebuilt, "javascript");
            }
        }
    }
}

pub(crate) fn emulate_vba(
    inputs: &[String],
    state: &mut EmulationState,
    config: EmulationConfig,
    started: Instant,
) {
    let chr_re = Regex::new(r"(?i)chrw?\((\d{1,3})\)").expect("regex");
    let reverse_re = Regex::new(r#"(?i)strreverse\(["']([^"']{4,})["']\)"#).expect("regex");

    for input in inputs {
        if !consume_budget(state, config, started) {
            break;
        }

        if input.to_ascii_lowercase().contains("chr(") {
            let rebuilt = chr_re
                .captures_iter(input)
                .filter_map(|capture| capture.get(1))
                .filter_map(|value| value.as_str().parse::<u32>().ok())
                .filter_map(char::from_u32)
                .collect::<String>();
            if rebuilt.len() >= 4 {
                push_output(state, "vba.chr", rebuilt.clone(), "vba");
                if suspicious_script_content(&rebuilt) {
                    state.findings.push(Finding::new(
                        "EMULATION_VBA_CHR",
                        "VBA emulation reconstructed suspicious Chr/ChrW content",
                        1.5,
                    ));
                }
            }
        }

        for capture in reverse_re.captures_iter(input) {
            let rebuilt = capture
                .get(1)
                .map(|value| value.as_str().chars().rev().collect::<String>())
                .unwrap_or_default();
            if rebuilt.len() >= 4 {
                push_output(state, "vba.strreverse", rebuilt.clone(), "vba");
                if suspicious_script_content(&rebuilt) {
                    state.findings.push(Finding::new(
                        "EMULATION_VBA_STRREVERSE",
                        "VBA emulation reconstructed suspicious StrReverse content",
                        1.5,
                    ));
                }
            }
        }
    }
}

fn suspicious_script_content(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "iex",
        "invoke-expression",
        "downloadstring",
        "new-object net.webclient",
        "wscript.shell",
        "cmd.exe",
        "mshta",
        "urlmon",
        "virtualalloc",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn maybe_decode_utf16le(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return None;
    }

    let units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&units).ok()?;
    decoded
        .chars()
        .any(|ch| ch.is_ascii_alphabetic())
        .then_some(decoded)
}

fn decode_percent_bytes(input: &str) -> String {
    let mut bytes = Vec::new();
    let raw = input.as_bytes();
    let mut index = 0usize;
    while index + 2 < raw.len() {
        if raw[index] == b'%' {
            if let Ok(hex) = std::str::from_utf8(&raw[index + 1..index + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    bytes.push(value);
                }
            }
        }
        index += 3;
    }
    String::from_utf8_lossy(&bytes).to_string()
}
