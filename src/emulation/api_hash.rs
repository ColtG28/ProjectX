use std::sync::OnceLock;
use std::time::Instant;

use regex::Regex;

use crate::emulation::{consume_budget, EmulationConfig, EmulationState};
use crate::r#static::types::Finding;

const COMMON_APIS: &[&str] = &[
    "VirtualAlloc",
    "VirtualProtect",
    "LoadLibraryA",
    "GetProcAddress",
    "WinExec",
    "CreateProcessW",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenUrlA",
    "WriteProcessMemory",
];

pub(crate) fn resolve_in_inputs(
    inputs: &[String],
    state: &mut EmulationState,
    config: EmulationConfig,
    started: Instant,
) {
    static HEX_RE: OnceLock<Regex> = OnceLock::new();
    let hex_re = HEX_RE.get_or_init(|| Regex::new(r"0x[0-9a-fA-F]{6,8}").expect("regex"));

    for input in inputs {
        if !consume_budget(state, config, started) {
            break;
        }

        for capture in hex_re.find_iter(input) {
            let value = capture.as_str().trim_start_matches("0x");
            let Ok(candidate) = u32::from_str_radix(value, 16) else {
                continue;
            };

            for api in COMMON_APIS {
                let ror13 = hash_name_for_resolution(api);
                if ror13 == candidate {
                    let resolution = format!("{api} via ror13({candidate:#010X})");
                    if !state.resolved_api_hashes.contains(&resolution) {
                        state.resolved_api_hashes.push(resolution.clone());
                        state.findings.push(Finding::new(
                            "EMULATION_API_HASH",
                            format!("Analysis reconstructed a hashed API reference to {api}"),
                            1.5,
                        ));
                    }
                }
            }
        }
    }
}

pub(crate) fn hash_name_for_resolution(name: &str) -> u32 {
    let mut hash = 0u32;
    for byte in name.bytes() {
        hash = hash
            .rotate_right(13)
            .wrapping_add(byte.to_ascii_uppercase() as u32);
    }
    hash
}

