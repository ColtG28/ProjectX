use std::time::Instant;

use crate::emulation::{consume_budget, EmulationConfig, EmulationState};
use crate::r#static::types::Finding;

pub(crate) fn emulate_loader(
    bytes: &[u8],
    inputs: &[String],
    state: &mut EmulationState,
    config: EmulationConfig,
    started: Instant,
) {
    if !bytes.starts_with(b"MZ") || !consume_budget(state, config, started) {
        return;
    }

    let lower_bytes =
        String::from_utf8_lossy(&bytes[..bytes.len().min(32_768)]).to_ascii_lowercase();
    let lower_inputs = inputs
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();

    let loader_markers = [
        "virtualalloc",
        "virtualprotect",
        "loadlibrarya",
        "getprocaddress",
        "writeprocessmemory",
        "createprocessw",
        "urlmon",
        "wininet",
    ];

    let hits = loader_markers
        .iter()
        .filter(|marker| {
            lower_bytes.contains(**marker)
                || lower_inputs.iter().any(|value| value.contains(**marker))
        })
        .cloned()
        .collect::<Vec<_>>();

    if !hits.is_empty() {
        state.findings.push(Finding::new(
            "EMULATION_PE_LOADER",
            format!(
                "PE loader emulation observed suspicious loader/import markers: {}",
                hits.join(", ")
            ),
            2.0,
        ));
    }

    let imports = extract_import_indicators(bytes);
    if !imports.is_empty() {
        state.findings.push(Finding::new(
            "EMULATION_PE_IMPORTS",
            format!(
                "PE emulation recovered suspicious import indicators: {}",
                imports.join(", ")
            ),
            1.5,
        ));
    }
}

fn extract_import_indicators(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(131_072)]).to_ascii_lowercase();
    let dlls = [
        "kernel32.dll",
        "advapi32.dll",
        "urlmon.dll",
        "wininet.dll",
        "ws2_32.dll",
    ];
    let apis = [
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "winexec",
        "shellexecute",
        "internetopen",
        "urldownloadtofile",
        "regsetvalue",
        "wsastartup",
    ];

    let mut hits = Vec::new();
    for dll in dlls {
        if text.contains(dll) {
            hits.push(dll.to_string());
        }
    }
    for api in apis {
        if text.contains(api) {
            hits.push(api.to_string());
        }
    }
    hits
}
