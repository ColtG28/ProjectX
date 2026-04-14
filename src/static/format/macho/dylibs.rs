use crate::r#static::types::Finding;

use super::{parse_binary, MachoDylibKind};

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let Some(binary) = parse_binary(bytes) else {
        return Vec::new();
    };
    if binary.dylibs.is_empty() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();

    let has_system_runtime = has_any(&binary.dylibs, &["libsystem.b.dylib", "libdyld.dylib"]);
    let has_exec_memory_markers = contains_any(
        &text,
        &["mprotect", "mmap", "vm_protect", "mach_vm_protect"],
    );
    if has_system_runtime && contains_all(&text, &["dlopen", "dlsym"]) && has_exec_memory_markers {
        findings.push(Finding::new(
            "MACHO_DYNAMIC_LOADER_CHAIN",
            "Parsed Mach-O load commands and linked libraries align with runtime symbol loading plus executable-memory behavior",
            2.4,
        ));
    }

    let has_network_framework = has_any(
        &binary.dylibs,
        &[
            "cfnetwork.framework",
            "foundation.framework",
            "security.framework",
        ],
    );
    let has_launch_markers =
        contains_any(&text, &["posix_spawn", "execve", "nstask", "/usr/bin/open"]);
    let has_network_markers = contains_any(
        &text,
        &[
            "nsurlsession",
            "cfnetwork",
            "curl ",
            "urlsession",
            "getaddrinfo",
        ],
    );
    if has_network_framework && has_launch_markers && has_network_markers {
        findings.push(Finding::new(
            "MACHO_EXEC_NETWORK_CHAIN",
            "Parsed Mach-O linked libraries and embedded content combine launch-style behavior with network communication markers",
            2.1,
        ));
    }

    let has_relative_dylib = binary.dylibs.iter().any(|dylib| {
        dylib.path.starts_with("@loader_path/")
            || dylib.path.starts_with("@rpath/")
            || dylib.path.starts_with("@executable_path/")
    });
    let has_nonstandard_dylib_kind = binary
        .dylibs
        .iter()
        .any(|dylib| matches!(dylib.kind, MachoDylibKind::Weak | MachoDylibKind::Reexport));
    if has_relative_dylib
        && (contains_all(&text, &["dlopen", "dlsym"])
            || (has_nonstandard_dylib_kind && has_launch_markers))
    {
        findings.push(Finding::new(
            "MACHO_RELATIVE_LOADER_PATH_CHAIN",
            "Parsed Mach-O load commands reference relative loader paths alongside staged loading markers, which can support relocatable follow-on behavior",
            2.0,
        ));
    }

    findings
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}

fn contains_any(input: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| input.contains(needle))
}

fn has_any(values: &[super::MachoDylib], expected: &[&str]) -> bool {
    expected.iter().any(|needle| {
        values
            .iter()
            .any(|value| value.path.contains(&needle.to_ascii_lowercase()))
    })
}

