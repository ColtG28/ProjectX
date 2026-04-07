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

#[cfg(test)]
mod tests {
    mod parser_fixtures {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/parser_fixtures.rs"
        ));
    }

    use super::check;
    use crate::r#static::format::macho::parse_binary;
    use parser_fixtures::{
        build_test_macho, build_test_macho_with_dylib_specs, malformed_macho_bad_dylib_name_offset,
        MachoDylibSpec, MachoSegmentSpec,
    };

    #[test]
    fn dynamic_loader_message_is_clear() {
        let bytes = build_test_macho(
            &[MachoSegmentSpec {
                name: "__TEXT",
                maxprot: 5,
                initprot: 5,
                sections: &["__text"],
            }],
            &["/usr/lib/libSystem.B.dylib", "/usr/lib/libdyld.dylib"],
            b"dlopen dlsym vm_protect",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "MACHO_DYNAMIC_LOADER_CHAIN"));
    }

    #[test]
    fn malformed_dylib_command_fails_safely() {
        let bytes = malformed_macho_bad_dylib_name_offset();
        assert!(check(&bytes).is_empty());
        assert!(parse_binary(&bytes).is_none());
    }

    #[test]
    fn relative_loader_path_chain_is_detected() {
        let bytes = build_test_macho_with_dylib_specs(
            &[MachoSegmentSpec {
                name: "__TEXT",
                maxprot: 5,
                initprot: 5,
                sections: &["__text"],
            }],
            &[
                MachoDylibSpec {
                    path: "@loader_path/Frameworks/Helper.framework/Helper",
                    command: 0x8000_0018,
                },
                MachoDylibSpec {
                    path: "/usr/lib/libSystem.B.dylib",
                    command: 0xC,
                },
            ],
            b"dlopen dlsym bootstrap notes",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "MACHO_RELATIVE_LOADER_PATH_CHAIN"));
    }
}
