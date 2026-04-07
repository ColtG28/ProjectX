use crate::r#static::types::Finding;

use super::parse_binary;

const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let Some(binary) = parse_binary(bytes) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if binary.segments.iter().any(|segment| {
        suspicious_name(&segment.name)
            || segment.sections.iter().any(|section| {
                suspicious_name(&section.sectname) || suspicious_name(&section.segname)
            })
    }) {
        findings.push(Finding::new(
            "MACHO_PACKED_SECTION_LAYOUT",
            "Parsed Mach-O segments or sections include packed or unusually named regions that can hide embedded logic until a later stage",
            2.0,
        ));
    }

    if binary.segments.iter().any(|segment| {
        has_write_and_execute(segment.initprot) || has_write_and_execute(segment.maxprot)
    }) {
        findings.push(Finding::new(
            "MACHO_EXECUTABLE_WRITABLE_SEGMENT",
            "Parsed Mach-O load commands define a segment that is both writable and executable, which is unusual for standard macOS applications",
            2.2,
        ));
    }

    findings
}

fn suspicious_name(name: &str) -> bool {
    name.contains("upx") || name.contains("packed")
}

fn has_write_and_execute(protection: u32) -> bool {
    protection & VM_PROT_WRITE != 0 && protection & VM_PROT_EXECUTE != 0
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
    use parser_fixtures::{build_test_macho, malformed_macho_bad_load_command, MachoSegmentSpec};

    #[test]
    fn packed_layout_message_is_clear() {
        let bytes = build_test_macho(
            &[MachoSegmentSpec {
                name: "__UPX",
                maxprot: 7,
                initprot: 7,
                sections: &["__packed"],
            }],
            &["/usr/lib/libSystem.B.dylib"],
            b"payload",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "MACHO_PACKED_SECTION_LAYOUT"));
    }

    #[test]
    fn parses_macho_segments() {
        let bytes = build_test_macho(
            &[
                MachoSegmentSpec {
                    name: "__TEXT",
                    maxprot: 5,
                    initprot: 5,
                    sections: &["__text"],
                },
                MachoSegmentSpec {
                    name: "__DATA",
                    maxprot: 3,
                    initprot: 3,
                    sections: &["__data"],
                },
            ],
            &["/usr/lib/libSystem.B.dylib"],
            b"payload",
        );
        let parsed = parse_binary(&bytes).unwrap();
        assert_eq!(parsed.segments.len(), 2);
        assert!(parsed.segments[0]
            .sections
            .iter()
            .any(|section| section.sectname == "__text"));
    }

    #[test]
    fn malformed_macho_headers_fail_safely() {
        let bytes = malformed_macho_bad_load_command();
        assert!(check(&bytes).is_empty());
        assert!(parse_binary(&bytes).is_none());
    }
}
