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

