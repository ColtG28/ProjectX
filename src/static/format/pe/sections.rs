use crate::r#static::types::Finding;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug, Clone)]
pub(crate) struct PeSection {
    pub(crate) name: String,
    pub(crate) virtual_size: u32,
    pub(crate) virtual_address: u32,
    pub(crate) raw_size: u32,
    pub(crate) raw_pointer: u32,
    pub(crate) characteristics: u32,
}

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let Some(sections) = parse_sections(bytes) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let entrypoint_section = parse_entrypoint_rva(bytes)
        .and_then(|entrypoint_rva| section_for_rva(&sections, entrypoint_rva));

    if sections.iter().any(|section| {
        matches!(
            section.name.as_str(),
            "upx0" | "upx1" | ".upx" | ".aspack" | ".vmp0" | ".vmp1"
        )
    }) {
        findings.push(Finding::new(
            "PE_PACKED_SECTION_LAYOUT",
            "Parsed PE section headers include packed or unusually named sections that are often used to hide embedded logic until a later stage",
            2.2,
        ));
    }

    if sections.iter().any(|section| {
        let flags = section.characteristics;
        flags & IMAGE_SCN_MEM_EXECUTE != 0 && flags & IMAGE_SCN_MEM_WRITE != 0
    }) {
        findings.push(Finding::new(
            "PE_EXECUTABLE_WRITABLE_SECTION",
            "Parsed PE section headers show a section that is both writable and executable, which is unusual for standard applications",
            2.3,
        ));
    }

    if sections.len() <= 2
        && sections.iter().any(|section| section.raw_size > 0)
        && sections
            .iter()
            .any(|section| section.virtual_size > section.raw_size.saturating_mul(4))
    {
        findings.push(Finding::new(
            "PE_SPARSE_SECTION_LAYOUT",
            "Parsed PE layout is unusually sparse, with very few sections and one section expanding far beyond its on-disk size",
            1.6,
        ));
    }

    if let Some(section) = entrypoint_section {
        if matches!(
            section.name.as_str(),
            "upx0" | "upx1" | ".upx" | ".aspack" | ".vmp0" | ".vmp1"
        ) {
            findings.push(Finding::new(
                "PE_ENTRYPOINT_IN_PACKED_SECTION",
                "Parsed PE entry point falls inside a packed or unusually named section, which can indicate an unpacking stub or staged loader",
                2.4,
            ));
        }

        let flags = section.characteristics;
        if flags & IMAGE_SCN_MEM_EXECUTE != 0 && flags & IMAGE_SCN_MEM_WRITE != 0 {
            findings.push(Finding::new(
                "PE_ENTRYPOINT_IN_WRITABLE_EXECUTABLE_SECTION",
                "Parsed PE entry point starts in a writable and executable section, which is unusual for standard applications",
                2.5,
            ));
        }
    }

    findings
}

pub(crate) fn parse_sections(bytes: &[u8]) -> Option<Vec<PeSection>> {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return None;
    }

    let pe_offset = read_u32_le(bytes, 0x3c)? as usize;
    if pe_offset.checked_add(24)? > bytes.len() {
        return None;
    }
    if bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }

    let section_count = read_u16_le(bytes, pe_offset + 6)? as usize;
    let optional_header_size = read_u16_le(bytes, pe_offset + 20)? as usize;
    let section_table = pe_offset
        .checked_add(24)?
        .checked_add(optional_header_size)?;
    let table_size = section_count.checked_mul(40)?;
    if section_table.checked_add(table_size)? > bytes.len()
        || section_count == 0
        || section_count > 96
    {
        return None;
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table + index * 40;
        let name_bytes = bytes.get(offset..offset + 8)?;
        let name_end = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_ascii_lowercase();
        let virtual_size = read_u32_le(bytes, offset + 8)?;
        let virtual_address = read_u32_le(bytes, offset + 12)?;
        let raw_size = read_u32_le(bytes, offset + 16)?;
        let raw_pointer = read_u32_le(bytes, offset + 20)?;
        let characteristics = read_u32_le(bytes, offset + 36)?;
        sections.push(PeSection {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            characteristics,
        });
    }

    Some(sections)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn parse_entrypoint_rva(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return None;
    }
    let pe_offset = read_u32_le(bytes, 0x3c)? as usize;
    if pe_offset.checked_add(24)? > bytes.len() || bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0"
    {
        return None;
    }
    let optional_offset = pe_offset + 24;
    if optional_offset.checked_add(20)? > bytes.len() {
        return None;
    }
    Some(read_u32_le(bytes, optional_offset + 16)?)
}

fn section_for_rva<'a>(sections: &'a [PeSection], rva: u32) -> Option<&'a PeSection> {
    sections.iter().find(|section| {
        let start = section.virtual_address;
        let span = section.virtual_size.max(section.raw_size).max(1);
        let end = start.saturating_add(span);
        rva >= start && rva < end
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

    use super::{check, parse_sections, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
    use parser_fixtures::{
        build_test_pe, build_test_pe_with_imports_and_entrypoint, malformed_pe_bad_lfanew,
        malformed_pe_truncated_section_table, PeSectionSpec,
    };

    #[test]
    fn parses_real_pe_section_headers() {
        let bytes = build_test_pe(
            &[
                PeSectionSpec {
                    name: ".text",
                    virtual_size: 0x500,
                    raw_size: 0x400,
                    characteristics: 0x6000_0020,
                },
                PeSectionSpec {
                    name: ".rsrc",
                    virtual_size: 0x200,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
            ],
            b"payload",
        );
        let sections = parse_sections(&bytes).unwrap();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, ".text");
        assert_eq!(sections[1].name, ".rsrc");
        assert_eq!(sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn packed_section_layout_message_is_clear() {
        let bytes = build_test_pe(
            &[
                PeSectionSpec {
                    name: "UPX0",
                    virtual_size: 0x900,
                    raw_size: 0x200,
                    characteristics: 0xE000_0020,
                },
                PeSectionSpec {
                    name: "UPX1",
                    virtual_size: 0x700,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                },
            ],
            b"payload",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "PE_PACKED_SECTION_LAYOUT"));
    }

    #[test]
    fn executable_writable_section_message_is_clear() {
        let bytes = build_test_pe(
            &[PeSectionSpec {
                name: ".text",
                virtual_size: 0x900,
                raw_size: 0x200,
                characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE,
            }],
            b"payload",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "PE_EXECUTABLE_WRITABLE_SECTION"));
    }

    #[test]
    fn entrypoint_in_packed_section_message_is_clear() {
        let bytes = build_test_pe_with_imports_and_entrypoint(
            &[
                PeSectionSpec {
                    name: "UPX0",
                    virtual_size: 0x900,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                },
                PeSectionSpec {
                    name: ".rsrc",
                    virtual_size: 0x200,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
            ],
            &[],
            b"payload",
            Some("UPX0"),
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "PE_ENTRYPOINT_IN_PACKED_SECTION"));
    }

    #[test]
    fn malformed_pe_headers_fail_safely() {
        assert!(check(b"MZ").is_empty());
    }

    #[test]
    fn bad_pe_offset_fails_safely() {
        let bytes = malformed_pe_bad_lfanew();
        assert!(check(&bytes).is_empty());
        assert!(parse_sections(&bytes).is_none());
    }

    #[test]
    fn truncated_section_table_fails_safely() {
        let bytes = malformed_pe_truncated_section_table();
        assert!(check(&bytes).is_empty());
        assert!(parse_sections(&bytes).is_none());
    }
}
