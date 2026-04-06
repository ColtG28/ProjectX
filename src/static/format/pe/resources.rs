use crate::r#static::types::Finding;

use super::sections::parse_sections;

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();

    let Some(parsed_sections) = parse_sections(bytes) else {
        return Vec::new();
    };
    let has_resource_data = parsed_sections
        .iter()
        .any(|section| section.name == ".rsrc");

    if has_resource_data
        && (contains_all(&text, &["powershell", "-enc", "downloadstring"])
            || contains_all(&text, &["mshta", "http"])
            || contains_all(&text, &["urlmon", "rundll32", "http"]))
    {
        findings.push(Finding::new(
            "PE_RESOURCE_SCRIPT_STAGE",
            "Parsed PE resources and nearby content suggest an embedded script or launcher stage stored in the file",
            2.3,
        ));
    }

    if has_resource_data && contains_all(&text, &["virtualalloc", "writeprocessmemory"]) {
        findings.push(Finding::new(
            "PE_RESOURCE_LOADER_CHAIN",
            "Parsed PE resources appear alongside memory-loading imports, which can indicate an embedded follow-on component",
            2.2,
        ));
    }

    findings
}

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
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
    use parser_fixtures::{build_test_pe, PeSectionSpec};

    fn build_test_pe_with_rsrc(payload: &[u8]) -> Vec<u8> {
        build_test_pe(
            &[
                PeSectionSpec {
                    name: ".text",
                    virtual_size: 0x300,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                },
                PeSectionSpec {
                    name: ".rsrc",
                    virtual_size: 0x300,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
            ],
            payload,
        )
    }

    #[test]
    fn resource_script_stage_message_is_clear() {
        let findings = check(&build_test_pe_with_rsrc(b"powershell -enc DownloadString"));
        assert!(findings
            .iter()
            .any(|finding| finding.code == "PE_RESOURCE_SCRIPT_STAGE"));
    }

    #[test]
    fn malformed_pe_resources_fail_safely() {
        assert!(check(b"MZ").is_empty());
    }

    #[test]
    fn resource_stage_requires_parsed_resource_section() {
        let mut bytes = build_test_pe_with_rsrc(b"powershell -enc DownloadString");
        let pe_offset = 0x80usize;
        let section_table = pe_offset + 24 + 0xE0;
        bytes[section_table + 40..section_table + 48].copy_from_slice(b".data\0\0\0");
        assert!(check(&bytes).is_empty());
    }
}
