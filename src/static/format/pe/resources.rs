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
