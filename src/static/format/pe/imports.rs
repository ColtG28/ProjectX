use crate::r#static::types::Finding;

use super::sections::{parse_sections, PeSection};

#[derive(Debug, Clone)]
pub(crate) struct ParsedImport {
    pub(crate) dll: String,
    pub(crate) functions: Vec<String>,
}

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let Some(imports) = parse_imports(bytes) else {
        return Vec::new();
    };
    if imports.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let functions = imports
        .iter()
        .flat_map(|import| {
            import
                .functions
                .iter()
                .map(|function| function.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    let dlls = imports
        .iter()
        .map(|import| import.dll.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if has_all(&functions, &["virtualalloc", "createremotethread"])
        && has_any(&dlls, &["kernel32.dll", "kernelbase.dll"])
    {
        findings.push(Finding::new(
            "PE_INJECTION_IMPORTS",
            "Parsed PE imports include functions commonly associated with remote memory staging or process injection",
            2.6,
        ));
    }

    if has_all(&functions, &["virtualalloc", "writeprocessmemory"])
        && (functions.iter().any(|name| name == "createremotethread")
            || functions.iter().any(|name| name == "queueuserapc"))
    {
        findings.push(Finding::new(
            "PE_INJECTION_CHAIN",
            "Parsed PE imports combine memory allocation, remote write, and follow-on execution functions in a way commonly associated with code injection",
            3.2,
        ));
    }

    if has_all(&functions, &["loadlibrarya", "getprocaddress"])
        || has_all(&functions, &["loadlibraryw", "getprocaddress"])
    {
        findings.push(Finding::new(
            "PE_DYNAMIC_LOADER_IMPORTS",
            "Parsed PE imports dynamically load libraries and resolve functions at runtime, which can support staged or evasive behavior when corroborated",
            1.7,
        ));
    }

    if has_all(&functions, &["virtualalloc", "virtualprotect"])
        || has_all(&functions, &["virtualalloc", "virtualprotectex"])
    {
        findings.push(Finding::new(
            "PE_MEMORY_PERMISSION_CHAIN",
            "Parsed PE imports combine memory allocation and memory-permission changes, which can support unpacking or in-memory execution chains",
            2.0,
        ));
    }

    findings
}

pub(crate) fn parse_imports(bytes: &[u8]) -> Option<Vec<ParsedImport>> {
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

    let optional_header_size = read_u16_le(bytes, pe_offset + 20)? as usize;
    let optional_offset = pe_offset + 24;
    if optional_offset.checked_add(optional_header_size)? > bytes.len() {
        return None;
    }

    let magic = read_u16_le(bytes, optional_offset)?;
    let is_pe32_plus = match magic {
        0x10b => false,
        0x20b => true,
        _ => return None,
    };
    let data_directory_start = optional_offset + if is_pe32_plus { 112 } else { 96 };
    if data_directory_start.checked_add(16)? > optional_offset + optional_header_size {
        return Some(Vec::new());
    }

    let import_rva = read_u32_le(bytes, data_directory_start + 8)?;
    let import_size = read_u32_le(bytes, data_directory_start + 12)?;
    if import_rva == 0 || import_size == 0 {
        return Some(Vec::new());
    }

    let sections = parse_sections(bytes)?;
    let descriptor_offset = rva_to_offset(import_rva, &sections)?;
    let thunk_entry_size = if is_pe32_plus { 8 } else { 4 };

    let mut imports = Vec::new();
    for descriptor_index in 0..64usize {
        let offset = descriptor_offset + descriptor_index * 20;
        if offset.checked_add(20)? > bytes.len() {
            return None;
        }

        let original_first_thunk = read_u32_le(bytes, offset)?;
        let _time_date_stamp = read_u32_le(bytes, offset + 4)?;
        let _forwarder_chain = read_u32_le(bytes, offset + 8)?;
        let name_rva = read_u32_le(bytes, offset + 12)?;
        let first_thunk = read_u32_le(bytes, offset + 16)?;

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name_offset = rva_to_offset(name_rva, &sections)?;
        let dll = read_c_string(bytes, dll_name_offset)?.to_ascii_lowercase();
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let thunk_offset = rva_to_offset(thunk_rva, &sections)?;

        let mut functions = Vec::new();
        for thunk_index in 0..256usize {
            let entry_offset = thunk_offset + thunk_index * thunk_entry_size;
            if entry_offset.checked_add(thunk_entry_size)? > bytes.len() {
                return None;
            }

            let thunk_value = if is_pe32_plus {
                read_u64_le(bytes, entry_offset)?
            } else {
                u64::from(read_u32_le(bytes, entry_offset)?)
            };

            if thunk_value == 0 {
                break;
            }

            let is_ordinal = if is_pe32_plus {
                thunk_value & (1u64 << 63) != 0
            } else {
                thunk_value & 0x8000_0000 != 0
            };
            if is_ordinal {
                continue;
            }

            let name_offset = rva_to_offset(thunk_value as u32, &sections)?;
            let function = read_c_string(bytes, name_offset + 2)?.to_ascii_lowercase();
            functions.push(function);
        }

        imports.push(ParsedImport { dll, functions });
    }

    Some(imports)
}

fn rva_to_offset(rva: u32, sections: &[PeSection]) -> Option<usize> {
    let rva = rva as usize;
    sections.iter().find_map(|section| {
        let start = section.virtual_address as usize;
        let span = section.virtual_size.max(section.raw_size) as usize;
        let end = start.checked_add(span)?;
        if rva < start || rva >= end {
            return None;
        }

        let delta = rva - start;
        let raw_pointer = section.raw_pointer as usize;
        let file_offset = raw_pointer.checked_add(delta)?;
        Some(file_offset)
    })
}

fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let slice = bytes.get(offset..)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).to_string())
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn has_all(functions: &[String], expected: &[&str]) -> bool {
    expected
        .iter()
        .all(|name| functions.iter().any(|function| function == name))
}

fn has_any(values: &[String], expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|name| values.iter().any(|value| value == name))
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

    use super::{check, parse_imports};
    use parser_fixtures::{
        build_test_pe_with_imports, malformed_pe_bad_import_directory, PeImportSpec, PeSectionSpec,
    };

    fn build_import_test_pe(imports: &[PeImportSpec<'_>], payload: &[u8]) -> Vec<u8> {
        build_test_pe_with_imports(
            &[
                PeSectionSpec {
                    name: ".text",
                    virtual_size: 0x600,
                    raw_size: 0x200,
                    characteristics: 0x6000_0020,
                },
                PeSectionSpec {
                    name: ".idata",
                    virtual_size: 0x800,
                    raw_size: 0x400,
                    characteristics: 0xC000_0040,
                },
                PeSectionSpec {
                    name: ".rsrc",
                    virtual_size: 0x400,
                    raw_size: 0x200,
                    characteristics: 0x4000_0040,
                },
            ],
            imports,
            payload,
        )
    }

    #[test]
    fn parses_real_import_directory() {
        let bytes = build_import_test_pe(
            &[PeImportSpec {
                dll: "kernel32.dll",
                functions: &["LoadLibraryA", "GetProcAddress"],
            }],
            b"payload",
        );
        let imports = parse_imports(&bytes).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll, "kernel32.dll");
        assert!(imports[0]
            .functions
            .iter()
            .any(|function| function == "loadlibrarya"));
    }

    #[test]
    fn injection_chain_message_is_clear() {
        let bytes = build_import_test_pe(
            &[PeImportSpec {
                dll: "kernel32.dll",
                functions: &["VirtualAlloc", "WriteProcessMemory", "QueueUserAPC"],
            }],
            b"payload",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "PE_INJECTION_CHAIN"));
    }

    #[test]
    fn malformed_import_directory_fails_safely() {
        let bytes = malformed_pe_bad_import_directory();
        assert!(check(&bytes).is_empty());
        assert!(parse_imports(&bytes).is_none());
    }
}
