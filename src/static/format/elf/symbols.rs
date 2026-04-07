use crate::r#static::types::Finding;

use super::sections::{parse_sections, ElfSection};

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let Some(symbols) = parse_symbol_tables(bytes) else {
        return Vec::new();
    };
    let all_symbols = symbols
        .iter()
        .map(|symbol| symbol.name.clone())
        .collect::<Vec<_>>();
    if all_symbols.is_empty() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();

    if has_all(&all_symbols, &["dlopen", "dlsym"])
        && has_any(&all_symbols, &["mprotect", "mmap", "memfd_create"])
    {
        findings.push(Finding::new(
            "ELF_DYNAMIC_SYMBOL_CHAIN",
            "Parsed ELF dynamic symbols combine runtime symbol loading with executable-memory behavior",
            2.3,
        ));
    }

    if has_any(&all_symbols, &["system", "execve", "posix_spawn"])
        && has_any(
            &all_symbols,
            &["socket", "connect", "getaddrinfo", "curl_easy_perform"],
        )
    {
        findings.push(Finding::new(
            "ELF_EXEC_NETWORK_SYMBOL_CHAIN",
            "Parsed ELF dynamic symbols combine command execution and network communication functions in a way that can support follow-on behavior",
            2.1,
        ));
    }

    if has_any(&all_symbols, &["execve", "posix_spawn"])
        && has_any(&all_symbols, &["readlink", "readlinkat", "realpath"])
        && text.contains("/proc/self/exe")
    {
        findings.push(Finding::new(
            "ELF_SELF_RELAUNCH_SYMBOL_CHAIN",
            "Parsed ELF symbols and self-reference paths suggest the file may relaunch itself through a second stage",
            1.9,
        ));
    }

    let static_symbols = symbols
        .iter()
        .filter(|symbol| matches!(symbol.kind, SymbolKind::Static))
        .map(|symbol| symbol.name.clone())
        .collect::<Vec<_>>();
    if has_all(&static_symbols, &["dlopen", "dlsym"])
        && has_any(&static_symbols, &["mprotect", "mmap", "memfd_create"])
    {
        findings.push(Finding::new(
            "ELF_STATIC_SYMBOL_LOADER_CHAIN",
            "Parsed ELF symbol tables combine runtime symbol loading with executable-memory behavior even when those relationships are not exposed through dynamic symbols",
            2.1,
        ));
    }

    if has_any(&static_symbols, &["system", "execve", "posix_spawn"])
        && has_any(
            &static_symbols,
            &["socket", "connect", "getaddrinfo", "curl_easy_perform"],
        )
    {
        findings.push(Finding::new(
            "ELF_STATIC_SYMBOL_EXEC_NETWORK_CHAIN",
            "Parsed ELF symbol tables combine command execution and network communication functions in a way that can support follow-on behavior",
            2.0,
        ));
    }

    findings
}

#[cfg(test)]
pub(crate) fn parse_symbols(bytes: &[u8]) -> Option<Vec<String>> {
    Some(
        parse_symbol_tables(bytes)?
            .into_iter()
            .map(|symbol| symbol.name)
            .collect(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolKind {
    Dynamic,
    Static,
}

#[derive(Debug, Clone)]
struct ParsedSymbol {
    name: String,
    kind: SymbolKind,
}

fn parse_symbol_tables(bytes: &[u8]) -> Option<Vec<ParsedSymbol>> {
    let sections = parse_sections(bytes)?;
    let mut symbols = Vec::new();
    symbols.extend(parse_named_symbol_table(
        bytes,
        &sections,
        ".dynsym",
        11,
        SymbolKind::Dynamic,
    )?);
    symbols.extend(parse_named_symbol_table(
        bytes,
        &sections,
        ".symtab",
        2,
        SymbolKind::Static,
    )?);
    Some(symbols)
}

fn parse_named_symbol_table(
    bytes: &[u8],
    sections: &[ElfSection],
    section_name: &str,
    section_type: u32,
    kind: SymbolKind,
) -> Option<Vec<ParsedSymbol>> {
    let Some(table) = sections
        .iter()
        .find(|section| section.name == section_name && section.section_type == section_type)
    else {
        return Some(Vec::new());
    };
    if table.size == 0 || table.entry_size == 0 {
        return Some(Vec::new());
    }
    if table.entry_size < 8 || table.entry_size > 256 || table.size % table.entry_size != 0 {
        return None;
    }

    let strtab = linked_strtab(sections, table)?;
    if strtab.size == 0 {
        return Some(Vec::new());
    }
    let strtab_bytes = bytes.get(strtab.offset..strtab.offset.checked_add(strtab.size)?)?;
    let table_bytes = bytes.get(table.offset..table.offset.checked_add(table.size)?)?;
    let entry_count = (table.size / table.entry_size).min(512);
    if entry_count == 0 {
        return Some(Vec::new());
    }

    let mut symbols = Vec::new();
    for index in 1..entry_count {
        let offset = index.checked_mul(table.entry_size)?;
        let name_offset = read_u32_le(table_bytes, offset)? as usize;
        let name = read_c_string(strtab_bytes, name_offset)?.to_ascii_lowercase();
        if !name.is_empty() {
            symbols.push(ParsedSymbol { name, kind });
        }
    }
    Some(symbols)
}

fn linked_strtab<'a>(sections: &'a [ElfSection], dynsym: &ElfSection) -> Option<&'a ElfSection> {
    let linked_index = dynsym.link as usize;
    sections
        .iter()
        .find(|section| section.index == linked_index && section.section_type == 3)
}

fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    let slice = bytes.get(offset..)?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).to_string())
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn has_all(values: &[String], expected: &[&str]) -> bool {
    expected
        .iter()
        .all(|name| values.iter().any(|value| value == name))
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

    use super::{check, parse_symbols};
    use parser_fixtures::{
        build_test_elf_with_symbol_tables, build_test_elf_with_symbols,
        malformed_elf_bad_static_symbol_table, malformed_elf_bad_symbol_table,
        malformed_elf_invalid_symbol_entry_size, malformed_elf_partial_loader_symbols,
        malformed_elf_symbol_name_out_of_bounds, malformed_elf_truncated_dynstr,
        malformed_elf_truncated_dynsym, ElfSymbolSpec, ElfSymbolTableSpec,
    };

    #[test]
    fn parses_real_elf_dynamic_symbols() {
        let bytes = build_test_elf_with_symbols(
            &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
            Some("/lib64/ld-linux-x86-64.so.2"),
            &[
                ElfSymbolSpec { name: "dlopen" },
                ElfSymbolSpec { name: "dlsym" },
                ElfSymbolSpec { name: "mprotect" },
            ],
            b"notes",
        );
        let symbols = parse_symbols(&bytes).unwrap();
        assert!(symbols.iter().any(|symbol| symbol == "dlopen"));
        assert!(symbols.iter().any(|symbol| symbol == "mprotect"));
    }

    #[test]
    fn dynamic_symbol_chain_message_is_clear() {
        let bytes = build_test_elf_with_symbols(
            &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
            Some("/lib64/ld-linux-x86-64.so.2"),
            &[
                ElfSymbolSpec { name: "dlopen" },
                ElfSymbolSpec { name: "dlsym" },
                ElfSymbolSpec { name: "mprotect" },
            ],
            b"runtime notes",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "ELF_DYNAMIC_SYMBOL_CHAIN"));
    }

    #[test]
    fn malformed_symbol_table_fails_safely() {
        let bytes = malformed_elf_bad_symbol_table();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }

    #[test]
    fn truncated_dynsym_fails_safely() {
        let bytes = malformed_elf_truncated_dynsym();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }

    #[test]
    fn truncated_dynstr_fails_safely() {
        let bytes = malformed_elf_truncated_dynstr();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }

    #[test]
    fn invalid_symbol_entry_size_fails_safely() {
        let bytes = malformed_elf_invalid_symbol_entry_size();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }

    #[test]
    fn out_of_bounds_symbol_name_fails_safely() {
        let bytes = malformed_elf_symbol_name_out_of_bounds();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }

    #[test]
    fn partial_loader_text_without_symbol_table_does_not_emit_parsed_symbol_findings() {
        let bytes = malformed_elf_partial_loader_symbols();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }

    #[test]
    fn static_symbol_table_chain_is_detected() {
        let bytes = build_test_elf_with_symbol_tables(
            &[".text", ".strtab", ".symtab", ".interp", ".shstrtab"],
            Some("/lib64/ld-linux-x86-64.so.2"),
            ElfSymbolTableSpec {
                dyn_symbols: &[],
                static_symbols: &[
                    ElfSymbolSpec { name: "dlopen" },
                    ElfSymbolSpec { name: "dlsym" },
                    ElfSymbolSpec { name: "mprotect" },
                ],
            },
            b"notes",
        );
        let findings = check(&bytes);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "ELF_STATIC_SYMBOL_LOADER_CHAIN"));
    }

    #[test]
    fn malformed_static_symbol_table_fails_safely() {
        let bytes = malformed_elf_bad_static_symbol_table();
        assert!(check(&bytes).is_empty());
        assert!(parse_symbols(&bytes).is_none());
    }
}
