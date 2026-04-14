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
