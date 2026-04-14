use crate::r#static::types::Finding;

#[derive(Debug, Clone)]
pub(crate) struct ElfSection {
    pub(crate) index: usize,
    pub(crate) name: String,
    pub(crate) section_type: u32,
    pub(crate) link: u32,
    pub(crate) entry_size: usize,
    pub(crate) offset: usize,
    pub(crate) size: usize,
}

pub fn check(bytes: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let mut findings = Vec::new();

    let Some(sections) = parse_sections(bytes) else {
        return Vec::new();
    };

    if sections
        .iter()
        .any(|section| matches!(section.name.as_str(), ".upx0" | ".upx1" | ".upx"))
    {
        findings.push(Finding::new(
            "ELF_PACKED_SECTION_LAYOUT",
            "Parsed ELF section headers include packed or compressed names that can hide embedded logic until a later stage",
            2.0,
        ));
    }

    let has_dynamic_sections = sections
        .iter()
        .any(|section| matches!(section.name.as_str(), ".dynamic" | ".dynsym" | ".dynstr"));
    let has_exec_memory_markers = contains_any(&text, &["mprotect", "mmap", "memfd_create"]);
    if has_dynamic_sections && contains_all(&text, &["dlopen", "dlsym"]) && has_exec_memory_markers
    {
        findings.push(Finding::new(
            "ELF_DYNAMIC_LOADER_CHAIN",
            "Parsed ELF dynamic-linking sections appear alongside runtime symbol loading and executable-memory functions",
            2.5,
        ));
    }

    let interp_path = sections
        .iter()
        .find(|section| section.name == ".interp")
        .and_then(|section| bytes.get(section.offset..section.offset + section.size))
        .map(|slice| String::from_utf8_lossy(slice).to_ascii_lowercase())
        .unwrap_or_default();
    if (interp_path.contains("ld-linux") || interp_path.contains("ld-musl"))
        && contains_all(&text, &["/proc/self/exe", "execve"])
    {
        findings.push(Finding::new(
            "ELF_SELF_RELAUNCH_CHAIN",
            "Parsed ELF interpreter data and self-relaunch paths suggest the file may chain into a second execution stage",
            2.1,
        ));
    }

    findings
}

pub(crate) fn parse_sections(bytes: &[u8]) -> Option<Vec<ElfSection>> {
    if bytes.len() < 0x34 || bytes.get(0..4)? != b"\x7fELF" {
        return None;
    }

    let class = *bytes.get(4)?;
    let little_endian = *bytes.get(5)? == 1;
    if !little_endian {
        return None;
    }

    let (section_offset, section_entry_size, section_count, shstr_index, is_64) = match class {
        1 => (
            read_u32_le(bytes, 0x20)? as usize,
            read_u16_le(bytes, 0x2e)? as usize,
            read_u16_le(bytes, 0x30)? as usize,
            read_u16_le(bytes, 0x32)? as usize,
            false,
        ),
        2 => (
            read_u64_le(bytes, 0x28)? as usize,
            read_u16_le(bytes, 0x3a)? as usize,
            read_u16_le(bytes, 0x3c)? as usize,
            read_u16_le(bytes, 0x3e)? as usize,
            true,
        ),
        _ => return None,
    };

    if section_count == 0
        || section_count > 128
        || section_entry_size == 0
        || section_offset.checked_add(section_entry_size.checked_mul(section_count)?)? > bytes.len()
        || shstr_index >= section_count
    {
        return None;
    }

    let shstr_entry_offset = section_offset + shstr_index * section_entry_size;
    let (shstr_offset, shstr_size) = if is_64 {
        (
            read_u64_le(bytes, shstr_entry_offset + 24)? as usize,
            read_u64_le(bytes, shstr_entry_offset + 32)? as usize,
        )
    } else {
        (
            read_u32_le(bytes, shstr_entry_offset + 16)? as usize,
            read_u32_le(bytes, shstr_entry_offset + 20)? as usize,
        )
    };
    let shstr = bytes.get(shstr_offset..shstr_offset.checked_add(shstr_size)?)?;

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_offset + index * section_entry_size;
        let name_offset = read_u32_le(bytes, offset)? as usize;
        let (_section_type, _flags, data_offset, size) = if is_64 {
            (
                read_u32_le(bytes, offset + 4)?,
                read_u64_le(bytes, offset + 8)?,
                read_u64_le(bytes, offset + 24)? as usize,
                read_u64_le(bytes, offset + 32)? as usize,
            )
        } else {
            (
                read_u32_le(bytes, offset + 4)?,
                read_u32_le(bytes, offset + 8)? as u64,
                read_u32_le(bytes, offset + 16)? as usize,
                read_u32_le(bytes, offset + 20)? as usize,
            )
        };

        let name = read_c_string(shstr, name_offset)?.to_ascii_lowercase();
        let section_type = read_u32_le(bytes, offset + 4)?;
        let link = read_u32_le(bytes, offset + 40)?;
        let entry_size = if is_64 {
            read_u64_le(bytes, offset + 56)? as usize
        } else {
            read_u32_le(bytes, offset + 36)? as usize
        };
        sections.push(ElfSection {
            index,
            name,
            section_type,
            link,
            entry_size,
            offset: data_offset,
            size,
        });
    }

    Some(sections)
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

fn contains_all(input: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| input.contains(needle))
}

fn contains_any(input: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| input.contains(needle))
}

