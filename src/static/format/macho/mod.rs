pub mod dylibs;
pub mod sections;

use crate::r#static::types::Finding;

const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
const LC_LOAD_WEAK_DYLIB_NORMALIZED: u32 = LC_LOAD_WEAK_DYLIB & !LC_REQ_DYLD;
const LC_REEXPORT_DYLIB_NORMALIZED: u32 = LC_REEXPORT_DYLIB & !LC_REQ_DYLD;

#[derive(Debug, Clone)]
pub(crate) struct MachoBinary {
    pub(crate) segments: Vec<MachoSegment>,
    pub(crate) dylibs: Vec<MachoDylib>,
}

#[derive(Debug, Clone)]
pub(crate) struct MachoSegment {
    pub(crate) name: String,
    pub(crate) initprot: u32,
    pub(crate) maxprot: u32,
    pub(crate) sections: Vec<MachoSection>,
}

#[derive(Debug, Clone)]
pub(crate) struct MachoSection {
    pub(crate) segname: String,
    pub(crate) sectname: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachoDylibKind {
    Normal,
    Weak,
    Reexport,
}

#[derive(Debug, Clone)]
pub(crate) struct MachoDylib {
    pub(crate) path: String,
    pub(crate) kind: MachoDylibKind,
}

#[derive(Debug, Clone, Copy)]
struct MachoHeaderLayout {
    little_endian: bool,
    is_64: bool,
}

pub fn analyze(bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(sections::check(bytes));
    findings.extend(dylibs::check(bytes));
    findings
}

pub(crate) fn parse_binary(bytes: &[u8]) -> Option<MachoBinary> {
    match macho_magic(bytes)? {
        MachoMagic::Thin(layout) => parse_thin(bytes, 0, layout),
        MachoMagic::Fat {
            little_endian,
            is_64,
        } => parse_fat(bytes, little_endian, is_64),
    }
}

enum MachoMagic {
    Thin(MachoHeaderLayout),
    Fat { little_endian: bool, is_64: bool },
}

fn macho_magic(bytes: &[u8]) -> Option<MachoMagic> {
    match bytes.get(0..4)? {
        [0xCF, 0xFA, 0xED, 0xFE] => Some(MachoMagic::Thin(MachoHeaderLayout {
            little_endian: true,
            is_64: true,
        })),
        [0xCE, 0xFA, 0xED, 0xFE] => Some(MachoMagic::Thin(MachoHeaderLayout {
            little_endian: true,
            is_64: false,
        })),
        [0xFE, 0xED, 0xFA, 0xCF] => Some(MachoMagic::Thin(MachoHeaderLayout {
            little_endian: false,
            is_64: true,
        })),
        [0xFE, 0xED, 0xFA, 0xCE] => Some(MachoMagic::Thin(MachoHeaderLayout {
            little_endian: false,
            is_64: false,
        })),
        [0xCA, 0xFE, 0xBA, 0xBE] => Some(MachoMagic::Fat {
            little_endian: false,
            is_64: false,
        }),
        [0xBE, 0xBA, 0xFE, 0xCA] => Some(MachoMagic::Fat {
            little_endian: true,
            is_64: false,
        }),
        [0xCA, 0xFE, 0xBA, 0xBF] => Some(MachoMagic::Fat {
            little_endian: false,
            is_64: true,
        }),
        [0xBF, 0xBA, 0xFE, 0xCA] => Some(MachoMagic::Fat {
            little_endian: true,
            is_64: true,
        }),
        _ => None,
    }
}

fn parse_fat(bytes: &[u8], little_endian: bool, is_64: bool) -> Option<MachoBinary> {
    let nfat_arch = read_u32(bytes, 4, little_endian)? as usize;
    if nfat_arch == 0 || nfat_arch > 16 {
        return None;
    }

    let arch_size = if is_64 { 32 } else { 20 };
    let table_end = 8usize.checked_add(nfat_arch.checked_mul(arch_size)?)?;
    if table_end > bytes.len() {
        return None;
    }

    let first_arch = 8usize;
    let offset = if is_64 {
        read_u64(bytes, first_arch + 8, little_endian)? as usize
    } else {
        read_u32(bytes, first_arch + 8, little_endian)? as usize
    };
    let size = if is_64 {
        read_u64(bytes, first_arch + 16, little_endian)? as usize
    } else {
        read_u32(bytes, first_arch + 12, little_endian)? as usize
    };

    let slice = bytes.get(offset..offset.checked_add(size)?)?;
    let MachoMagic::Thin(layout) = macho_magic(slice)? else {
        return None;
    };
    parse_thin(slice, 0, layout)
}

fn parse_thin(bytes: &[u8], base_offset: usize, layout: MachoHeaderLayout) -> Option<MachoBinary> {
    let header_size = if layout.is_64 { 32usize } else { 28usize };
    let header = bytes.get(base_offset..base_offset.checked_add(header_size)?)?;
    let ncmds = read_u32(header, 16, layout.little_endian)? as usize;
    let sizeofcmds = read_u32(header, 20, layout.little_endian)? as usize;
    if ncmds > 128 {
        return None;
    }

    let load_start = base_offset.checked_add(header_size)?;
    let load_end = load_start.checked_add(sizeofcmds)?;
    if load_end > bytes.len() {
        return None;
    }

    let mut cursor = load_start;
    let mut segments = Vec::new();
    let mut dylibs = Vec::new();
    for _ in 0..ncmds {
        let command = bytes.get(cursor..cursor.checked_add(8)?)?;
        let cmd = read_u32(command, 0, layout.little_endian)?;
        let cmdsize = read_u32(command, 4, layout.little_endian)? as usize;
        if cmdsize < 8 {
            return None;
        }
        let command_bytes = bytes.get(cursor..cursor.checked_add(cmdsize)?)?;
        let normalized_cmd = cmd & !LC_REQ_DYLD;

        match normalized_cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let segment =
                    parse_segment(command_bytes, layout, normalized_cmd == LC_SEGMENT_64)?;
                segments.push(segment);
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB_NORMALIZED | LC_REEXPORT_DYLIB_NORMALIZED => {
                let dylib = parse_dylib_name(command_bytes, layout.little_endian)?;
                if !dylib.is_empty() {
                    let kind = match normalized_cmd {
                        LC_LOAD_WEAK_DYLIB_NORMALIZED => MachoDylibKind::Weak,
                        LC_REEXPORT_DYLIB_NORMALIZED => MachoDylibKind::Reexport,
                        _ => MachoDylibKind::Normal,
                    };
                    dylibs.push(MachoDylib {
                        path: dylib.to_ascii_lowercase(),
                        kind,
                    });
                }
            }
            _ => {}
        }

        cursor = cursor.checked_add(cmdsize)?;
        if cursor > load_end {
            return None;
        }
    }

    Some(MachoBinary { segments, dylibs })
}

fn parse_segment(bytes: &[u8], layout: MachoHeaderLayout, is_64: bool) -> Option<MachoSegment> {
    let segment_min_size = if is_64 { 72usize } else { 56usize };
    if bytes.len() < segment_min_size {
        return None;
    }

    let name = read_fixed_string(bytes.get(8..24)?).to_ascii_lowercase();
    let (maxprot_offset, initprot_offset, nsects_offset, sections_offset, section_size) = if is_64 {
        (56usize, 60usize, 64usize, 72usize, 80usize)
    } else {
        (36usize, 40usize, 48usize, 56usize, 68usize)
    };
    let maxprot = read_u32(bytes, maxprot_offset, layout.little_endian)?;
    let initprot = read_u32(bytes, initprot_offset, layout.little_endian)?;
    let nsects = read_u32(bytes, nsects_offset, layout.little_endian)? as usize;
    if nsects > 128 {
        return None;
    }

    let sections_end = sections_offset.checked_add(nsects.checked_mul(section_size)?)?;
    if sections_end > bytes.len() {
        return None;
    }

    let mut sections = Vec::with_capacity(nsects);
    for index in 0..nsects {
        let section_offset = sections_offset + index * section_size;
        let sectname =
            read_fixed_string(bytes.get(section_offset..section_offset + 16)?).to_ascii_lowercase();
        let segname = read_fixed_string(bytes.get(section_offset + 16..section_offset + 32)?)
            .to_ascii_lowercase();
        sections.push(MachoSection { segname, sectname });
    }

    Some(MachoSegment {
        name,
        initprot,
        maxprot,
        sections,
    })
}

fn parse_dylib_name(bytes: &[u8], little_endian: bool) -> Option<String> {
    if bytes.len() < 24 {
        return None;
    }
    let name_offset = read_u32(bytes, 8, little_endian)? as usize;
    let slice = bytes.get(name_offset..)?;
    Some(read_fixed_string(slice))
}

fn read_fixed_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
    } else {
        u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
    })
}

fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(if little_endian {
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    } else {
        u64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    })
}
