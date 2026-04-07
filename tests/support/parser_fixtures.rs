use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static TEMP_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub struct PeSectionSpec<'a> {
    pub name: &'a str,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Copy)]
pub struct PeImportSpec<'a> {
    pub dll: &'a str,
    pub functions: &'a [&'a str],
}

#[derive(Clone, Copy)]
pub struct ElfSymbolSpec<'a> {
    pub name: &'a str,
}

#[derive(Clone, Copy)]
pub struct ElfSymbolTableSpec<'a> {
    pub dyn_symbols: &'a [ElfSymbolSpec<'a>],
    pub static_symbols: &'a [ElfSymbolSpec<'a>],
}

#[derive(Clone, Copy)]
pub struct MachoSegmentSpec<'a> {
    pub name: &'a str,
    pub maxprot: u32,
    pub initprot: u32,
    pub sections: &'a [&'a str],
}

#[derive(Clone, Copy)]
pub struct MachoDylibSpec<'a> {
    pub path: &'a str,
    pub command: u32,
}

pub fn unique_temp_path(prefix: &str, extension: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let counter = TEMP_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("{prefix}_{pid}_{nanos}_{counter}.{extension}"))
}

pub fn build_test_pe(section_specs: &[PeSectionSpec<'_>], payload: &[u8]) -> Vec<u8> {
    build_test_pe_with_imports(section_specs, &[], payload)
}

pub fn build_standard_pe(payload: &[u8]) -> Vec<u8> {
    build_test_pe(
        &[
            PeSectionSpec {
                name: ".text",
                virtual_size: 0x900,
                raw_size: 0x400,
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".rdata",
                virtual_size: 0x600,
                raw_size: 0x200,
                characteristics: 0x4000_0040,
            },
            PeSectionSpec {
                name: ".rsrc",
                virtual_size: 0x400,
                raw_size: 0x200,
                characteristics: 0x4000_0040,
            },
        ],
        payload,
    )
}

pub fn build_standard_pe_with_imports(imports: &[PeImportSpec<'_>], payload: &[u8]) -> Vec<u8> {
    build_test_pe_with_imports(
        &[
            PeSectionSpec {
                name: ".text",
                virtual_size: 0x900,
                raw_size: 0x400,
                characteristics: 0x6000_0020,
            },
            PeSectionSpec {
                name: ".rdata",
                virtual_size: 0x600,
                raw_size: 0x200,
                characteristics: 0x4000_0040,
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

pub fn build_test_pe_with_imports(
    section_specs: &[PeSectionSpec<'_>],
    imports: &[PeImportSpec<'_>],
    payload: &[u8],
) -> Vec<u8> {
    build_test_pe_with_imports_and_entrypoint(section_specs, imports, payload, None)
}

pub fn build_test_pe_with_imports_and_entrypoint(
    section_specs: &[PeSectionSpec<'_>],
    imports: &[PeImportSpec<'_>],
    payload: &[u8],
    entrypoint_section: Option<&str>,
) -> Vec<u8> {
    let section_alignment = 0x1000u32;
    let file_alignment = 0x200u32;
    let optional_header_size = 0xE0u16;

    let mut sections = section_specs.to_vec();
    let idata_index = sections
        .iter()
        .position(|section| section.name.eq_ignore_ascii_case(".idata"));

    let headers_size = align(
        0x80 + 4 + 20 + usize::from(optional_header_size) + sections.len() * 40,
        file_alignment as usize,
    );

    let initial_layout = layout_pe_sections(
        &sections,
        headers_size as u32,
        section_alignment,
        file_alignment,
    );

    let import_blob = if let Some(idata_index) = idata_index {
        let blob = build_import_blob(imports, initial_layout[idata_index].virtual_address);
        sections[idata_index].raw_size = sections[idata_index].raw_size.max(blob.len() as u32);
        sections[idata_index].virtual_size =
            sections[idata_index].virtual_size.max(blob.len() as u32);
        blob
    } else {
        Vec::new()
    };

    let layout = layout_pe_sections(
        &sections,
        headers_size as u32,
        section_alignment,
        file_alignment,
    );

    let mut bytes = vec![0u8; headers_size];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());

    let pe_offset = 0x80usize;
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    bytes[pe_offset + 4..pe_offset + 6].copy_from_slice(&(0x14cu16).to_le_bytes());
    bytes[pe_offset + 6..pe_offset + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    bytes[pe_offset + 20..pe_offset + 22].copy_from_slice(&optional_header_size.to_le_bytes());
    bytes[pe_offset + 22..pe_offset + 24].copy_from_slice(&(0x210Eu16).to_le_bytes());

    let optional_offset = pe_offset + 24;
    bytes[optional_offset..optional_offset + 2].copy_from_slice(&(0x10Bu16).to_le_bytes());
    let entrypoint_rva = entrypoint_section
        .and_then(|name| {
            sections
                .iter()
                .position(|section| section.name.eq_ignore_ascii_case(name))
                .and_then(|idx| layout.get(idx))
                .map(|layout| layout.virtual_address)
        })
        .or_else(|| layout.first().map(|section| section.virtual_address))
        .unwrap_or(section_alignment);
    bytes[optional_offset + 16..optional_offset + 20]
        .copy_from_slice(&entrypoint_rva.to_le_bytes());
    bytes[optional_offset + 32..optional_offset + 36]
        .copy_from_slice(&section_alignment.to_le_bytes());
    bytes[optional_offset + 36..optional_offset + 40]
        .copy_from_slice(&file_alignment.to_le_bytes());

    let section_table = optional_offset + usize::from(optional_header_size);
    let mut idata_directory = None;

    for (index, section) in sections.iter().enumerate() {
        let section_layout = &layout[index];
        let offset = section_table + index * 40;
        let mut name_bytes = [0u8; 8];
        let source = section.name.as_bytes();
        let copy_len = source.len().min(8);
        name_bytes[..copy_len].copy_from_slice(&source[..copy_len]);
        bytes[offset..offset + 8].copy_from_slice(&name_bytes);
        bytes[offset + 8..offset + 12].copy_from_slice(&section.virtual_size.to_le_bytes());
        bytes[offset + 12..offset + 16]
            .copy_from_slice(&section_layout.virtual_address.to_le_bytes());
        bytes[offset + 16..offset + 20].copy_from_slice(&section.raw_size.to_le_bytes());
        bytes[offset + 20..offset + 24].copy_from_slice(&section_layout.raw_pointer.to_le_bytes());
        bytes[offset + 36..offset + 40].copy_from_slice(&section.characteristics.to_le_bytes());

        let aligned_raw_size = align_u32(section.raw_size.max(1), file_alignment);
        if bytes.len() < section_layout.raw_pointer as usize + aligned_raw_size as usize {
            bytes.resize(
                section_layout.raw_pointer as usize + aligned_raw_size as usize,
                0,
            );
        }

        if section.name.eq_ignore_ascii_case(".idata") && !import_blob.is_empty() {
            let start = section_layout.raw_pointer as usize;
            let end = start + import_blob.len();
            bytes[start..end].copy_from_slice(&import_blob);
            idata_directory = Some((section_layout.virtual_address, import_blob.len() as u32));
        }
    }

    if let Some((import_rva, import_size)) = idata_directory {
        let import_dir_offset = optional_offset + 96 + 8;
        bytes[import_dir_offset..import_dir_offset + 4].copy_from_slice(&import_rva.to_le_bytes());
        bytes[import_dir_offset + 4..import_dir_offset + 8]
            .copy_from_slice(&import_size.to_le_bytes());
    }

    bytes.extend_from_slice(payload);
    bytes
}

#[derive(Clone, Copy)]
struct PeSectionLayout {
    virtual_address: u32,
    raw_pointer: u32,
}

fn layout_pe_sections(
    sections: &[PeSectionSpec<'_>],
    headers_size: u32,
    section_alignment: u32,
    file_alignment: u32,
) -> Vec<PeSectionLayout> {
    let mut raw_pointer = headers_size;
    let mut virtual_address = section_alignment;
    let mut layout = Vec::with_capacity(sections.len());

    for section in sections {
        layout.push(PeSectionLayout {
            virtual_address,
            raw_pointer,
        });
        raw_pointer =
            raw_pointer.saturating_add(align_u32(section.raw_size.max(1), file_alignment));
        virtual_address = virtual_address
            .saturating_add(align_u32(section.virtual_size.max(1), section_alignment));
    }

    layout
}

pub fn malformed_pe_bad_lfanew() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x40];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(0xFFFF_FFF0u32).to_le_bytes());
    bytes
}

pub fn malformed_pe_truncated_section_table() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x120];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&(5u16).to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&(0xE0u16).to_le_bytes());
    bytes
}

pub fn malformed_pe_bad_import_directory() -> Vec<u8> {
    let mut bytes = build_test_pe(
        &[PeSectionSpec {
            name: ".text",
            virtual_size: 0x400,
            raw_size: 0x200,
            characteristics: 0x6000_0020,
        }],
        b"notes",
    );
    let optional_offset = 0x80 + 24;
    let import_dir_offset = optional_offset + 96 + 8;
    bytes[import_dir_offset..import_dir_offset + 4]
        .copy_from_slice(&(0xFFFF_0000u32).to_le_bytes());
    bytes[import_dir_offset + 4..import_dir_offset + 8].copy_from_slice(&(64u32).to_le_bytes());
    bytes
}

pub fn build_test_elf(section_names: &[&str], interp: Option<&str>, payload: &[u8]) -> Vec<u8> {
    build_test_elf_with_symbol_tables(
        section_names,
        interp,
        ElfSymbolTableSpec {
            dyn_symbols: &[],
            static_symbols: &[],
        },
        payload,
    )
}

pub fn build_standard_elf(payload: &[u8]) -> Vec<u8> {
    build_test_elf(
        &[".text", ".dynamic", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        payload,
    )
}

pub fn build_standard_elf_with_symbols(symbols: &[ElfSymbolSpec<'_>], payload: &[u8]) -> Vec<u8> {
    build_test_elf_with_symbols(
        &[
            ".text",
            ".dynamic",
            ".dynstr",
            ".dynsym",
            ".interp",
            ".shstrtab",
        ],
        Some("/lib64/ld-linux-x86-64.so.2"),
        symbols,
        payload,
    )
}

pub fn build_test_elf_with_symbols(
    section_names: &[&str],
    interp: Option<&str>,
    symbols: &[ElfSymbolSpec<'_>],
    payload: &[u8],
) -> Vec<u8> {
    build_test_elf_with_symbol_tables(
        section_names,
        interp,
        ElfSymbolTableSpec {
            dyn_symbols: symbols,
            static_symbols: &[],
        },
        payload,
    )
}

pub fn build_test_elf_with_symbol_tables(
    section_names: &[&str],
    interp: Option<&str>,
    symbol_tables: ElfSymbolTableSpec<'_>,
    payload: &[u8],
) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    let mut name_offsets = Vec::new();
    for name in section_names {
        name_offsets.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }

    let dynstr_index = section_names.iter().position(|name| *name == ".dynstr");
    let dynsym_index = section_names.iter().position(|name| *name == ".dynsym");
    let strtab_index = section_names.iter().position(|name| *name == ".strtab");
    let symtab_index = section_names.iter().position(|name| *name == ".symtab");
    let dynstr = build_elf_string_table(symbol_tables.dyn_symbols);
    let dynsym = build_elf_symbol_table(
        symbol_tables.dyn_symbols,
        dynsym_index.is_some() && dynstr_index.is_some(),
    );
    let strtab = build_elf_string_table(symbol_tables.static_symbols);
    let symtab = build_elf_symbol_table(
        symbol_tables.static_symbols,
        symtab_index.is_some() && strtab_index.is_some(),
    );

    let section_count = section_names.len() + 1;
    let sh_entry_size = 64usize;
    let sh_table_offset = 0x100usize;
    let mut bytes = vec![0u8; sh_table_offset + section_count * sh_entry_size];

    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x28..0x30].copy_from_slice(&(sh_table_offset as u64).to_le_bytes());
    bytes[0x3a..0x3c].copy_from_slice(&(sh_entry_size as u16).to_le_bytes());
    bytes[0x3c..0x3e].copy_from_slice(&(section_count as u16).to_le_bytes());
    bytes[0x3e..0x40].copy_from_slice(&((section_count - 1) as u16).to_le_bytes());

    let mut data_offset = 0x400usize;
    for (index, name) in section_names.iter().enumerate() {
        let sh_offset = sh_table_offset + (index + 1) * sh_entry_size;
        bytes[sh_offset..sh_offset + 4].copy_from_slice(&name_offsets[index].to_le_bytes());
        let (section_type, link, entry_size, section_bytes) = if *name == ".interp" {
            let mut value = interp
                .unwrap_or("/lib64/ld-linux-x86-64.so.2")
                .as_bytes()
                .to_vec();
            value.push(0);
            (1u32, 0u32, 0u64, value)
        } else if *name == ".dynstr" {
            (3u32, 0u32, 0u64, dynstr.clone())
        } else if *name == ".dynsym" {
            let link = dynstr_index.map(|value| (value + 1) as u32).unwrap_or(0);
            (11u32, link, 24u64, dynsym.clone())
        } else if *name == ".strtab" {
            (3u32, 0u32, 0u64, strtab.clone())
        } else if *name == ".symtab" {
            let link = strtab_index.map(|value| (value + 1) as u32).unwrap_or(0);
            (2u32, link, 24u64, symtab.clone())
        } else if *name == ".shstrtab" {
            (3u32, 0u32, 0u64, shstrtab.clone())
        } else {
            (1u32, 0u32, 0u64, payload.to_vec())
        };
        bytes[sh_offset + 4..sh_offset + 8].copy_from_slice(&section_type.to_le_bytes());
        bytes[sh_offset + 40..sh_offset + 44].copy_from_slice(&link.to_le_bytes());
        bytes[sh_offset + 56..sh_offset + 64].copy_from_slice(&entry_size.to_le_bytes());

        let size = section_bytes.len();
        if bytes.len() < data_offset + size {
            bytes.resize(data_offset + size, 0);
        }
        bytes[data_offset..data_offset + size].copy_from_slice(&section_bytes);
        bytes[sh_offset + 24..sh_offset + 32].copy_from_slice(&(data_offset as u64).to_le_bytes());
        bytes[sh_offset + 32..sh_offset + 40].copy_from_slice(&(size as u64).to_le_bytes());
        data_offset += size.max(1);
    }

    bytes
}

pub fn malformed_elf_bad_bounds() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x80];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x28..0x30].copy_from_slice(&(0x200u64).to_le_bytes());
    bytes[0x3a..0x3c].copy_from_slice(&(64u16).to_le_bytes());
    bytes[0x3c..0x3e].copy_from_slice(&(8u16).to_le_bytes());
    bytes[0x3e..0x40].copy_from_slice(&(1u16).to_le_bytes());
    bytes
}

pub fn malformed_elf_bad_shstrtab() -> Vec<u8> {
    let mut bytes = build_test_elf(&[".text", ".interp", ".shstrtab"], None, b"");
    bytes[0x3e..0x40].copy_from_slice(&(7u16).to_le_bytes());
    bytes
}

pub fn malformed_elf_bad_symbol_table() -> Vec<u8> {
    let mut bytes = build_test_elf_with_symbols(
        &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
        ],
        b"placeholder",
    );
    let sh_table_offset = 0x100usize;
    let dynsym_offset = sh_table_offset + 3 * 64;
    bytes[dynsym_offset + 40..dynsym_offset + 44].copy_from_slice(&(99u32).to_le_bytes());
    bytes
}

pub fn malformed_elf_truncated_dynsym() -> Vec<u8> {
    let mut bytes = build_test_elf_with_symbols(
        &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
            ElfSymbolSpec { name: "mprotect" },
        ],
        b"placeholder",
    );
    let sh_offset = elf_section_header_offset(3);
    bytes[sh_offset + 32..sh_offset + 40].copy_from_slice(&(25u64).to_le_bytes());
    bytes
}

pub fn malformed_elf_truncated_dynstr() -> Vec<u8> {
    let mut bytes = build_test_elf_with_symbols(
        &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
        ],
        b"placeholder",
    );
    let sh_offset = elf_section_header_offset(2);
    bytes[sh_offset + 32..sh_offset + 40].copy_from_slice(&(4u64).to_le_bytes());
    bytes
}

pub fn malformed_elf_invalid_symbol_entry_size() -> Vec<u8> {
    let mut bytes = build_test_elf_with_symbols(
        &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
        ],
        b"placeholder",
    );
    let sh_offset = elf_section_header_offset(3);
    bytes[sh_offset + 56..sh_offset + 64].copy_from_slice(&(3u64).to_le_bytes());
    bytes
}

pub fn malformed_elf_symbol_name_out_of_bounds() -> Vec<u8> {
    let mut bytes = build_test_elf_with_symbols(
        &[".text", ".dynstr", ".dynsym", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        &[
            ElfSymbolSpec { name: "dlopen" },
            ElfSymbolSpec { name: "dlsym" },
        ],
        b"placeholder",
    );
    let dynsym_data_offset = elf_section_data_offset(&bytes, 3);
    let first_symbol_offset = dynsym_data_offset + 24;
    bytes[first_symbol_offset..first_symbol_offset + 4].copy_from_slice(&(0xFFFFu32).to_le_bytes());
    bytes
}

pub fn malformed_elf_partial_loader_symbols() -> Vec<u8> {
    let mut bytes = malformed_elf_bad_bounds();
    bytes.extend_from_slice(b"\x7fELF dlopen dlsym mprotect /proc/self/exe");
    bytes
}

pub fn malformed_elf_bad_static_symbol_table() -> Vec<u8> {
    let mut bytes = build_test_elf_with_symbol_tables(
        &[".text", ".strtab", ".symtab", ".interp", ".shstrtab"],
        Some("/lib64/ld-linux-x86-64.so.2"),
        ElfSymbolTableSpec {
            dyn_symbols: &[],
            static_symbols: &[
                ElfSymbolSpec { name: "execve" },
                ElfSymbolSpec { name: "socket" },
            ],
        },
        b"placeholder",
    );
    let symtab_offset = elf_section_header_offset(3);
    bytes[symtab_offset + 40..symtab_offset + 44].copy_from_slice(&(99u32).to_le_bytes());
    bytes
}

fn elf_section_header_offset(index: usize) -> usize {
    0x100 + index * 64
}

fn elf_section_data_offset(bytes: &[u8], index: usize) -> usize {
    let offset = elf_section_header_offset(index) + 24;
    let slice = &bytes[offset..offset + 8];
    u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]) as usize
}

fn build_elf_string_table(symbols: &[ElfSymbolSpec<'_>]) -> Vec<u8> {
    let mut dynstr = vec![0u8];
    for symbol in symbols {
        dynstr.extend_from_slice(symbol.name.as_bytes());
        dynstr.push(0);
    }
    dynstr
}

fn build_elf_symbol_table(symbols: &[ElfSymbolSpec<'_>], enabled: bool) -> Vec<u8> {
    if !enabled {
        return Vec::new();
    }

    let mut dynsym = vec![0u8; 24];
    let mut name_offset = 1u32;
    for symbol in symbols {
        dynsym.extend_from_slice(&name_offset.to_le_bytes());
        dynsym.push(0x12);
        dynsym.push(0);
        dynsym.extend_from_slice(&0u16.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        dynsym.extend_from_slice(&0u64.to_le_bytes());
        name_offset = name_offset.saturating_add(symbol.name.len() as u32 + 1);
    }
    dynsym
}

pub fn build_test_macho(
    segments: &[MachoSegmentSpec<'_>],
    dylibs: &[&str],
    payload: &[u8],
) -> Vec<u8> {
    let dylibs = dylibs
        .iter()
        .map(|path| MachoDylibSpec { path, command: 0xC })
        .collect::<Vec<_>>();
    build_test_macho_with_dylib_specs(segments, &dylibs, payload)
}

pub fn build_test_macho_with_dylib_specs(
    segments: &[MachoSegmentSpec<'_>],
    dylibs: &[MachoDylibSpec<'_>],
    payload: &[u8],
) -> Vec<u8> {
    build_test_macho_with_magic(0xFEEDFACF, segments, dylibs, payload)
}

pub fn build_standard_macho(payload: &[u8]) -> Vec<u8> {
    build_test_macho(
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
        payload,
    )
}

pub fn build_test_fat_macho(thin: &[u8]) -> Vec<u8> {
    let header_size = 8usize + 20usize;
    let thin_offset = align(header_size, 0x1000);
    let mut bytes = vec![0u8; thin_offset + thin.len()];
    bytes[0..4].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
    bytes[4..8].copy_from_slice(&(1u32).to_be_bytes());
    bytes[8..12].copy_from_slice(&(0x0100_0007u32).to_be_bytes());
    bytes[12..16].copy_from_slice(&(3u32).to_be_bytes());
    bytes[16..20].copy_from_slice(&(thin_offset as u32).to_be_bytes());
    bytes[20..24].copy_from_slice(&(thin.len() as u32).to_be_bytes());
    bytes[24..28].copy_from_slice(&(12u32).to_be_bytes());
    bytes[thin_offset..thin_offset + thin.len()].copy_from_slice(thin);
    bytes
}

pub fn malformed_macho_bad_load_command() -> Vec<u8> {
    let mut bytes = build_standard_macho(b"notes");
    bytes[16..20].copy_from_slice(&(1u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(8u32).to_le_bytes());
    bytes[32..36].copy_from_slice(&(0x19u32).to_le_bytes());
    bytes[36..40].copy_from_slice(&(4u32).to_le_bytes());
    bytes
}

pub fn malformed_macho_bad_dylib_name_offset() -> Vec<u8> {
    let mut bytes = build_test_macho(
        &[MachoSegmentSpec {
            name: "__TEXT",
            maxprot: 5,
            initprot: 5,
            sections: &["__text"],
        }],
        &["/usr/lib/libSystem.B.dylib"],
        b"notes",
    );
    let first_command = 32usize;
    let segment_cmdsize = u32::from_le_bytes(
        bytes[first_command + 4..first_command + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let dylib_offset = first_command + segment_cmdsize;
    bytes[dylib_offset + 8..dylib_offset + 12].copy_from_slice(&(0xFFFFu32).to_le_bytes());
    bytes
}

fn build_test_macho_with_magic(
    magic: u32,
    segments: &[MachoSegmentSpec<'_>],
    dylibs: &[MachoDylibSpec<'_>],
    payload: &[u8],
) -> Vec<u8> {
    let segment_commands_size = segments
        .iter()
        .map(|segment| 72usize + segment.sections.len() * 80usize)
        .sum::<usize>();
    let dylib_commands_size = dylibs
        .iter()
        .map(|dylib| align(24usize + dylib.path.len() + 1, 8))
        .sum::<usize>();
    let header_size = 32usize;
    let sizeofcmds = segment_commands_size + dylib_commands_size;
    let mut bytes = vec![0u8; header_size + sizeofcmds + payload.len()];

    bytes[0..4].copy_from_slice(&magic.to_le_bytes());
    bytes[4..8].copy_from_slice(&(0x0100_0007u32).to_le_bytes());
    bytes[8..12].copy_from_slice(&(3u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&(2u32).to_le_bytes());
    bytes[16..20].copy_from_slice(&((segments.len() + dylibs.len()) as u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());
    bytes[24..28].copy_from_slice(&(0u32).to_le_bytes());
    bytes[28..32].copy_from_slice(&(0u32).to_le_bytes());

    let mut cursor = header_size;
    let section_data_cursor = header_size + sizeofcmds;
    for segment in segments {
        let cmdsize = 72usize + segment.sections.len() * 80usize;
        bytes[cursor..cursor + 4].copy_from_slice(&(0x19u32).to_le_bytes());
        bytes[cursor + 4..cursor + 8].copy_from_slice(&(cmdsize as u32).to_le_bytes());
        write_fixed_name(&mut bytes[cursor + 8..cursor + 24], segment.name);
        bytes[cursor + 40..cursor + 48].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes[cursor + 56..cursor + 60].copy_from_slice(&segment.maxprot.to_le_bytes());
        bytes[cursor + 60..cursor + 64].copy_from_slice(&segment.initprot.to_le_bytes());
        bytes[cursor + 64..cursor + 68]
            .copy_from_slice(&(segment.sections.len() as u32).to_le_bytes());

        for (index, section_name) in segment.sections.iter().enumerate() {
            let section_offset = cursor + 72 + index * 80;
            write_fixed_name(
                &mut bytes[section_offset..section_offset + 16],
                section_name,
            );
            write_fixed_name(
                &mut bytes[section_offset + 16..section_offset + 32],
                segment.name,
            );
            bytes[section_offset + 48..section_offset + 52]
                .copy_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes[section_offset + 52..section_offset + 56]
                .copy_from_slice(&(section_data_cursor as u32).to_le_bytes());
        }

        cursor += cmdsize;
    }

    for dylib in dylibs {
        let cmdsize = align(24usize + dylib.path.len() + 1, 8);
        bytes[cursor..cursor + 4].copy_from_slice(&dylib.command.to_le_bytes());
        bytes[cursor + 4..cursor + 8].copy_from_slice(&(cmdsize as u32).to_le_bytes());
        bytes[cursor + 8..cursor + 12].copy_from_slice(&(24u32).to_le_bytes());
        let name_start = cursor + 24;
        bytes[name_start..name_start + dylib.path.len()].copy_from_slice(dylib.path.as_bytes());
        bytes[name_start + dylib.path.len()] = 0;
        cursor += cmdsize;
    }

    bytes[section_data_cursor..section_data_cursor + payload.len()].copy_from_slice(payload);
    bytes
}

fn write_fixed_name(slot: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(slot.len());
    slot[..copy_len].copy_from_slice(&bytes[..copy_len]);
    for byte in &mut slot[copy_len..] {
        *byte = 0;
    }
}

fn build_import_blob(imports: &[PeImportSpec<'_>], section_rva: u32) -> Vec<u8> {
    if imports.is_empty() {
        return Vec::new();
    }

    let descriptor_count = imports.len() + 1;
    let descriptor_bytes = descriptor_count * 20;
    let thunk_entry_size = 4usize;
    let mut cursor = descriptor_bytes;

    let mut ilt_rvas = Vec::with_capacity(imports.len());
    let mut iat_rvas = Vec::with_capacity(imports.len());
    let mut dll_rvas = Vec::with_capacity(imports.len());
    let mut hint_name_rvas: Vec<Vec<u32>> = Vec::with_capacity(imports.len());

    for import in imports {
        ilt_rvas.push(section_rva + cursor as u32);
        for _ in import.functions {
            cursor += thunk_entry_size;
        }
        cursor += thunk_entry_size;

        iat_rvas.push(section_rva + cursor as u32);
        for _ in import.functions {
            cursor += thunk_entry_size;
        }
        cursor += thunk_entry_size;
    }

    for import in imports {
        let mut names = Vec::with_capacity(import.functions.len());
        for function in import.functions {
            let rva = section_rva + cursor as u32;
            names.push(rva);
            cursor += 2 + function.len() + 1;
            if cursor % 2 != 0 {
                cursor += 1;
            }
        }
        hint_name_rvas.push(names);
    }

    for import in imports {
        let rva = section_rva + cursor as u32;
        dll_rvas.push(rva);
        cursor += import.dll.len() + 1;
    }

    let mut blob = vec![0u8; cursor];

    for (index, _) in imports.iter().enumerate() {
        let ilt_offset = (ilt_rvas[index] - section_rva) as usize;
        let iat_offset = (iat_rvas[index] - section_rva) as usize;
        for (func_index, name_rva) in hint_name_rvas[index].iter().enumerate() {
            let entry_offset = ilt_offset + func_index * 4;
            blob[entry_offset..entry_offset + 4].copy_from_slice(&name_rva.to_le_bytes());
            let iat_entry = iat_offset + func_index * 4;
            blob[iat_entry..iat_entry + 4].copy_from_slice(&name_rva.to_le_bytes());
        }

        let descriptor_offset = index * 20;
        blob[descriptor_offset..descriptor_offset + 4]
            .copy_from_slice(&ilt_rvas[index].to_le_bytes());
        blob[descriptor_offset + 12..descriptor_offset + 16]
            .copy_from_slice(&dll_rvas[index].to_le_bytes());
        blob[descriptor_offset + 16..descriptor_offset + 20]
            .copy_from_slice(&iat_rvas[index].to_le_bytes());
    }

    for (index, import) in imports.iter().enumerate() {
        for (func_index, function) in import.functions.iter().enumerate() {
            let name_offset = (hint_name_rvas[index][func_index] - section_rva) as usize;
            blob[name_offset..name_offset + 2].copy_from_slice(&0u16.to_le_bytes());
            let string_offset = name_offset + 2;
            blob[string_offset..string_offset + function.len()]
                .copy_from_slice(function.as_bytes());
            blob[string_offset + function.len()] = 0;
        }

        let dll_offset = (dll_rvas[index] - section_rva) as usize;
        blob[dll_offset..dll_offset + import.dll.len()].copy_from_slice(import.dll.as_bytes());
        blob[dll_offset + import.dll.len()] = 0;
    }

    blob
}

fn align(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn align_u32(value: u32, alignment: u32) -> u32 {
    value.div_ceil(alignment) * alignment
}
