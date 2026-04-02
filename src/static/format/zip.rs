use std::io::Read;

use flate2::read::DeflateDecoder;

use crate::r#static::config::ResourceLimits;

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct ZipExtraction {
    pub entries: Vec<ZipEntry>,
    pub hit_entry_limit: bool,
    pub hit_decompression_limit: bool,
    pub unsupported_entries: usize,
}

#[derive(Debug, Clone)]
struct CentralDirectoryEntry {
    name: String,
    compression_method: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    local_header_offset: usize,
}

pub fn has_many_entries(bytes: &[u8]) -> bool {
    central_directory_entries(bytes).len() > 1000
}

pub fn suspicious_entries(bytes: &[u8]) -> Vec<&'static str> {
    let names = central_directory_entries(bytes)
        .into_iter()
        .map(|entry| entry.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let markers = [
        (".exe", ".exe"),
        (".dll", ".dll"),
        (".js", ".js"),
        (".vbs", ".vbs"),
        (".ps1", ".ps1"),
        (".bat", ".bat"),
        (".cmd", ".cmd"),
        ("vbaproject.bin", "vbaProject.bin"),
    ];

    markers
        .into_iter()
        .filter_map(|(needle, label)| {
            names
                .iter()
                .any(|name| name.contains(needle))
                .then_some(label)
        })
        .collect()
}

pub fn nested_archive_markers(bytes: &[u8]) -> usize {
    let names = central_directory_entries(bytes)
        .into_iter()
        .map(|entry| entry.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    [".zip", ".rar", ".7z", ".iso", ".jar"]
        .into_iter()
        .filter(|needle| names.iter().any(|name| name.ends_with(*needle)))
        .count()
}

pub fn extract_entries(bytes: &[u8], limits: &ResourceLimits) -> ZipExtraction {
    let mut out = ZipExtraction::default();
    let mut total_decompressed = 0usize;

    for entry in central_directory_entries(bytes) {
        if out.entries.len() >= limits.max_archive_entries {
            out.hit_entry_limit = true;
            break;
        }

        match extract_entry_data(bytes, &entry, limits.max_extracted_entry_bytes) {
            Some(data) => {
                total_decompressed = total_decompressed.saturating_add(data.len());
                if total_decompressed > limits.max_decompressed_bytes {
                    out.hit_decompression_limit = true;
                    break;
                }
                out.entries.push(ZipEntry {
                    name: entry.name,
                    data,
                });
            }
            None => out.unsupported_entries += 1,
        }
    }

    out
}

fn central_directory_entries(bytes: &[u8]) -> Vec<CentralDirectoryEntry> {
    let Some(eocd) = find_eocd(bytes) else {
        return Vec::new();
    };
    if eocd + 22 > bytes.len() {
        return Vec::new();
    }

    let entry_count = read_u16(bytes, eocd + 10) as usize;
    let central_dir_offset = read_u32(bytes, eocd + 16) as usize;

    let mut entries = Vec::new();
    let mut cursor = central_dir_offset;
    while cursor + 46 <= bytes.len() && entries.len() < entry_count {
        if &bytes[cursor..cursor + 4] != b"PK\x01\x02" {
            break;
        }

        let compression_method = read_u16(bytes, cursor + 10);
        let compressed_size = read_u32(bytes, cursor + 20) as usize;
        let uncompressed_size = read_u32(bytes, cursor + 24) as usize;
        let name_len = read_u16(bytes, cursor + 28) as usize;
        let extra_len = read_u16(bytes, cursor + 30) as usize;
        let comment_len = read_u16(bytes, cursor + 32) as usize;
        let local_header_offset = read_u32(bytes, cursor + 42) as usize;

        let name_start = cursor + 46;
        let name_end = name_start.saturating_add(name_len);
        if name_end > bytes.len() {
            break;
        }

        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_string();
        entries.push(CentralDirectoryEntry {
            name,
            compression_method,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });

        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
    }

    entries
}

fn extract_entry_data(
    bytes: &[u8],
    entry: &CentralDirectoryEntry,
    max_entry_bytes: usize,
) -> Option<Vec<u8>> {
    let header = entry.local_header_offset;
    if header + 30 > bytes.len() || &bytes[header..header + 4] != b"PK\x03\x04" {
        return None;
    }

    let name_len = read_u16(bytes, header + 26) as usize;
    let extra_len = read_u16(bytes, header + 28) as usize;
    let data_start = header + 30 + name_len + extra_len;
    let data_end = data_start.saturating_add(entry.compressed_size);
    if data_end > bytes.len() {
        return None;
    }

    let compressed = &bytes[data_start..data_end];
    let cap = max_entry_bytes.min(entry.uncompressed_size.max(1));
    match entry.compression_method {
        0 => Some(compressed[..compressed.len().min(cap)].to_vec()),
        8 => {
            let decoder = DeflateDecoder::new(compressed);
            let mut data = Vec::new();
            let limit = (cap + 1) as u64;
            if decoder.take(limit).read_to_end(&mut data).is_ok() {
                data.truncate(cap);
                Some(data)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let lower = bytes.len().saturating_sub(22 + 65_535);
    (lower..=bytes.len().saturating_sub(4))
        .rev()
        .find(|&index| &bytes[index..index + 4] == b"PK\x05\x06")
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}
