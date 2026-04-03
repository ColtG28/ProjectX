use std::fs::File;
use std::io::Read;
use std::path::Path;

const STRING_MIN_LEN: usize = 4;
const BYTE_HISTOGRAM_BINS: usize = 32;
pub const FEATURE_COUNT: usize = 74;

pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "size_log2",
    "bytes_examined_log2",
    "truncated_input",
    "entropy",
    "unique_byte_ratio",
    "null_byte_ratio",
    "printable_ratio",
    "ascii_ratio",
    "high_byte_ratio",
    "longest_printable_run_ratio",
    "string_count_log2",
    "avg_string_len",
    "max_string_len_log2",
    "url_string_ratio",
    "path_string_ratio",
    "suspicious_string_ratio",
    "mz_header",
    "pe_valid",
    "pe_is_64",
    "pe_is_dll",
    "pe_num_sections",
    "pe_executable_sections",
    "pe_writable_sections",
    "pe_zero_raw_sections",
    "pe_suspicious_section_name_hits",
    "pe_import_descriptor_count",
    "pe_import_function_count_log2",
    "pe_has_exports",
    "pe_has_resources",
    "pe_has_tls",
    "pe_has_debug",
    "pe_section_entropy_mean",
    "pe_section_entropy_max",
    "pe_entrypoint_ratio",
    "pe_image_size_log2",
    "pe_overlay_ratio",
    "pe_header_anomaly_score",
    "elf_header",
    "pdf_header",
    "zip_header",
    "shebang_header",
    "dos_stub_contains_message",
    "byte_hist_00",
    "byte_hist_01",
    "byte_hist_02",
    "byte_hist_03",
    "byte_hist_04",
    "byte_hist_05",
    "byte_hist_06",
    "byte_hist_07",
    "byte_hist_08",
    "byte_hist_09",
    "byte_hist_10",
    "byte_hist_11",
    "byte_hist_12",
    "byte_hist_13",
    "byte_hist_14",
    "byte_hist_15",
    "byte_hist_16",
    "byte_hist_17",
    "byte_hist_18",
    "byte_hist_19",
    "byte_hist_20",
    "byte_hist_21",
    "byte_hist_22",
    "byte_hist_23",
    "byte_hist_24",
    "byte_hist_25",
    "byte_hist_26",
    "byte_hist_27",
    "byte_hist_28",
    "byte_hist_29",
    "byte_hist_30",
    "byte_hist_31",
];

#[derive(Debug, Clone)]
pub struct ExtractedFeatures {
    pub values: [f32; FEATURE_COUNT],
    pub file_kind: &'static str,
    pub bytes_examined: usize,
    pub file_size_bytes: u64,
    pub truncated_input: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct StringMetrics {
    count: usize,
    avg_len: f32,
    max_len: usize,
    url_ratio: f32,
    path_ratio: f32,
    suspicious_ratio: f32,
    longest_printable_run: usize,
}

#[derive(Debug, Default)]
struct StringScanState {
    count: usize,
    total_len: usize,
    max_len: usize,
    url_hits: usize,
    path_hits: usize,
    suspicious_hits: usize,
}

#[derive(Debug, Clone, Default)]
struct PeMetrics {
    valid: bool,
    is_64: bool,
    is_dll: bool,
    num_sections: usize,
    executable_sections: usize,
    writable_sections: usize,
    zero_raw_sections: usize,
    suspicious_section_names: usize,
    import_descriptors: usize,
    import_functions: usize,
    has_exports: bool,
    has_resources: bool,
    has_tls: bool,
    has_debug: bool,
    section_entropy_mean: f32,
    section_entropy_max: f32,
    entrypoint_ratio: f32,
    image_size_log2: f32,
    overlay_ratio: f32,
    header_anomaly_score: f32,
}

#[derive(Debug, Clone)]
struct SectionInfo {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
}

pub fn feature_names() -> Vec<String> {
    FEATURE_NAMES.iter().map(|item| item.to_string()).collect()
}

pub fn extract_path(path: &Path, max_input_bytes: usize) -> Result<ExtractedFeatures, String> {
    let metadata = path
        .metadata()
        .map_err(|error| format!("Failed to read metadata for {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("Path is not a regular file: {}", path.display()));
    }

    let file_size_bytes = metadata.len();
    let file =
        File::open(path).map_err(|error| format!("Failed to open {}: {error}", path.display()))?;
    let mut buffer = Vec::with_capacity((file_size_bytes as usize).min(max_input_bytes));
    file.take(max_input_bytes as u64)
        .read_to_end(&mut buffer)
        .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;

    let truncated_input = file_size_bytes > buffer.len() as u64;
    let bytes_examined = buffer.len();
    if buffer.is_empty() {
        return Ok(ExtractedFeatures {
            values: [0.0; FEATURE_COUNT],
            file_kind: "empty",
            bytes_examined,
            file_size_bytes,
            truncated_input,
            warning: Some("File is empty".to_string()),
        });
    }

    let byte_stats = compute_byte_stats(&buffer);
    let string_metrics = extract_string_metrics(&buffer);
    let file_kind = detect_kind(&buffer);

    let (pe, warning) = if looks_like_pe(&buffer) {
        match extract_pe_metrics(&buffer) {
            Ok(metrics) => (metrics, None),
            Err(error) => (PeMetrics::default(), Some(error)),
        }
    } else {
        (PeMetrics::default(), None)
    };

    let mut values = [0.0; FEATURE_COUNT];
    let head = [
        log2ish(file_size_bytes as f64),
        log2ish(bytes_examined as f64),
        f32::from(truncated_input),
        byte_stats.entropy,
        byte_stats.unique_ratio,
        byte_stats.null_ratio,
        byte_stats.printable_ratio,
        byte_stats.ascii_ratio,
        byte_stats.high_ratio,
        ratio(string_metrics.longest_printable_run, bytes_examined),
        log2ish(string_metrics.count as f64),
        string_metrics.avg_len,
        log2ish(string_metrics.max_len as f64),
        string_metrics.url_ratio,
        string_metrics.path_ratio,
        string_metrics.suspicious_ratio,
        f32::from(buffer.starts_with(b"MZ")),
        f32::from(pe.valid),
        f32::from(pe.is_64),
        f32::from(pe.is_dll),
        pe.num_sections as f32,
        pe.executable_sections as f32,
        pe.writable_sections as f32,
        pe.zero_raw_sections as f32,
        pe.suspicious_section_names as f32,
        pe.import_descriptors as f32,
        log2ish(pe.import_functions as f64),
        f32::from(pe.has_exports),
        f32::from(pe.has_resources),
        f32::from(pe.has_tls),
        f32::from(pe.has_debug),
        pe.section_entropy_mean,
        pe.section_entropy_max,
        pe.entrypoint_ratio,
        pe.image_size_log2,
        pe.overlay_ratio,
        pe.header_anomaly_score,
        f32::from(buffer.starts_with(b"\x7FELF")),
        f32::from(buffer.starts_with(b"%PDF")),
        f32::from(buffer.starts_with(b"PK\x03\x04")),
        f32::from(buffer.starts_with(b"#!")),
        f32::from(slice_contains(&buffer, b"This program cannot be run")),
    ];
    values[..head.len()].copy_from_slice(&head);
    values[head.len()..].copy_from_slice(&byte_stats.histogram);

    Ok(ExtractedFeatures {
        values,
        file_kind,
        bytes_examined,
        file_size_bytes,
        truncated_input,
        warning,
    })
}

fn detect_kind(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MZ") {
        "pe"
    } else if bytes.starts_with(b"\x7FELF") {
        "elf"
    } else if bytes.starts_with(b"%PDF") {
        "pdf"
    } else if bytes.starts_with(b"PK\x03\x04") {
        "zip"
    } else if bytes.starts_with(b"#!") {
        "script"
    } else {
        "binary"
    }
}

#[derive(Debug, Clone)]
struct ByteStats {
    histogram: [f32; BYTE_HISTOGRAM_BINS],
    entropy: f32,
    unique_ratio: f32,
    null_ratio: f32,
    printable_ratio: f32,
    ascii_ratio: f32,
    high_ratio: f32,
}

fn compute_byte_stats(bytes: &[u8]) -> ByteStats {
    let mut counts = [0usize; 256];
    let mut bins = [0usize; BYTE_HISTOGRAM_BINS];
    let mut null_count = 0usize;
    let mut printable_count = 0usize;
    let mut ascii_count = 0usize;
    let mut high_count = 0usize;

    for &byte in bytes {
        counts[byte as usize] += 1;
        bins[(byte as usize) >> 3] += 1;
        null_count += usize::from(byte == 0);
        printable_count += usize::from(is_printable_ascii(byte));
        ascii_count += usize::from(byte.is_ascii());
        high_count += usize::from(byte >= 0x80);
    }

    let len = bytes.len() as f32;
    let mut entropy = 0.0f32;
    let mut unique_count = 0usize;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        unique_count += 1;
        let p = count as f32 / len;
        entropy -= p * p.log2();
    }

    let mut histogram = [0.0; BYTE_HISTOGRAM_BINS];
    for (slot, count) in histogram.iter_mut().zip(bins) {
        *slot = ratio(count, bytes.len());
    }

    ByteStats {
        histogram,
        entropy,
        unique_ratio: ratio(unique_count, 256),
        null_ratio: ratio(null_count, bytes.len()),
        printable_ratio: ratio(printable_count, bytes.len()),
        ascii_ratio: ratio(ascii_count, bytes.len()),
        high_ratio: ratio(high_count, bytes.len()),
    }
}

fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    compute_byte_stats(bytes).entropy
}

fn extract_string_metrics(bytes: &[u8]) -> StringMetrics {
    let mut state = StringScanState::default();
    let mut longest_printable_run = 0usize;
    let mut current_start = 0usize;
    let mut current_len = 0usize;

    for (index, &byte) in bytes.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current_len == 0 {
                current_start = index;
            }
            current_len += 1;
            longest_printable_run = longest_printable_run.max(current_len);
            continue;
        }

        apply_string_run(bytes, current_start, current_len, &mut state);
        current_len = 0;
    }
    apply_string_run(bytes, current_start, current_len, &mut state);

    if state.count == 0 {
        return StringMetrics {
            longest_printable_run,
            ..StringMetrics::default()
        };
    }

    StringMetrics {
        count: state.count,
        avg_len: state.total_len as f32 / state.count as f32,
        max_len: state.max_len,
        url_ratio: ratio(state.url_hits, state.count),
        path_ratio: ratio(state.path_hits, state.count),
        suspicious_ratio: ratio(state.suspicious_hits, state.count),
        longest_printable_run,
    }
}

fn apply_string_run(bytes: &[u8], start: usize, len: usize, state: &mut StringScanState) {
    if len < STRING_MIN_LEN {
        return;
    }

    let value = &bytes[start..start + len];
    state.count += 1;
    state.total_len += len;
    state.max_len = state.max_len.max(len);

    if ascii_contains_ignore_case(value, b"http://")
        || ascii_contains_ignore_case(value, b"https://")
    {
        state.url_hits += 1;
    }
    if ascii_contains_ignore_case(value, b"c:\\")
        || ascii_contains_ignore_case(value, b"/tmp/")
        || ascii_contains_ignore_case(value, b"/usr/")
        || ascii_contains_ignore_case(value, b"\\users\\")
    {
        state.path_hits += 1;
    }
    if ascii_contains_ignore_case(value, b"powershell")
        || ascii_contains_ignore_case(value, b"cmd.exe")
        || ascii_contains_ignore_case(value, b"rundll32")
        || ascii_contains_ignore_case(value, b"base64")
        || ascii_contains_ignore_case(value, b"invoke-")
        || ascii_contains_ignore_case(value, b"virtualalloc")
        || ascii_contains_ignore_case(value, b"loadlibrary")
    {
        state.suspicious_hits += 1;
    }
}

fn looks_like_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 0x40 && bytes.starts_with(b"MZ")
}

fn extract_pe_metrics(bytes: &[u8]) -> Result<PeMetrics, String> {
    if bytes.len() < 0x100 {
        return Err("PE file too small to parse safely".to_string());
    }

    let pe_offset = read_u32(bytes, 0x3c).ok_or_else(|| "Missing PE offset".to_string())? as usize;
    if pe_offset + 0x18 >= bytes.len() {
        return Err("PE header offset points outside file".to_string());
    }
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err("PE signature missing".to_string());
    }

    let number_of_sections = read_u16(bytes, pe_offset + 6).unwrap_or(0) as usize;
    let size_of_optional_header = read_u16(bytes, pe_offset + 20).unwrap_or(0) as usize;
    let characteristics = read_u16(bytes, pe_offset + 22).unwrap_or(0);
    let optional_offset = pe_offset + 24;
    if optional_offset + size_of_optional_header > bytes.len() {
        return Err("Optional header extends beyond file bounds".to_string());
    }

    let magic = read_u16(bytes, optional_offset).unwrap_or(0);
    let is_64 = magic == 0x20b;
    let number_of_rva_and_sizes_offset = if is_64 {
        optional_offset + 108
    } else {
        optional_offset + 92
    };
    let number_of_rva_and_sizes =
        read_u32(bytes, number_of_rva_and_sizes_offset).unwrap_or(0) as usize;
    let data_directories_offset = number_of_rva_and_sizes_offset + 4;

    let address_of_entry_point = read_u32(bytes, optional_offset + 16).unwrap_or(0);
    let size_of_image = read_u32(bytes, optional_offset + 56).unwrap_or(0);

    let mut anomaly_points = 0usize;
    if number_of_sections == 0 || number_of_sections > 96 {
        anomaly_points += 1;
    }
    if size_of_optional_header == 0 {
        anomaly_points += 1;
    }
    if !(magic == 0x10b || magic == 0x20b) {
        anomaly_points += 1;
    }

    let section_table = optional_offset + size_of_optional_header;
    let mut sections = Vec::new();
    let mut executable_sections = 0usize;
    let mut writable_sections = 0usize;
    let mut zero_raw_sections = 0usize;
    let mut suspicious_section_names = 0usize;
    let mut section_entropy_sum = 0.0f32;
    let mut section_entropy_max = 0.0f32;

    for index in 0..number_of_sections {
        let offset = section_table + (index * 40);
        if offset + 40 > bytes.len() {
            anomaly_points += 1;
            break;
        }

        let name = trim_nul_ascii(&bytes[offset..offset + 8]);
        let virtual_size = read_u32(bytes, offset + 8).unwrap_or(0);
        let virtual_address = read_u32(bytes, offset + 12).unwrap_or(0);
        let raw_size = read_u32(bytes, offset + 16).unwrap_or(0);
        let raw_ptr = read_u32(bytes, offset + 20).unwrap_or(0);
        let section_characteristics = read_u32(bytes, offset + 36).unwrap_or(0);

        if section_characteristics & 0x2000_0000 != 0 {
            executable_sections += 1;
        }
        if section_characteristics & 0x8000_0000 != 0 {
            writable_sections += 1;
        }
        if raw_size == 0 {
            zero_raw_sections += 1;
        }
        if eq_ignore_ascii(name, b".upx")
            || eq_ignore_ascii(name, b"upx0")
            || eq_ignore_ascii(name, b"upx1")
            || eq_ignore_ascii(name, b".packed")
            || eq_ignore_ascii(name, b"aspack")
            || eq_ignore_ascii(name, b".adata")
        {
            suspicious_section_names += 1;
        }

        let raw_start = raw_ptr as usize;
        let raw_end = raw_start.saturating_add(raw_size as usize);
        if raw_start < bytes.len() && raw_end <= bytes.len() && raw_start < raw_end {
            let entropy = shannon_entropy(&bytes[raw_start..raw_end]);
            section_entropy_sum += entropy;
            section_entropy_max = section_entropy_max.max(entropy);
        }

        sections.push(SectionInfo {
            virtual_size,
            virtual_address,
            raw_size,
            raw_ptr,
        });
    }

    let data_directory = |index: usize| -> Option<(u32, u32)> {
        if index >= number_of_rva_and_sizes {
            return None;
        }
        let offset = data_directories_offset + (index * 8);
        Some((read_u32(bytes, offset)?, read_u32(bytes, offset + 4)?))
    };

    let (export_rva, export_size) = data_directory(0).unwrap_or((0, 0));
    let (import_rva, import_size) = data_directory(1).unwrap_or((0, 0));
    let (resource_rva, resource_size) = data_directory(2).unwrap_or((0, 0));
    let (debug_rva, debug_size) = data_directory(6).unwrap_or((0, 0));
    let (tls_rva, tls_size) = data_directory(9).unwrap_or((0, 0));

    let import_descriptors = if import_rva > 0 && import_size > 0 {
        count_import_descriptors(bytes, &sections, import_rva, import_size)
    } else {
        0
    };
    let import_functions = if import_rva > 0 && import_size > 0 {
        count_import_functions(bytes, &sections, import_rva)
    } else {
        0
    };

    let overlay_ratio = sections
        .iter()
        .map(|section| (section.raw_ptr + section.raw_size) as usize)
        .max()
        .map(|max_raw_end| {
            if bytes.len() > max_raw_end {
                ratio(bytes.len() - max_raw_end, bytes.len())
            } else {
                0.0
            }
        })
        .unwrap_or(0.0);

    Ok(PeMetrics {
        valid: true,
        is_64,
        is_dll: characteristics & 0x2000 != 0,
        num_sections: sections.len(),
        executable_sections,
        writable_sections,
        zero_raw_sections,
        suspicious_section_names,
        import_descriptors,
        import_functions,
        has_exports: export_rva > 0 && export_size > 0,
        has_resources: resource_rva > 0 && resource_size > 0,
        has_tls: tls_rva > 0 && tls_size > 0,
        has_debug: debug_rva > 0 && debug_size > 0,
        section_entropy_mean: if sections.is_empty() {
            0.0
        } else {
            section_entropy_sum / sections.len() as f32
        },
        section_entropy_max,
        entrypoint_ratio: if size_of_image > 0 {
            address_of_entry_point as f32 / size_of_image as f32
        } else {
            0.0
        }
        .clamp(0.0, 1.0),
        image_size_log2: log2ish(size_of_image as f64),
        overlay_ratio,
        header_anomaly_score: (anomaly_points as f32 / 4.0).clamp(0.0, 1.0),
    })
}

fn count_import_descriptors(
    bytes: &[u8],
    sections: &[SectionInfo],
    import_rva: u32,
    import_size: u32,
) -> usize {
    let Some(mut offset) = rva_to_offset(sections, import_rva) else {
        return 0;
    };
    let limit = offset.saturating_add(import_size as usize).min(bytes.len());
    let mut count = 0usize;

    while offset + 20 <= limit {
        let original_first_thunk = read_u32(bytes, offset).unwrap_or(0);
        let name_rva = read_u32(bytes, offset + 12).unwrap_or(0);
        let first_thunk = read_u32(bytes, offset + 16).unwrap_or(0);
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        count += 1;
        offset += 20;
    }

    count
}

fn count_import_functions(bytes: &[u8], sections: &[SectionInfo], import_rva: u32) -> usize {
    let Some(mut descriptor_offset) = rva_to_offset(sections, import_rva) else {
        return 0;
    };
    let mut count = 0usize;

    while descriptor_offset + 20 <= bytes.len() {
        let original_first_thunk = read_u32(bytes, descriptor_offset).unwrap_or(0);
        let first_thunk = read_u32(bytes, descriptor_offset + 16).unwrap_or(0);
        if original_first_thunk == 0 && first_thunk == 0 {
            break;
        }
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        count += count_thunks(bytes, sections, thunk_rva);
        descriptor_offset += 20;
    }

    count
}

fn count_thunks(bytes: &[u8], sections: &[SectionInfo], thunk_rva: u32) -> usize {
    let Some(mut offset) = rva_to_offset(sections, thunk_rva) else {
        return 0;
    };
    let mut count = 0usize;

    while offset + 8 <= bytes.len() {
        let value = read_u64(bytes, offset).unwrap_or(0);
        if value == 0 {
            break;
        }
        count += 1;
        offset += 8;
    }

    if count == 0 {
        let Some(mut offset32) = rva_to_offset(sections, thunk_rva) else {
            return 0;
        };
        while offset32 + 4 <= bytes.len() {
            let value = read_u32(bytes, offset32).unwrap_or(0);
            if value == 0 {
                break;
            }
            count += 1;
            offset32 += 4;
        }
    }

    count
}

fn rva_to_offset(sections: &[SectionInfo], rva: u32) -> Option<usize> {
    for section in sections {
        let section_span = section.virtual_size.max(section.raw_size);
        if rva >= section.virtual_address && rva < section.virtual_address + section_span {
            let delta = rva - section.virtual_address;
            if delta <= section.raw_size {
                return Some((section.raw_ptr + delta) as usize);
            }
        }
    }
    None
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn ratio(count: usize, total: usize) -> f32 {
    if total == 0 {
        0.0
    } else {
        count as f32 / total as f32
    }
}

fn log2ish(value: f64) -> f32 {
    if value <= 0.0 {
        0.0
    } else {
        (value + 1.0).log2() as f32
    }
}

fn is_printable_ascii(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t')
}

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| eq_ignore_ascii(window, needle))
}

fn eq_ignore_ascii(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn trim_nul_ascii(mut value: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = value.split_last() {
        if last == 0 || last == b' ' {
            value = rest;
        } else {
            break;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{extract_path, feature_names, FEATURE_NAMES};

    #[test]
    fn feature_layout_is_stable() {
        assert_eq!(feature_names().len(), FEATURE_NAMES.len());
    }

    #[test]
    fn extracts_generic_binary_features() {
        let path = std::env::temp_dir().join("projectx_portable_features.bin");
        std::fs::write(&path, b"MZhello http://example.com powershell").unwrap();

        let extracted = extract_path(&path, 1024).unwrap();
        assert_eq!(extracted.values.len(), FEATURE_NAMES.len());
        assert_eq!(extracted.file_kind, "pe");

        let _ = std::fs::remove_file(path);
    }
}
