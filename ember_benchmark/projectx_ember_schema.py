from __future__ import annotations

import json
import math
from pathlib import Path

from common import PROJECT_ROOT, ROOT, rust_portable_feature_names


ARTIFACTS_DIR = ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


SUSPICIOUS_SECTION_NAMES = {".upx", "upx0", "upx1", ".packed", "aspack", ".adata"}
SUSPICIOUS_IMPORT_MODULES = {
    "kernel32",
    "advapi32",
    "ntdll",
    "shell32",
    "user32",
    "ws2_32",
    "urlmon",
    "wininet",
    "msvcrt",
    "ole32",
    "crypt32",
}
NETWORK_IMPORT_MODULES = {"ws2_32", "wsock32", "urlmon", "wininet", "iphlpapi", "dnsapi"}
PROCESS_IMPORT_MODULES = {"kernel32", "advapi32", "ntdll", "psapi", "user32"}

EMBER_DATA_DIRECTORY_NAMES = [
    "EXPORT_TABLE",
    "IMPORT_TABLE",
    "RESOURCE_TABLE",
    "EXCEPTION_TABLE",
    "CERTIFICATE_TABLE",
    "BASE_RELOCATION_TABLE",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS_TABLE",
    "LOAD_CONFIG_TABLE",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT_DESCRIPTOR",
    "CLR_RUNTIME_HEADER",
]

PROJECTX_PATTERN_NAMES = [
    "http",
    "https",
    "exe",
    "dll",
    "bat",
    "cmd",
    "powershell",
    "net",
    "web",
    "download",
    "upload",
    "connect",
    "server",
    "client",
    "file",
    "path",
    "url",
    "ip",
    "address",
    "port",
    "tcp",
    "udp",
    "socket",
    "bind",
    "listen",
    "accept",
    "send",
    "recv",
    "read",
    "write",
    "open",
    "close",
    "create",
    "delete",
    "copy",
    "move",
    "run",
    "exec",
    "system",
    "shell",
    "bash",
    "sh",
    "python",
    "perl",
    "ruby",
    "java",
    "c#",
    "vb",
    "macro",
    "vba",
]


def jsonl_raw_feature_paths(dataset_dir: Path) -> list[Path]:
    return [
        dataset_dir / f"train_features_{index}.jsonl" for index in range(6)
    ] + [dataset_dir / "test_features.jsonl"]


def ember_vector_feature_descriptors() -> list[dict]:
    descriptors: list[dict] = []

    for index in range(256):
        descriptors.append(
            {
                "name": f"histogram_{index:03d}",
                "group": "ByteHistogram",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "ByteHistogram.process_raw_features",
                "semantic_meaning": f"Normalized full-file byte frequency for byte value 0x{index:02x}.",
                "numeric_type": "f32 normalized ratio",
            }
        )

    for entropy_bin in range(16):
        for byte_bin in range(16):
            flat_index = entropy_bin * 16 + byte_bin
            descriptors.append(
                {
                    "name": f"byteentropy_{flat_index:03d}",
                    "group": "ByteEntropyHistogram",
                    "source_file": "ember_benchmark/ember_repo/ember/features.py",
                    "code_location": "ByteEntropyHistogram.process_raw_features",
                    "semantic_meaning": (
                        f"Normalized joint histogram bin for entropy bucket {entropy_bin} and high-nibble bucket {byte_bin}."
                    ),
                    "numeric_type": "f32 normalized ratio",
                }
            )

    descriptors.extend(
        [
            {
                "name": "strings_numstrings",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Count of printable strings with length >= 5.",
                "numeric_type": "f32 count",
            },
            {
                "name": "strings_avlength",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Average printable string length.",
                "numeric_type": "f32 scalar",
            },
            {
                "name": "strings_printables",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Count of printable characters across extracted strings.",
                "numeric_type": "f32 count",
            },
        ]
    )
    for index in range(96):
        descriptors.append(
            {
                "name": f"strings_printabledist_{index:02d}",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": f"Normalized histogram value for printable character bucket {index}.",
                "numeric_type": "f32 normalized ratio",
            }
        )
    descriptors.extend(
        [
            {
                "name": "strings_entropy",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Entropy of printable string character distribution.",
                "numeric_type": "f32 scalar",
            },
            {
                "name": "strings_paths",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Count of C:\\ path indicators in the binary.",
                "numeric_type": "f32 count",
            },
            {
                "name": "strings_urls",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Count of http/https indicators in the binary.",
                "numeric_type": "f32 count",
            },
            {
                "name": "strings_registry",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Count of HKEY_ registry indicators in the binary.",
                "numeric_type": "f32 count",
            },
            {
                "name": "strings_MZ",
                "group": "StringExtractor",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "StringExtractor.process_raw_features",
                "semantic_meaning": "Count of embedded MZ indicators in printable strings.",
                "numeric_type": "f32 count",
            },
        ]
    )

    for name in [
        "size",
        "vsize",
        "has_debug",
        "exports",
        "imports",
        "has_relocations",
        "has_resources",
        "has_signature",
        "has_tls",
        "symbols",
    ]:
        descriptors.append(
            {
                "name": f"general_{name}",
                "group": "GeneralFileInfo",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "GeneralFileInfo.process_raw_features",
                "semantic_meaning": f"General PE metadata field `{name}`.",
                "numeric_type": "f32 scalar/bool-as-count",
            }
        )

    descriptors.append(
        {
            "name": "header_coff_timestamp",
            "group": "HeaderFileInfo",
            "source_file": "ember_benchmark/ember_repo/ember/features.py",
            "code_location": "HeaderFileInfo.process_raw_features",
            "semantic_meaning": "COFF timestamp.",
            "numeric_type": "f32 scalar",
        }
    )
    for prefix in (
        "header_coff_machine_hash",
        "header_coff_characteristics_hash",
        "header_optional_subsystem_hash",
        "header_optional_dll_characteristics_hash",
        "header_optional_magic_hash",
    ):
        for index in range(10):
            descriptors.append(
                {
                    "name": f"{prefix}_{index:02d}",
                    "group": "HeaderFileInfo",
                    "source_file": "ember_benchmark/ember_repo/ember/features.py",
                    "code_location": "HeaderFileInfo.process_raw_features",
                    "semantic_meaning": f"FeatureHasher output dimension {index} for `{prefix}`.",
                    "numeric_type": "f32 hashed value",
                }
            )
    for name in [
        "major_image_version",
        "minor_image_version",
        "major_linker_version",
        "minor_linker_version",
        "major_operating_system_version",
        "minor_operating_system_version",
        "major_subsystem_version",
        "minor_subsystem_version",
        "sizeof_code",
        "sizeof_headers",
        "sizeof_heap_commit",
    ]:
        descriptors.append(
            {
                "name": f"header_optional_{name}",
                "group": "HeaderFileInfo",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "HeaderFileInfo.process_raw_features",
                "semantic_meaning": f"Optional-header numeric field `{name}`.",
                "numeric_type": "f32 scalar",
            }
        )

    for name in [
        "section_count",
        "section_zero_size_count",
        "section_empty_name_count",
        "section_rx_count",
        "section_writable_count",
    ]:
        descriptors.append(
            {
                "name": name,
                "group": "SectionInfo",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "SectionInfo.process_raw_features",
                "semantic_meaning": f"Section aggregate field `{name}`.",
                "numeric_type": "f32 scalar",
            }
        )
    for prefix in (
        "section_size_hash",
        "section_entropy_hash",
        "section_vsize_hash",
        "section_entry_name_hash",
        "section_entry_characteristics_hash",
    ):
        for index in range(50):
            descriptors.append(
                {
                    "name": f"{prefix}_{index:02d}",
                    "group": "SectionInfo",
                    "source_file": "ember_benchmark/ember_repo/ember/features.py",
                    "code_location": "SectionInfo.process_raw_features",
                    "semantic_meaning": f"FeatureHasher output dimension {index} for `{prefix}`.",
                    "numeric_type": "f32 hashed value",
                }
            )

    for index in range(256):
        descriptors.append(
            {
                "name": f"imports_library_hash_{index:03d}",
                "group": "ImportsInfo",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "ImportsInfo.process_raw_features",
                "semantic_meaning": f"FeatureHasher library bucket {index}.",
                "numeric_type": "f32 hashed value",
            }
        )
    for index in range(1024):
        descriptors.append(
            {
                "name": f"imports_function_hash_{index:04d}",
                "group": "ImportsInfo",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "ImportsInfo.process_raw_features",
                "semantic_meaning": f"FeatureHasher import-function bucket {index}.",
                "numeric_type": "f32 hashed value",
            }
        )

    for index in range(128):
        descriptors.append(
            {
                "name": f"exports_hash_{index:03d}",
                "group": "ExportsInfo",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "ExportsInfo.process_raw_features",
                "semantic_meaning": f"FeatureHasher export bucket {index}.",
                "numeric_type": "f32 hashed value",
            }
        )

    for index, name in enumerate(EMBER_DATA_DIRECTORY_NAMES):
        descriptors.append(
            {
                "name": f"datadir_{name.lower()}_size",
                "group": "DataDirectories",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "DataDirectories.process_raw_features",
                "semantic_meaning": f"Data directory `{name}` size.",
                "numeric_type": "f32 scalar",
            }
        )
        descriptors.append(
            {
                "name": f"datadir_{name.lower()}_virtual_address",
                "group": "DataDirectories",
                "source_file": "ember_benchmark/ember_repo/ember/features.py",
                "code_location": "DataDirectories.process_raw_features",
                "semantic_meaning": f"Data directory `{name}` RVA.",
                "numeric_type": "f32 scalar",
            }
        )

    return descriptors


def projectx_portable_feature_descriptors() -> list[dict]:
    names = rust_portable_feature_names()
    descriptors = []
    for name in names:
        descriptors.append(
            {
                "name": name,
                "source_file": "src/ml/portable_features.rs",
                "code_location": "FEATURE_NAMES + extract_path",
                "semantic_meaning": portable_semantic_meaning(name),
                "numeric_type": portable_numeric_type(name),
            }
        )
    return descriptors


def projectx_legacy_feature_descriptors() -> list[dict]:
    fields = [
        ("finding_count", "Count of static findings collected in ScanContext."),
        ("suspicious_weight", "Sum of finding weights from static analysis."),
        ("decoded_count", "Count of decoded strings."),
        ("artifact_count", "Count of collected artifacts."),
        ("nested_depth", "Nested container/archive depth."),
        ("yara_hits", "Count of YARA_MATCH findings."),
        ("emulation_runtime_hits", "Runtime emulation YARA hit count."),
        ("has_macro_indicator", "Boolean macro indicator from findings."),
        ("has_network_indicator", "Boolean network indicator from findings."),
        ("dynamic_network_events", "Dynamic sandbox network event count."),
        ("dynamic_process_events", "Dynamic sandbox process event count."),
        ("dynamic_file_events", "Dynamic sandbox file event count."),
        ("dynamic_runtime_yara_hits", "Dynamic runtime YARA hit count."),
    ]
    return [
        {
            "name": name,
            "source_file": "src/ml/features.rs",
            "code_location": "FeatureVector + extract",
            "semantic_meaning": meaning,
            "numeric_type": "usize/f64/bool",
        }
        for name, meaning in fields
    ]


def portable_numeric_type(name: str) -> str:
    if name.startswith(("byte_hist_", "string_pattern_", "byte_entropy_")):
        return "f32 normalized ratio"
    if name.endswith(("_ratio", "_score")) or name in {"entropy", "avg_string_len"}:
        return "f32 scalar"
    return "f32 scalar/bool-as-f32"


def portable_semantic_meaning(name: str) -> str:
    if name.startswith("byte_hist_"):
        return "32-bin normalized byte histogram aggregated across the full input."
    if name.startswith("string_pattern_"):
        index = int(name.rsplit("_", 1)[1])
        return f"Ratio of extracted printable strings containing the pattern `{PROJECTX_PATTERN_NAMES[index]}`."
    if name.startswith("byte_entropy_"):
        return "16x16 normalized byte/entropy histogram bin using the ProjectX entropy-window algorithm."
    semantic_map = {
        "size_log2": "log2(file_size_bytes + 1)",
        "bytes_examined_log2": "log2(bytes_examined + 1)",
        "truncated_input": "Whether ProjectX truncated the scanned bytes to model.max_input_bytes.",
        "entropy": "Shannon entropy over examined bytes.",
        "unique_byte_ratio": "Distinct byte count divided by 256.",
        "null_byte_ratio": "Null-byte ratio across examined bytes.",
        "printable_ratio": "Printable ASCII plus tab ratio across examined bytes.",
        "ascii_ratio": "ASCII-byte ratio across examined bytes.",
        "high_byte_ratio": "Ratio of bytes >= 0x80.",
        "longest_printable_run_ratio": "Length of the longest printable ASCII run divided by examined bytes.",
        "string_count_log2": "log2(number of extracted printable strings + 1).",
        "avg_string_len": "Average extracted printable string length.",
        "max_string_len_log2": "log2(max printable string length + 1).",
        "url_string_ratio": "Share of extracted printable strings containing URLs.",
        "path_string_ratio": "Share of extracted printable strings containing filesystem paths.",
        "suspicious_string_ratio": "Share of extracted printable strings containing ProjectX suspicious tokens.",
        "mz_header": "Whether the bytes start with MZ.",
        "pe_valid": "Whether ProjectX PE parsing succeeded.",
        "pe_is_64": "Whether PE optional header indicates PE32+.",
        "pe_is_dll": "Whether PE characteristics include DLL.",
        "pe_num_sections": "PE section count.",
        "pe_executable_sections": "Count of executable PE sections.",
        "pe_writable_sections": "Count of writable PE sections.",
        "pe_zero_raw_sections": "Count of PE sections with zero raw size.",
        "pe_suspicious_section_name_hits": "Count of section names matching ProjectX suspicious packer names.",
        "pe_import_descriptor_count": "Import descriptor count from PE import table.",
        "pe_import_function_count_log2": "log2(imported function count + 1).",
        "pe_suspicious_import_count": "Count of suspicious import modules from the PE import table.",
        "pe_network_import_modules": "Count of network-oriented import modules.",
        "pe_process_import_modules": "Count of process-oriented import modules.",
        "pe_has_cert": "Whether PE certificate directory is present.",
        "pe_is_probably_packed": "Heuristic packed flag using section-name and import-count heuristics.",
        "pe_has_exports": "Whether exports are present.",
        "pe_has_resources": "Whether resources are present.",
        "pe_has_tls": "Whether TLS directory is present.",
        "pe_has_debug": "Whether debug directory is present.",
        "pe_section_entropy_mean": "Mean section entropy over raw section bytes.",
        "pe_section_entropy_max": "Maximum section entropy over raw section bytes.",
        "pe_high_entropy_sections": "Count of sections with entropy > 0.8 in current ProjectX implementation.",
        "pe_entrypoint_ratio": "Entrypoint RVA divided by size_of_image.",
        "pe_image_size_log2": "log2(PE size_of_image + 1).",
        "pe_overlay_ratio": "Overlay size divided by file length.",
        "pe_header_anomaly_score": "Normalized anomaly score from PE header sanity checks.",
        "elf_header": "Whether the bytes start with ELF magic.",
        "pdf_header": "Whether the bytes start with %PDF.",
        "zip_header": "Whether the bytes start with PK\\x03\\x04.",
        "shebang_header": "Whether the bytes start with #!.",
        "dos_stub_contains_message": "Whether the bytes contain the DOS stub message string.",
    }
    return semantic_map.get(name, "ProjectX portable feature.")


def projectx_portable_mapping_spec() -> list[dict]:
    names = rust_portable_feature_names()
    mapping = []
    for name in names:
        mapping.append(single_mapping_spec(name))
    return mapping


def single_mapping_spec(name: str) -> dict:
    if name == "size_log2":
        return spec(name, "transformable_match", ["general.size"], "log2(general.size + 1)", "EMBER stores raw size directly.")
    if name == "bytes_examined_log2":
        return spec(name, "transformable_match", ["general.size"], "log2(general.size + 1)", "Assumes no ProjectX truncation on adapted EMBER rows.")
    if name == "truncated_input":
        return spec(name, "partial", ["general.size"], "set 0 unless an explicit adapter byte cap is applied", "EMBER raw features are whole-file; ProjectX truncation semantics are not encoded.")
    if name == "entropy":
        return spec(name, "transformable_match", ["histogram"], "compute Shannon entropy from EMBER byte histogram", "Lossless derivation from byte histogram.")
    if name == "unique_byte_ratio":
        return spec(name, "transformable_match", ["histogram"], "nonzero_byte_values / 256", "Lossless derivation from byte histogram.")
    if name == "null_byte_ratio":
        return spec(name, "exact_match", ["histogram[0]"], "histogram[0] / sum(histogram)", "Directly encoded by EMBER byte histogram.")
    if name == "printable_ratio":
        return spec(name, "transformable_match", ["histogram"], "sum(printable byte counts) / total", "Derived from full byte histogram.")
    if name == "ascii_ratio":
        return spec(name, "transformable_match", ["histogram"], "sum(byte 0x00..0x7f) / total", "Derived from full byte histogram.")
    if name == "high_byte_ratio":
        return spec(name, "transformable_match", ["histogram"], "sum(byte 0x80..0xff) / total", "Derived from full byte histogram.")
    if name == "longest_printable_run_ratio":
        return spec(name, "partial", ["strings.avlength", "strings.numstrings", "imports", "exports", "section.entry", "section.sections[].name"], "lower-bound estimate from known printable metadata strings and EMBER string statistics", "EMBER raw rows do not preserve full contiguous printable runs, so this is only a lower-bound estimate.")
    if name == "string_count_log2":
        return spec(name, "transformable_match", ["strings.numstrings"], "log2(strings.numstrings + 1)", "Direct count with ProjectX log scaling.")
    if name == "avg_string_len":
        return spec(name, "exact_match", ["strings.avlength"], "copy", "Directly encoded by EMBER string stats.")
    if name == "max_string_len_log2":
        return spec(name, "partial", ["strings.avlength", "imports", "exports", "section.entry", "section.sections[].name"], "log2(lower-bound max printable string length + 1)", "EMBER raw rows omit true max string length, so this is derived from the longest known metadata string and average string length.")
    if name == "url_string_ratio":
        return spec(name, "transformable_match", ["strings.urls", "strings.numstrings"], "strings.urls / max(strings.numstrings, 1)", "EMBER stores URL count, ProjectX expects ratio.")
    if name == "path_string_ratio":
        return spec(name, "transformable_match", ["strings.paths", "strings.numstrings"], "strings.paths / max(strings.numstrings, 1)", "EMBER stores path count, ProjectX expects ratio.")
    if name == "suspicious_string_ratio":
        return spec(name, "partial", ["strings.urls", "strings.paths", "strings.registry", "strings.MZ", "strings.numstrings", "imports", "exports", "section.entry", "section.sections[].name"], "(coarse EMBER suspicious counters + suspicious metadata-string hits) / max(numstrings, 1)", "ProjectX uses raw printable strings; this path uses EMBER counters plus PE metadata strings likely present in bytes.")
    if name == "mz_header":
        return spec(name, "transformable_match", ["dataset PE constraint"], "1.0", "EMBER dataset rows are PE samples.")
    if name == "pe_valid":
        return spec(name, "transformable_match", ["dataset PE constraint"], "1.0", "EMBER raw rows are extracted from successfully parsed PE samples.")
    if name == "pe_is_64":
        return spec(name, "transformable_match", ["header.optional.magic", "header.coff.machine"], "1 if PE32+ or AMD64 else 0", "Derived from EMBER header fields.")
    if name == "pe_is_dll":
        return spec(name, "transformable_match", ["header.coff.characteristics"], "1 if DLL characteristic present else 0", "Derived from EMBER header fields.")
    if name == "pe_num_sections":
        return spec(name, "exact_match", ["section.sections"], "len(section.sections)", "Direct section count.")
    if name == "pe_executable_sections":
        return spec(name, "exact_match", ["section.sections[].props"], "count sections with MEM_EXECUTE", "Direct section property count.")
    if name == "pe_writable_sections":
        return spec(name, "exact_match", ["section.sections[].props"], "count sections with MEM_WRITE", "Direct section property count.")
    if name == "pe_zero_raw_sections":
        return spec(name, "exact_match", ["section.sections[].size"], "count sections where size == 0", "EMBER section size corresponds to raw size here.")
    if name == "pe_suspicious_section_name_hits":
        return spec(name, "exact_match", ["section.sections[].name"], "count names in ProjectX suspicious section-name set", "Directly derivable from raw section names.")
    if name == "pe_import_descriptor_count":
        return spec(name, "partial", ["imports"], "len(unique import-module keys)", "EMBER raw imports merge duplicate descriptors by module name.")
    if name == "pe_import_function_count_log2":
        return spec(name, "transformable_match", ["imports"], "log2(total imported function names + 1)", "Directly derivable from raw import map.")
    if name == "pe_suspicious_import_count":
        return spec(name, "partial", ["imports"], "count unique module keys matching ProjectX suspicious module set", "Descriptor-level duplication is not preserved in EMBER raw imports.")
    if name == "pe_network_import_modules":
        return spec(name, "exact_match", ["imports"], "count unique module keys in ProjectX network-module set", "Directly derivable from raw import map.")
    if name == "pe_process_import_modules":
        return spec(name, "exact_match", ["imports"], "count unique module keys in ProjectX process-module set", "Directly derivable from raw import map.")
    if name == "pe_has_cert":
        return spec(name, "exact_match", ["datadirectories[CERTIFICATE_TABLE]"], "1 if certificate directory size > 0 else 0", "Directly derivable from EMBER data directories.")
    if name == "pe_is_probably_packed":
        return spec(name, "partial", ["section.sections[].name", "imports"], "1 if suspicious_section_name_hits > 0 and approximate import_descriptor_count < 3 else 0", "Depends on an approximate import-descriptor count.")
    if name == "pe_has_exports":
        return spec(name, "exact_match", ["general.exports", "exports"], "1 if exports > 0 else 0", "Directly derivable from EMBER general/export data.")
    if name == "pe_has_resources":
        return spec(name, "exact_match", ["general.has_resources"], "copy", "Direct EMBER general field.")
    if name == "pe_has_tls":
        return spec(name, "exact_match", ["general.has_tls"], "copy", "Direct EMBER general field.")
    if name == "pe_has_debug":
        return spec(name, "exact_match", ["general.has_debug"], "copy", "Direct EMBER general field.")
    if name == "pe_section_entropy_mean":
        return spec(name, "exact_match", ["section.sections[].entropy"], "mean(section entropies)", "Directly derivable from raw section entropy values.")
    if name == "pe_section_entropy_max":
        return spec(name, "exact_match", ["section.sections[].entropy"], "max(section entropies)", "Directly derivable from raw section entropy values.")
    if name == "pe_high_entropy_sections":
        return spec(name, "exact_match", ["section.sections[].entropy"], "count sections where entropy > 0.8", "Matches current ProjectX implementation exactly, including its threshold.")
    if name == "pe_entrypoint_ratio":
        return spec(name, "partial", ["section.entry", "section.sections[].vsize", "general.vsize", "datadirectories[].virtual_address"], "alignment-aware estimated entrypoint position from inferred PE virtual layout", "EMBER raw rows expose the entry section name and section sizes, but not raw AddressOfEntryPoint or section virtual addresses.")
    if name == "pe_image_size_log2":
        return spec(name, "transformable_match", ["general.vsize"], "log2(general.vsize + 1)", "EMBER general.vsize maps to virtual image size.")
    if name == "pe_overlay_ratio":
        return spec(name, "partial", ["general.size", "header.optional.sizeof_headers", "section.sections[].size"], "alignment-aware estimated overlay from inferred sequential raw layout", "EMBER raw rows expose section raw sizes but not raw offsets, so overlay is estimated with inferred file alignment.")
    if name == "pe_header_anomaly_score":
        return spec(name, "partial", ["header", "section.sections"], "approximate anomaly fraction from available header checks", "ProjectX uses PE offsets and size_of_optional_header checks not present in EMBER raw rows.")
    if name in {"elf_header", "pdf_header", "zip_header", "shebang_header"}:
        return spec(name, "transformable_match", ["dataset PE constraint"], "0.0", "EMBER benchmark rows are PE files, so non-PE header flags are zero.")
    if name == "dos_stub_contains_message":
        return spec(name, "missing_in_ember", [], "set 0.0 sentinel", "EMBER raw features do not preserve DOS stub bytes or substring presence.")
    if name.startswith("byte_hist_"):
        bin_index = int(name.rsplit("_", 1)[1])
        start = bin_index * 8
        end = start + 7
        return spec(name, "transformable_match", ["histogram"], f"sum(histogram[{start}:{end + 1}]) / total", "ProjectX uses 32 coarse bins; EMBER uses 256 byte bins.")
    if name.startswith("string_pattern_"):
        index = int(name.rsplit("_", 1)[1])
        pattern = PROJECTX_PATTERN_NAMES[index]
        return spec(name, "partial", ["imports", "exports", "section.entry", "section.sections[].name", "strings.numstrings", "strings.urls", "strings.paths", "strings.registry", "strings.MZ"], "metadata-string hits normalized by EMBER strings.numstrings", f"EMBER raw rows do not preserve the full extracted-string corpus, so ProjectX pattern `{pattern}` is approximated from PE metadata strings likely present in bytes and normalized by EMBER string count.")
    if name.startswith("byte_entropy_"):
        idx = int(name.rsplit("_", 1)[1], 16)
        return spec(name, "exact_match", [f"byteentropy[{idx}]"], "normalize EMBER byteentropy histogram exactly", "ProjectX and EMBER use the same 16x16 byte/entropy algorithm here.")
    return spec(name, "incompatible", [], "set 0.0 sentinel", "No mapping rule was defined.")


def spec(
    projectx_feature: str,
    status: str,
    ember_sources: list[str],
    transform: str,
    notes: str,
) -> dict:
    return {
        "projectx_feature": projectx_feature,
        "status": status,
        "ember_sources": ember_sources,
        "transform": transform,
        "notes": notes,
    }


def mapping_summary(mapping: list[dict]) -> dict:
    counts = {}
    for item in mapping:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    mapped = counts.get("exact_match", 0) + counts.get("transformable_match", 0) + counts.get("partial", 0)
    return {
        "total_projectx_portable_features": len(mapping),
        "status_counts": counts,
        "coverage_ratio": mapped / len(mapping),
    }


def write_schema_mapping_files(target_json: Path, target_md: Path) -> dict:
    ember_features = ember_vector_feature_descriptors()
    projectx_portable = projectx_portable_feature_descriptors()
    projectx_legacy = projectx_legacy_feature_descriptors()
    mapping = projectx_portable_mapping_spec()
    summary = mapping_summary(mapping)

    ember_only = ember_only_feature_summary()
    payload = {
        "ember_vectorized_schema": {
            "feature_count": len(ember_features),
            "features": ember_features,
        },
        "projectx_portable_schema": {
            "feature_count": len(projectx_portable),
            "features": projectx_portable,
        },
        "projectx_legacy_runtime_schema": {
            "feature_count": len(projectx_legacy),
            "features": projectx_legacy,
        },
        "projectx_to_ember_mapping": mapping,
        "ember_features_missing_in_projectx": ember_only,
        "summary": summary,
    }
    target_json.write_text(json.dumps(payload, indent=2) + "\n")
    target_md.write_text(schema_mapping_markdown(payload))
    return payload


def ember_only_feature_summary() -> list[dict]:
    return [
        {
            "feature_family": "EMBER hashed PE structure features",
            "examples": [
                "section_size_hash_*",
                "section_entropy_hash_*",
                "imports_library_hash_*",
                "imports_function_hash_*",
                "exports_hash_*",
                "header_*_hash_*",
                "datadir_*",
            ],
            "status": "missing_in_projectx",
            "notes": "ProjectX portable schema does not currently expose these EMBER-style hashed structural PE feature families.",
        },
        {
            "feature_family": "EMBER printable character distribution",
            "examples": ["strings_printabledist_*", "strings_entropy", "strings_printables"],
            "status": "missing_in_projectx",
            "notes": "ProjectX uses different string-derived features and token ratios instead of EMBER's printable-character histogram.",
        },
    ]


def schema_mapping_markdown(payload: dict) -> str:
    mapping = payload["projectx_to_ember_mapping"]
    sections = {
        "Exact Matches": [item for item in mapping if item["status"] == "exact_match"],
        "Transformable Features": [item for item in mapping if item["status"] == "transformable_match"],
        "Partial / Approximate Features": [item for item in mapping if item["status"] == "partial"],
        "Missing in EMBER": [item for item in mapping if item["status"] == "missing_in_ember"],
        "Missing in ProjectX": payload["ember_features_missing_in_projectx"],
    }
    risks = [
        "ProjectX portable schema expects 386 features, while EMBER vectorized schema exposes 2381 dimensions with a different design philosophy.",
        "ProjectX string-pattern features rely on the raw printable string corpus, but EMBER raw rows only expose aggregate string counts and histograms.",
        "ProjectX PE overlay and entrypoint-ratio features are not recoverable from EMBER raw rows as currently stored.",
        "EMBER import data merges duplicate library entries, which weakens descriptor-count parity for some ProjectX PE import heuristics.",
        "The legacy Rust heuristic FeatureVector in src/ml/features.rs is a separate runtime schema and should not be conflated with portable-model parity.",
    ]

    lines = [
        "# ProjectX ↔ EMBER Schema Mapping",
        "",
        f"- EMBER vectorized feature count: {payload['ember_vectorized_schema']['feature_count']}",
        f"- ProjectX portable feature count: {payload['projectx_portable_schema']['feature_count']}",
        f"- ProjectX legacy runtime feature count: {payload['projectx_legacy_runtime_schema']['feature_count']}",
        f"- Portable coverage ratio after exact/transformable/partial mapping: {payload['summary']['coverage_ratio']:.4f}",
        "",
    ]
    for title, items in sections.items():
        lines.append(f"## {title}")
        lines.append("")
        if title == "Missing in ProjectX":
            for item in items:
                lines.append(f"- {item['feature_family']}: {', '.join(item['examples'])}")
                lines.append(f"  Notes: {item['notes']}")
            lines.append("")
            continue
        for item in items:
            lines.append(f"- `{item['projectx_feature']}`")
            lines.append(f"  EMBER source(s): {', '.join(item['ember_sources']) or 'None'}")
            lines.append(f"  Transform: {item['transform']}")
            lines.append(f"  Notes: {item['notes']}")
        lines.append("")

    lines.append("## Benchmark Integrity Risks")
    lines.append("")
    for risk in risks:
        lines.append(f"- {risk}")
    lines.append("")
    return "\n".join(lines)


def load_projectx_embedded_model_from_rust_source() -> dict:
    text = (PROJECT_ROOT / "src" / "ml" / "portable_model.rs").read_text()
    weights_block = text.split("const EMBEDDED_WEIGHTS: [f32; 386] = [", 1)[1].split("];", 1)[0]
    weights = [
        float(token.strip())
        for token in weights_block.replace("\n", " ").split(",")
        if token.strip()
    ]
    return {
        "model_type": "portable-linear-v1",
        "version": "projectx-embedded-v1",
        "feature_names": rust_portable_feature_names(),
        "weights": weights,
        "intercept": -3.4,
        "malicious_threshold": 0.5,
        "suspicious_threshold": 0.4,
        "max_input_bytes": 32 * 1024 * 1024,
        "notes": "Exported from Rust embedded model source for parity testing.",
        "calibration": None,
    }


def sigmoid(value: float) -> float:
    if value >= 0.0:
        exp = math.exp(-value)
        return 1.0 / (1.0 + exp)
    exp = math.exp(value)
    return exp / (1.0 + exp)
