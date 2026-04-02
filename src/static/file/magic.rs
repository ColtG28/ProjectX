use phf::phf_map;
use std::fs::File;
use std::io::Read;

const MAX_SIG_BYTES: usize = 32;

pub fn find_header(file_path: &str, extension: &str) -> bool {
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file '{}': {}", file_path, e);
            return false;
        }
    };

    let mut buffer = vec![0u8; MAX_SIG_BYTES];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            return false;
        }
    };
    buffer.truncate(bytes_read);

    find_header_bytes(&buffer, extension)
}

pub fn find_header_bytes(bytes: &[u8], extension: &str) -> bool {
    let ext_upper = extension
        .trim_start_matches('.')
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_uppercase();

    if bytes.is_empty() {
        return true;
    }

    if matches_container_family(bytes, &ext_upper) || matches_text_family(bytes, &ext_upper) {
        return true;
    }

    let mut best_match: Option<&[&str]> = None;

    for sig_len in (1..=bytes.len().min(MAX_SIG_BYTES)).rev() {
        let hex_sig: String = bytes[..sig_len]
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if i < sig_len - 1 {
                    format!("{:02X} ", b)
                } else {
                    format!("{:02X}", b)
                }
            })
            .collect();

        if let Some(exts) = SIGNATURES.get(hex_sig.as_str()) {
            best_match = Some(exts);
            break;
        }
    }

    match best_match {
        Some(exts) => exts
            .iter()
            .any(|e| extension_matches_signature(&ext_upper, e)),
        None => {
            if seems_text(bytes) {
                matches!(
                    ext_upper.as_str(),
                    "" | "TXT"
                        | "CSV"
                        | "LOG"
                        | "MD"
                        | "JSON"
                        | "XML"
                        | "HTML"
                        | "HTM"
                        | "SVG"
                        | "JS"
                        | "VBS"
                        | "PS1"
                        | "BAT"
                        | "CMD"
                        | "SH"
                        | "PY"
                        | "RB"
                        | "PL"
                        | "PSM1"
                        | "YAML"
                        | "YML"
                        | "INI"
                        | "CONF"
                        | "REG"
                        | "RTF"
                )
            } else {
                false
            }
        }
    }
}

fn extension_matches_signature(ext_upper: &str, signature_ext: &str) -> bool {
    let sig = signature_ext.to_ascii_uppercase();
    if sig == ext_upper {
        return true;
    }

    matches!(
        (sig.as_str(), ext_upper),
        (
            "ZIP",
            "DOCX" | "XLSX" | "PPTX" | "DOCM" | "XLSM" | "PPTM" | "ODT" | "ODS" | "ODP"
        ) | ("DOC", "DOCM")
            | ("XLS", "XLSM")
            | ("PPT", "PPTM")
            | ("HTA", "HTML" | "HTM")
            | ("PS", "EPS")
    )
}

fn matches_container_family(bytes: &[u8], ext_upper: &str) -> bool {
    if bytes.starts_with(b"PK\x03\x04") {
        return matches!(
            ext_upper,
            "ZIP"
                | "JAR"
                | "APK"
                | "IPA"
                | "DOCX"
                | "XLSX"
                | "PPTX"
                | "DOCM"
                | "XLSM"
                | "PPTM"
                | "ODT"
                | "ODS"
                | "ODP"
        );
    }

    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return matches!(ext_upper, "DOC" | "XLS" | "PPT" | "MSI");
    }

    if bytes.starts_with(b"MZ") {
        return matches!(ext_upper, "EXE" | "DLL" | "SYS" | "SCR" | "CPL" | "COM");
    }

    if bytes.starts_with(b"%PDF") {
        return matches!(ext_upper, "PDF" | "FDF");
    }

    false
}

fn matches_text_family(bytes: &[u8], ext_upper: &str) -> bool {
    if bytes.starts_with(b"#!") {
        return matches!(ext_upper, "SH" | "PY" | "PL" | "RB" | "JS");
    }

    seems_text(bytes)
        && matches!(
            ext_upper,
            "TXT"
                | "CSV"
                | "LOG"
                | "MD"
                | "JSON"
                | "XML"
                | "HTML"
                | "HTM"
                | "SVG"
                | "JS"
                | "VBS"
                | "PS1"
                | "BAT"
                | "CMD"
                | "SH"
                | "PY"
                | "RB"
                | "PL"
                | "PSM1"
                | "YAML"
                | "YML"
                | "INI"
                | "CONF"
                | "REG"
                | "RTF"
        )
}

fn seems_text(bytes: &[u8]) -> bool {
    if std::str::from_utf8(bytes).is_ok() {
        return true;
    }

    let sample = &bytes[..bytes.len().min(1024)];
    let printable = sample
        .iter()
        .filter(|b| matches!(**b, b'\n' | b'\r' | b'\t') || b.is_ascii_graphic() || **b == b' ')
        .count();

    printable * 100 / sample.len().max(1) >= 85
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::find_header_bytes;

    #[test]
    fn accepts_plain_text_scripts_without_binary_magic() {
        assert!(find_header_bytes(
            b"powershell -EncodedCommand ZQBjAGgAbwA=",
            "ps1"
        ));
        assert!(find_header_bytes(b"#!/bin/sh\necho test\n", "sh"));
    }

    #[test]
    fn accepts_office_openxml_as_zip_family() {
        let bytes = b"PK\x03\x04[Content_Types].xmlword/document.xml";
        assert!(find_header_bytes(bytes, "docx"));
    }
}

static SIGNATURES: phf::Map<&'static str, &'static [&'static str]> = phf_map! {
    "00 00 00" => &["AVIF"],
    "00 00 00 20 66 74 79 70 68 65 69 63" => &["HEIC"],
    "00 00 00 0C 6A 50 20 20" => &["JP2"],
    "00 00 00 14 66 74 79 70" => &["3GP", "MP4", "GG"],
    "00 00 00 14 66 74 79 70 69 73 6F 6D" => &["MP4"],
    "00 00 00 00 14 00 00 00" => &["TBI"],
    "00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00" => &["DAT"],
    "00 00 00 18 66 74 79 70" => &["3GP5", "M4V", "MP4"],
    "00 00 00 1C 66 74 79 70" => &["MP4"],
    "00 00 00 20 66 74 79 70" => &["3GP", "3GG"],
    "00 00 00 20 66 74 79 70 4D 34 41" => &["M4A"],
    "00 00 01 00" => &["ICO", "SPL"],
    "00 00 01 B3" => &["MPG"],
    "00 00 01 BA" => &["MPG", "VOB"],
    "00 00 02 00" => &["CUR", "WB2"],
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" => &["XXX"],
    "00 00 03 F3" => &["DAT"],
    "00 20 AF 30" => &["TPL"],
    "00 00 02 00 06 04 06 00" => &["WK1"],
    "00 00 1A 00 00 10 04 00" => &["WK3", "WK5"],
    "00 00 1A 00 02 10 04 00" => &["WK4"],
    "00 00 1A 00 05 10 04" => &["123"],
    "00 00 49 49 58 50 52" => &["QXD"],
    "00 00 4D 4D 58 50 52" => &["QXD"],
    "00 00 FF FF FF FF" => &["HLP"],
    "00 01 00 00 00" => &["TTF"],
    "00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65" => &["MNY"],
    "00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42" => &["ACCDB"],
    "00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42" => &["MDB"],
    "00 01 42 41" => &["ABA"],
    "00 01 42 44" => &["DBA"],
    "00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00" => &["DB"],
    "00 0D BB A0" => &[""],
    "00 11" => &["FLI"],
    "00 14 00 00 01 02" => &[""],
    "00 1E 84 90 00 00 00 00" => &["SNM"],
    "00 3B 05 00 01 00 00 00" => &["DB"],
    "00 6E 1E F0" => &["PPT"],
    "01 00 02 00" => &["ARF"],
    "01 00 39 30" => &["FDB", "GDB"],
    "01 01 47 19 A4 00 00 00 00 00 00 00" => &["TBI"],
    "01 0F 00 00" => &["MDF"],
    "01 10" => &["TR1"],
    "01 DA 01 01 00 03" => &["RGB"],
    "01 FF 02 04 03 02" => &["DRW"],
    "02 64 73 73" => &["DSS"],
    "03 00 00 00" => &["DAT", "DB3"],
    "03 00 00 00 41 50 50 52" => &["QPH"],
    "03 64 73 73" => &["NFC"],
    "04 00 00 00" => &["ADX"],
    "05 00 00 00" => &["DSS"],
    "06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D" => &["INDD"],
    "06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02" => &["MXF"],
    "07 53 4B 46" => &["SKF"],
    "07 64 74 32 64 64 74 64" => &["DTD"],
    "09 08 10 00 00 06 05 00" => &["XLS"],
    "0A 02 01 01" => &["PCX"],
    "0A 03 01 01" => &["PCX"],
    "0A 05 01 01" => &["PCX"],
    "0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72" => &["WALLET"],
    "0C ED" => &["MP"],
    "0D 44 4F 43" => &["DOC"],
    "0E 4E 65 72 6F 49 53 4F" => &["NRI"],
    "0E 57 4B 53" => &["WKS"],
    "0F 00 E8 03" => &["PPT"],
    "0F 53 49 42 45 4C 49 55 53" => &["SIB"],
    "10 00 00 00" => &["CL5"],
    "11 00 00 00 53 43 43 41" => &["PF"],
    "1A 00 00" => &["NTF"],
    "1A 00 00 04 00 00" => &["NSF"],
    "1A 02" => &["ARC"],
    "1A 03" => &["ARC"],
    "1A 04" => &["ARC"],
    "1A 08" => &["ARC"],
    "1A 09" => &["ARC"],
    "1A 0B" => &["PAK"],
    "1A 35 01 00" => &["ETH"],
    "1A 45 DF A3" => &["WEBM", "MKV"],
    "1A 45 DF A3 93 42 82 88" => &["MKV"],
    "1A 52 54 53 20 43 4F 4D" => &["DAT"],
    "1D 7D" => &["WS"],
    "1F 8B 08" => &["GZ", "VLT"],
    "1F 8B 08 00" => &["DSS"],
    "1F 9D 90" => &["TAR.Z"],
    "1F A0" => &["TAR.Z"],
    "21" => &["BSB"],
    "21 0D 0A 43 52 52 2F 54 68 69 73 20 65 6C 65 63" => &["BSB"],
    "21 12" => &["AIN"],
    "21 3C 61 72 63 68 3E 0A" => &["LIB"],
    "21 42 44 4E" => &["OST"],
    "23 20" => &["MSI"],
    "23 20 44 69 73 6B 20 44" => &["VMDK"],
    "23 20 4D 69 63 72 6F 73" => &["DSP"],
    "23 20 54 68 69 73 20 69 73" => &["ETA"],
    "24 53 44 49 30 30 30 31" => &["SDI"],
    "25 21 50 53" => &["EPS", "PS"],
    "25 50 44 46" => &["PDF"],
    "25 62 69 74 6D 61 70" => &["FBM"],
    "25 21 42 53 2D 41 64 6F 62 65" => &["HQX"],
    "26 00 00 00" => &["LOG"],
    "1F 00" => &["LHA"],
    "2A 2A 2A 20 49 6E 73 74 61 6C 6C 61 74 69 6F 6E" => &["IVR"],
    "2E 52 4D 46" => &["RM", "RMVB"],
    "2E 52 4D 46 00 00 00 12 00" => &["RA"],
    "2E 72 61 FD 00" => &["RA"],
    "2E 73 6E 64" => &["AU"],
    "31 BE 00 00 00 AB 00 00 00" => &["MSF"],
    "33 C0 8E D0 BC 00 7C" => &["CAT"],
    "30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C" => &["ASF", "WMA", "WMV"],
    "34 CD B2 A1" => &["EVT"],
    "35 2D 00 00 2A" => &["GED"],
    "3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E" => &["NTF"],
    "3C 4D 61 6B 65 72 46 69 6C 65" => &["WRI", "WRI"],
    "3C 50 43 53 20 58 4D 4C" => &["PCS"],
    "3C 72 73 73" => &[""],
    "37 7A BC AF 27 1C" => &["7Z"],
    "38 42 50 53" => &["PSD"],
    "3C 3F" => &["SLE"],
    "3C 41 53 58" => &["ASX"],
    "3C 44 44 4F 43 54 59 50 45" => &["XDR"],
    "3C 4D 43 49" => &["DCI"],
    "3C 53 43 52 49 50 54" => &["WSC"],
    "3C 61 73 73 65 6D 62 6C 79" => &["MANIFEST"],
    "3C 3F 78 6D 6C" => &["XML"],
    "3C 4D 53 43" => &["MSC"],
    "3E 00 03 00 FE FF 09 00 06" => &["MXF"],
    "3C 43 73 6F 75 6E 64 53 79 6E 74 68" => &["CSD"],
    "3C 45 54 41" => &["ETA"],
    "3C 46 4D 20 56 65 72 73 69 6F 6E" => &["FM"],
    "3C 67 70 78 20 76 65 72 73 69 6F 6E" => &["GPX"],
    "42 38 42 57" => &["B85"],
    "43 61 6C 63 75 6C 61 74 65 64 20 57 61 76" => &["WB3"],
    "46 00 00 00" => &["GID"],
    "47 52 49 42" => &["ENL"],
    "41 42 4F 58" => &["ABOX2"],
    "41 43 31 30" => &["DWG"],
    "41 43 53 44" => &["SLE"],
    "41 44 49 46" => &[""],
    "41 4D 59 4F" => &["SYW"],
    "41 4F 4C 20 46 65 65 64 62 61 67" => &["ABI"],
    "41 4F 4C 44 42" => &["BAG", "IDX"],
    "41 4F 4C 49 44 58" => &["IND"],
    "41 4F 4C 56 4D 31 30 30" => &["ABI"],
    "41 56 47 36" => &["ORG"],
    "41 56 49 20" => &["DAT", "AVI"],
    "41 72 43 01" => &["ARC"],
    "42 41 43 4B 4D 49 4B 45 44 49 53 4B" => &[""],
    "42 44 49 43" => &["BDIC"],
    "42 45 47 49 4E 3A 56 43 41 52 44" => &["VCF"],
    "42 4C 49 32 32 33" => &["BIN"],
    "42 4D" => &["BMP", "DIB"],
    "42 50 47 FB" => &["BPG"],
    "42 5A 68" => &["BZ2", "TBZ2"],
    "43 41 52 52" => &["DMG"],
    "43 44 30 30 31" => &["APUF", "ISO"],
    "43 4C 41 4E 47 5F 61 73 74" => &["BLI"],
    "43 52 45 47" => &["RTD"],
    "46 4F 52 4D" => &["IFF", "AIFF"],
    "43 42 46 49 4C 45" => &["CBD"],
    "43 44 44 41" => &["CDA"],
    "43 49 53 4F" => &["CSO"],
    "43 4D 58 31" => &["DB"],
    "43 4C 42" => &["CLB"],
    "43 4C 42 00" => &["CLB"],
    "43 4F 57 44" => &["VMDK"],
    "43 50 54 37 46 49 4C 45" => &["CPT"],
    "43 50 54 46 49 4C 45" => &["CPT"],
    "43 52 55 53 48" => &["DAT", "CRU"],
    "43 57 53" => &["SWF"],
    "43 49 4E" => &["CIN"],
    "43 54 46 5F" => &["CTF"],
    "43 72 4F 44" => &["DAT", "CRX"],
    "43 68 72 6F 6D 65 20 45 78 74" => &["CRX"],
    "43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46" => &["VOC"],
    "44 41 41" => &["DAA"],
    "44 41 58 00" => &["DAX"],
    "44 42 48" => &["DB"],
    "44 4D 53 21" => &["DMS"],
    "44 4F 53" => &["ADF"],
    "44 53 54" => &["DST"],
    "44 56 44" => &["DVR"],
    "44 56 44 56 49 44 45 4F 2D 44 56 44" => &["IFO"],
    "45 4C 49 54 45 20 43 6F 6D 70 61 73 73 20 4D 6F" => &["CDR"],
    "45 4E 54 52 59 56 43 44 02 00 00 01 02 00 18 58" => &["VCD"],
    "45 52 02 00 00 00" => &["ISO", "IMG"],
    "45 56 46 09 0D 0A FF 00" => &["DAT"],
    "45 56 46 32 0D 0A 81" => &["DSF"],
    "45 50" => &["MDI"],
    "45 56 46" => &["E01"],
    "45 78 2F 01" => &["Ex01"],
    "45 6C 66 46 69 6C 65" => &["EVTX"],
    "45 86 00 00 06 00" => &["QBB"],
    "46 41 58 43 4F 56 45 52 2D 56 45 52" => &["CPE"],
    "46 44 42 48 00" => &["FDB"],
    "46 4C 56 01" => &["FLV"],
    "46 4C 69 43" => &["ANM"],
    "46 4F 52 4D 00" => &["IFF", "AIFF"],
    "46 50 58 20" => &["DAX"],
    "46 57 53" => &["SWF"],
    "46 72 6F 6D 20 20 20" => &["EML"],
    "47 49 46 38 37 61" => &["GIF"],
    "47 49 46 38 39 61" => &["PAT"],
    "47 52 49 42 00 00 00 02" => &["GRB"],
    "47 58 32" => &["GX2"],
    "47 53 46 00" => &["G64"],
    "47 50 41 54" => &["PBD"],
    "53 50 53 53" => &["XPT"],
    "48 48 47 42 31" => &["SH3"],
    "49 49 2A 00" => &["TIF", "TIFF"],
    "49 44 33" => &["MP3", "KOZ"],
    "49 49 1A 00 00 00 48 45 41 50 43 43 44 52 02 00" => &["CRW"],
    "49 49 2A 00 10 00 00 00 43 52" => &["TIF", "TIFF"],
    "49 4E 44 58" => &["DB"],
    "49 53 63 28" => &["CAB"],
    "49 54 4F 4C 49 54 4C 53" => &["LIT"],
    "49 54 53 46" => &["CHI"],
    "49 6E 74 65 72 20 40 63 74 72 6C" => &["DAT"],
    "49 50 4D 44 42" => &["IPD"],
    "50 4B 03 04" => &["JAR", "ZIP", "APK", "DOCX", "KMZ", "KWD", "ODT", "OXPS", "SXC", "WMZ", "XPI", "XPS", "XPT", "EPUB", "PPTX", "ODP", "XLSX", "OTT", "PPTX", "XLSX"],
    "50 4B 03 04 14 00 06 00" => &["DOCX", "PPTX", "XLSX"],
    "50 4B 05 06" => &["ZIP"],
    "50 4B 07 08" => &["ZIP"],
    "4A 47 03 0E" => &["JG"],
    "4A 47 04 0E" => &["JG"],
    "4A 4B 44 47 FB" => &["VMDK"],
    "4B 47 42 5F 61 72 63 68 20 2D" => &["KGB"],
    "4B 49 00 00" => &["SHD"],
    "4C 00 00 00 01 14 02 00" => &["LNK"],
    "4C 01" => &["OBJ"],
    "4C 44 53 43" => &["DST"],
    "4C 4E 02 00" => &["GID"],
    "4C 49 46 46" => &["IFF", "ANM"],
    "4C 76 56 32" => &["E01"],
    "4D 41 52 31 00" => &["PDB"],
    "4D 41 52 43" => &["MAR"],
    "4D 41 72 30 00" => &["MAR"],
    "4D 41 54 4C 41 42 20 35 2E 30 20 4D 41 54 2D 66" => &["MAT"],
    "4D 43 57" => &["MTE"],
    "4D 44 4D 50 93 A7 68 10" => &["DMP"],
    "4D 4C 53 57" => &["MLS"],
    "4D 4C 54 49" => &["MLS"],
    "4D 4D 00 2A" => &["TIF", "TIFF"],
    "4D 4D 00 2B" => &["TIF", "TIFF"],
    "4D 4D 4D 44 00 00" => &["MMF"],
    "4D 53 46 54 02 00 01 00" => &["NVRAM"],
    "4D 53 43 46" => &["CAB"],
    "4E 6F 6E 65" => &["ONEPKG"],
    "4F 67 67 53" => &["PPZ", "OGG", "OGV", "OGX"],
    "4F 4C 45 41" => &["SNP"],
    "4F 4C 45 41 00" => &["TLB"],
    "4F 4D 4F 4D" => &["HL7"],
    "4D 53 57 49 4D 00 00 D0" => &["WIM"],
    "4D 56 44 49" => &["CDR"],
    "4D 54 68 64" => &["MID", "MIDI", "RMI"],
    "4D 56 30 31" => &["PCS"],
    "4D 4C 53 57 4E 47" => &["DSN"],
    "4D 4C 53 57 4E 47 30 30" => &["MLS"],
    "4D 4C 53 57 4E 47 30 31" => &["MLS"],
    "4D 5A" => &["COM", "ACM", "AX", "CPL", "FON", "OCX", "OLB", "SCR", "VBX", "VXD", "API", "FLT", "ZAP", "PDB", "DLL", "EXE", "PIF"],
    "4D 5A 90 00 03 00 00 00" => &["SLN"],
    "4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 4D 65 64 69 61 20 50 6C 61 79 65 72 20 2D 2D" => &["WPL"],
    "4D 53 5F 56 4F 49 43 45" => &["MSV", "DVF"],
    "4E 45 53 4D 1A 01" => &["GDB"],
    "4E 54 52 4B 43 48 4E 4B" => &["DAT", "NTF"],
    "4E 61 6D 65 42 61 73 65" => &["JNT"],
    "4E 45 58 54" => &["NSF"],
    "4E 61 6D 65" => &["COD"],
    "4F 67 67 53 00 02 00 00" => &["attachment"],
    "4F 54 54 4F" => &["DBF", "OTF"],
    "4F 67 67 53 00 02 00 00 00 00 00 00 00 00" => &["OGA"],
    "5B 4D 53 56 43" => &["DW4"],
    "4D 53 5F 56 4F 49 43 45 00" => &["IDX"],
    "50 35 0A" => &["PGM"],
    "50 41 4B 00" => &["PAK"],
    "50 41 47 45 44 55 36 34" => &["DMP"],
    "50 41 58" => &["PAX"],
    "50 42 4F 58 43 4E 54 52" => &["DAT"],
    "50 47 50 64 4D 41 49 4E" => &["PGD"],
    "50 49 43 54 00 08" => &["IMG"],
    "52 41 52 21 1A 07 00" => &["RAR"],
    "52 61 72 21 1A 07 01 00" => &["RAR"],
    "52 45 43 45 49 50 54" => &["EML"],
    "52 54 53 53" => &["PF"],
    "52 49 46 46" => &["AST", "WAV", "WEBP", "AVI"],
    "52 53 56 4B 44 41 54 41" => &["IMG"],
    "53 44 50 58" => &["SDPX"],
    "53 48 4F 57" => &["SHW"],
    "53 54 41 52 54 4F 46" => &["CPI"],
    "53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54" => &["FITS"],
    "53 49 54 21 00" => &["SIT"],
    "53 44 52 00" => &["SDR"],
    "53 50 46 49 00" => &["SPF"],
    "53 50 56 42" => &["SPVB"],
    "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00" => &["DB"],
    "53 74 75 66 66 49 74" => &["SIT", "CNV"],
    "53 75 6E 20 4A 44 4B 20" => &["CAL"],
    "54 68 69 73 20 69 73 20 61 20 63 6F 6D 70 69 6C 65 64 20 63 6C 69 70 20 62 6F 61 72 64" => &["THP"],
    "73 72 63 64 6F 63 69 64 3A" => &["INFO"],
    "55 43 45 58" => &["UCE"],
    "55 46 41 12 29 00 A1 A4" => &["UFA"],
    "55 6E 46 61 63 65 57 65 62" => &["DAT"],
    "4D 46 34" => &["MF4"],
    "56 43 50 43 48 30" => &["PCH"],
    "56 58 4C 57" => &["CTL"],
    "56 65 72 73 69 6F 6E 20" => &["MIF"],
    "58 43 50 00" => &["SCT", "CAP", "ECF"],
    "52 49 46 46 XX XX XX XX 57 41 56 45" => &["WAV"],
    "52 49 46 46 XX XX XX XX 57 45 42 50" => &["WEBP"],
    "57 53 32 30 30 30" => &["WS2"],
    "57 6F 72 64 73 00" => &["LWP"],
    "58 2D" => &["EML"],
    "58 50 4B 00" => &["XPT"],
    "44 50 58 20" => &["DPX"],
    "42 44 52" => &["BDR"],
    "5A 4F 4F 20" => &["ZOO"],
    "56 43 57 20 46 6F 72 6D 61 74" => &["VCW"],
    "5B 50 68 6F 6E 65 5D" => &["DUN"],
    "57 6F 72 64 50 72 6F" => &["SAM"],
    "56 4D 44 4B" => &["VMD"],
    "7C 4C 75 63" => &["CPX"],
    "5B 56 65 72 73 69 6F 6E 5D" => &["CFG"],
    "5B 70 6C 61 79 6C 69 73 74 5D" => &["PLS"],
    "80 00 00 20 03 12 04" => &["HUS"],
    "50 4B 03 04 0A 00 02 00" => &["JAR"],
    "43 41 53 00 00 00" => &["CAS"],
    "60 EA" => &["ARJ"],
    "62 33 32 14" => &["b64"],
    "62 65 67 69 6E" => &[""],
    "43 41 46 20 00 01" => &["CAF"],
    "78 01 73 0D 62 62 60" => &["DMG"],
    "76 68 64 78 66 69 6C 65" => &["VHD"],
    "63 75 73 68 00 00 00 02" => &["CSH"],
    "30 82 02" => &["P10"],
    "64 38 3A 61 6E 6E 6F 75 6E 63 65" => &["TORRENT"],
    "64 65 78 0A 30 33 35 00" => &["dex"],
    "4E 43 42" => &["DSW"],
    "66 4C 61 43 00 00 00 22" => &["FLAC"],
    "00 00 00 20 66 74 79 70 4D 34 56 20" => &["MP4", "M4V"],
    "00 00 00 20 66 74 79 70 4D 34 41 20" => &["M4A"],
    "00 00 00 20 66 74 79 70 46 34 56 20" => &["FLV"],
    "00 00 00 20 66 74 79 70 69 73 6F 6D" => &["MP4"],
    "00 00 00 20 66 74 79 70 6D 70 34 32" => &["MP4", "M4V"],
    "00 00 00 20 66 74 79 70 71 74 20 20" => &["MOV"],
    "4B 49 00 00 00 00 00 00" => &["SHD"],
    "67 69 6D 70 20 78 63 66 20" => &["XCF"],
    "4B 49 00 01" => &["SHD"],
    "69 63 6E 73" => &["ICNS"],
    "42 4B 48 4D" => &["DBB"],
    "6D 6F 6F 76" => &["MOV"],
    "66 72 65 65" => &["MOV"],
    "6D 64 61 74" => &["MOV"],
    "77 69 64 65" => &["MOV"],
    "70 6E 6F 74" => &["MOV"],
    "73 6B 69 70" => &["MOV"],
    "54 52 55 45 56 49 53 49 4F 4E 2D 58 46 49 4C 45 2E 00" => &["TPL"],
    "73 6C 68 21" => &["INFO"],
    "73 6C 68 2E" => &["DAT", "INFO"],
    "41 43 00" => &["AC"],
    "72 74 73 70 3A 2F 2F" => &["RAM"],
    "4D 52 56 4E" => &["DAT"],
    "4F 50 4C 44 61 74 61 62 61 73 65 49 6D 61 67 65" => &["DAT"],
    "50 4D 4F 43 43 4D 4F 43" => &["PDB"],
    "4C 00 00 00" => &["STL"],
    "B5 A2 B0 B3 B3 B0 A2 B5" => &["CAL"],
    "AC ED 00 05 73 72" => &["PDB"],
    "4A 6F 79 21" => &["PRC"],
    "00 01 00 00" => &["TTF"],
    "1F 8B" => &["TAR"],
    "76 2F 31 01" => &["EXR"],
    "FF FF FF FF 0E" => &["FLT"],
    "77 4F 46 32" => &["WOFF2"],
    "77 4F 46 46" => &["WOFF"],
    "78 61 72 21" => &["XAR"],
    "4C 67 43 61 63 68 65" => &["LGC", "LGD"],
    "47 44 52 41 57" => &["GDRAW"],
    "70 77 69" => &["PWI"],
    "7B 5C 72 74 66 31" => &["RTF"],
    "7E 42 4B 00" => &["PSP"],
    "45 53 44 20 44 69 73 63 6F 76 65 72 79 20 46 6F 72 6D 61 74" => &["ESD"],
    "78 56 34 12" => &["OBJ"],
    "80 2A 5F D7" => &["ADX"],
    "80 3E 44 AC 99 40 D0 11 A7 61 00 A8 C9 33 56 0B" => &["CIN"],
    "9C CB CB 8D 13 75 D2 11 91 58 00 C0 4F 79 56 A4" => &["WAB", "AW"],
    "81 CD AB" => &["WPF"],
    "89 50 4E 47 0D 0A 1A 0A" => &["PNG"],
    "A1 B2 C3 D4" => &["HAP"],
    "95 00" => &["SKR"],
    "95 01" => &["SKR"],
    "97 4A 42 32 0D 0A 1A 0A" => &["JB2"],
    "99" => &["GPG"],
    "99 01" => &["PKR"],
    "A1 B2 CD 34" => &[""],
    "A9 46 49 4C 45" => &["DAT"],
    "AB 4B 54 58 20 31 31 BB 0D 0A 1A 0A" => &["KTX"],
    "AC 9E BD 8F 00 00" => &["QDF"],
    "A0 46 1D F0" => &["PPT"],
    "B4 6E 68 44" => &["", "TIB"],
    "C3 AB BE 22 C0 11 D0 11 85 9B 00 AA 00 4B 2E 24" => &["PDB"],
    "CF AD 12 FE" => &["PWL"],
    "C5 D0 D3 C6" => &["DCX", "DAT"],
    "B4 6E 68 44 00 00 00 00" => &["CAL"],
    "C8 00 79 00" => &["INS"],
    "C6 24" => &["WRI"],
    "CF FA ED FE" => &["ACS", "DOC"],
    "25 21 50 53 2D 41 64 6F 62 65" => &["EPS"],
    "4C 4B 42 4B" => &["LBK"],
    "CA FE BA BE" => &["CLASS"],
    "4E 4F 4B 4F 42 55 53 48 49 2C 20 4E 4F 4B 4F" => &["NBU"],
    "CE CE CE CE" => &["JCEKS"],
    "CF 11 E0 A1 B1 1A E1 00" => &[""],
    "D0 CF 11 E0 A1 B1 1A E1" => &["DBX", "DOC", "AC_", "ADP", "APR", "DB", "MSC", "MSI", "MSP", "MTW", "MXD", "OPT", "PUB", "RVT", "SOU", "SPO", "VSD", "WPS", "XLS", "PPT", "DOT", "XLA", "PPS", "MSG"],
    "D2 0A 00 00" => &["FTR"],
    "D4 C3 B2 A1" => &["ARL"],
    "D7 CD C6 9A" => &["WMF"],
    "DB A5 2D 00 00 00 00 00" => &["DOC"],
    "DC DC" => &["CPL"],
    "E3 10 00 01 00 00 00 00" => &["EFX"],
    "EB 52 90 4E 54 46 53 20 20 20 20 00" => &["SYS"],
    "E6 00 00 00 00 EC" => &["PWL"],
    "E8 00 00 00" => &["COM"],
    "E8 03 00 00" => &["COM"],
    "E9 00 00 00" => &["COM"],
    "EB 5A 90" => &[""],
    "EB 76 90" => &[""],
    "D0 CF 11 E0 A1 B1 1A E1 00 00 00 00 00 00 00 00 3E 00 03 00" => &["DOC"],
    "52 50 4D 00 FF FF" => &["RPM"],
    "FF 57 50 43" => &[""],
    "FF 57 50 43 08" => &["WSF"],
    "FF 57 50 43 09" => &["WSC"],
    "EF BB BF" => &["YTT"],
    "F0 F0 F0 F0" => &[""],
    "FE 30 00 00 00 AC C2 71" => &[""],
    "FE ED FA CE" => &[""],
    "FE ED FA CF" => &["DAT"],
    "FD 37 7A 58 5A 00" => &["XZ"],
    "06 32 00" => &["PUB"],
    "4A 6F 79 21 4C 59 58" => &["DB"],
    "06 06 2B 34 01 01 01 02 4C 02 41 14 BE E0 82 6C" => &["PUB"],
    "51 42 44 42" => &["QBM"],
    "FD FF FF FF 1C 00 00 00" => &["SUO"],
    "D0 CF 11 E0" => &["XLS"],
    "FD FF FF FF 20 00 00 00" => &["PPT"],
    "FD FF FF FF 22 00 00 00" => &["XLS"],
    "FD FF FF FF 23 00 00 00" => &["PPT"],
    "FD FF FF FF 28 00 00 00" => &["XLS"],
    "FD FF FF FF 29 00 00 00" => &["PPT"],
    "FD FF FF FF 43 00 00 00" => &["XLS"],
    "FD FF FF FF C0 00 00 00" => &["XLS"],
    "FD FF FF FF E2 00 00 00" => &["XLS"],
    "FD FF FF FF" => &["XLS"],
    "FE FF" => &[""],
    "FF 00 02 00 04 04 05 54 02 00" => &["GHO"],
    "FF 00 02 00 04 04 05 54 02 00 00 00" => &["GHS"],
    "FF FE 23 00 6C 00 69 00 6E 00 65 00 20 00 31 00" => &["SYS"],
    "FF FE" => &[""],
    "FF FE FF 0E 53 00 6B 00 65 00 74 00 63 00 68 00 55 00 70 00 20 00 4D 00 6F 00 64 00 65 00 6C 00" => &["SYS"],
    "FF D8 FF E0" => &["JPE", "JFIF", "JPG", "JPEG"],
    "FF D8 FF E1" => &["JPG"],
    "FF D8 FF E8" => &[""],
    "FF D8 FF FE" => &[""],
    "FF D8 FF" => &["JPG", "JPEG", "WPG", "WPD", "WPP", "WP5", "WP6"],
    "49 44 33 03 00 00 00" => &["AAC"],
    "FF F1" => &["AAC"],
    "FF F9" => &["REG"],
    "52 45 47 45 44 49 54" => &[""],
    "47 00 00 00" => &["MOF"],
    "FF 35 2A 00" => &["SYS"],
};
