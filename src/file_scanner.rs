use std::fs;
use sha2::{Sha256, Digest};
use hex;
use std::path::Path;
use reqwest::blocking::Client;
use serde::Deserialize;
/*
    This function will be used to scan a file given its path. It will collect the necessary information about the file
    and then pass it to the analyze_file function for further analysis.    
 */
pub fn scan_file(file_path: &str) -> bool {
    let metadata = fs::metadata(file_path).unwrap();
    
    // File name
    let name = Path::new(file_path).file_name().unwrap_or_default().to_string_lossy().to_string();
    
    // File size
    let size = metadata.len();
    
    // File type
    let n1 = file_path.find(".").unwrap_or(file_path.len());
    let file_type = &file_path[n1..];

    // Hash
    let mut sha256 = Sha256::new();
    sha256.update(file_path);
    let hash: String = format!("{:x}", sha256.finalize());

    // Collect file hex
    let hex = hex::encode(file_path);

    // Collect file contents
    let contents = fs::read_to_string(file_path).unwrap_or(String::from("Could not read file contents"));

    let new_file =  File {
        name: name,
        size: size,
        file_type: file_type,
        hash: &hash,
        hex: hex,
        contents: contents,
    };

    let result = analyze_file(&new_file);

    result
}

struct File<'a> {
    name: String,
    size: u64,
    file_type: &'a str,
    hash: &'a str,
    hex: String,
    contents: String, 
}


// The following will be used to run through the tests on each separate area of the file, returning a boolean of the file's safety.
fn analyze_file(file: &File) -> bool {
    println!("File name: {}", file.name);
    println!("File size: {} bytes", file.size);
    println!("File type: {:#?}", file.file_type);
    println!("File hash: {}", file.hash);
    println!("File hex: {}", file.hex);
    println!("File contents: {}", file.contents);

    let mut rating = 10; 

    if file.size < 1024 {
        rating -= 2;
    }

    match check_query(file.hash, "cffbefaf6178b38f75902a99ee5463f8604a3b8bb26422e5") {
        Ok(true) => return false,
        Ok(false) => {},
        Err(e) => eprintln!("Failed to query hash: {}", e),
    }

    let header_list = vec![
        vec!["00 00 00", "00 00 00 20 66 74 79 70 68 65 69 63", "00 00 00 0C 6A 50 20 20", "00 00 00 14 66 74 79 70", "00 00 00 14 66 74 79 70 69 73 6F 6D", "00 00 00 14 66 74 79 70", "00 00 00 00 14 00 00 00", "00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00", "00 00 00 18 66 74 79 70", "00 00 00 1C 66 74 79 70", "00 00 00 20 66 74 79 70", "00 00 00 20 66 74 79 70 4D 34 41", "00 00 00 20 66 74 79 70", "00 00 01 00", "00 00 01 B3", "00 00 01 BA", "00 00 02 00", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "00 00 02 00", "00 00 03 F3", "00 20 AF 30", "00 00 02 00 06 04 06 00", "00 00 1A 00 00 10 04 00", "00 00 1A 00 02 10 04 00", "00 00 1A 00 05 10 04", "00 00 49 49 58 50 52", "00 00 4D 4D 58 50 52", "00 00 FF FF FF FF", "00 01 00 00 00", "00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65", "00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42", "00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42", "00 01 42 41", "00 01 42 44", "00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00", "00 0D BB A0", "00 11", "00 14 00 00 01 02", "00 1E 84 90 00 00 00 00", "00 3B 05 00 01 00 00 00", "00 6E 1E F0", "01 00 02 00", "01 00 39 30", "01 01 47 19 A4 00 00 00 00 00 00 00", "01 0F 00 00", "01 10", "01 DA 01 01 00 03", "01 FF 02 04 03 02", "02 64 73 73", "3", "3", "03 00 00 00", "03 00 00 00", "03 00 00 00 41 50 50 52", "03 64 73 73", "4", "04 00 00 00", "05 00 00 00", "06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D", "06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02", "7", "07 53 4B 46", "07 64 74 32 64 64 74 64", "8", "09 08 10 00 00 06 05 00", "0A 02 01 01", "0A 03 01 01", "0A 05 01 01", "0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72", "0C ED", "0D 44 4F 43", "0E 4E 65 72 6F 49 53 4F", "0E 57 4B 53", "0F 00 E8 03", "0F 53 49 42 45 4C 49 55 53", "10 00 00 00", "11 00 00 00 53 43 43 41", "1A 00 00", "1A 00 00 04 00 00", "1A 02", "1A 03", "1A 04", "1A 08", "1A 09", "1A 0B", "1A 35 01 00", "1A 45 DF A3", "1A 45 DF A3", "1A 45 DF A3 93 42 82 88", "1A 52 54 53 20 43 4F 4D", "1D 7D", "1F 8B 08", "1F 8B 08", "1F 8B 08 00", "1F 9D 90", "1F A0", "21", "21 0D 0A 43 52 52 2F 54 68 69 73 20 65 6C 65 63", "21 12", "21 3C 61 72 63 68 3E 0A", "21 42 44 4E", "23 20", "23 20 44 69 73 6B 20 44", "23 20 4D 69 63 72 6F 73", "23 20 54 68 69 73 20 69 73"],
        vec!["AVIF", "HEIC", "JP2", "3GP", "MP4", "3GG", "TBI", "DAT", "3GP5", "MP4", "3GP", "M4A", "3GG", "ICO", "MGP", "MPG", "CUR", "XXX", "WB2", "", "TPL", "WK1", "WK3", "WK4", "123", "QXD", "QXD", "HLP", "TTF", "MNY", "ACCDB", "MDB", "ABA", "DBA", "DB", "", "FLI", "", "SNM", "DB", "PPT", "ARF", "FDB", "TBI", "MDF", "TR1", "RGB", "DRW", "DSS", "DAT", "DB3", "QPH", "NFC", "ADX", "DSS", "DB4", "", "", "INDD", "MXF", "DRW", "SKF", "DTD", "DB", "XLS", "PCX", "PCX", "PCX", "WALLET", "MP", "DOC", "NRI", "DKS", "PPT", "SIB", "CL5", "PF", "NTF", "NSF", "ARC", "ARC", "ARC", "ARC", "ARC", "PAC", "ETH", "WEBM", "MKV", "MKV", "DAT", "WS", "GZ", "VLT", "DSS", "TAR.Z", "TAR.Z", "BSB", "BSB", "AIN", "LIB", "OST", "MSI", "VMDK", "DSP", "ETA", "AMR", "SIL", "HDR", "VBE", "NBF", "PEC", "PES", "SAV", "EPS", "PS", "PDF", "FBM", "HQX", "LOG", "LHA", "IVR", "RM", "RA", "RA", "AU", "MSF", "CAT", "EVT", "GED", "ASF", "NTF", "", "WRI", "WRI", "PCS", "", "7Z", "", "PSD", "SLE", "ASX", "XDR", "DCI", "WSC", "MANIFEST", "XML", "MSC", "MXF", "CSD", "ETA", "FM", "GPX", "B85", "WB3", "GID", "ENL", "ABOX2", "DWG", "SLE", "", "SYW", "ABI", "BAG", "ABY", "IDX", "IND", "ABI", "ORG", "DAT", "AVI", "ARC", "", "BDIC", "VCF", "BIN", "BMP", "PRC", "BPG", "BZ2", "DMG", "APUF", "BLI", "RTD", "IFF", "CBD", "ISO", "CDA", "CSO", "DB", "CLB", "CLB", "VMDK", "CPT", "CPT", "DAT", "CRU", "SWF", "CIN", "CTF", "DAT", "CRX", "CRX", "VOC", "DAA", "DAX", "DB", "DMS", "ADF", "DST", "DVR", "IFO", "CDR", "VCD", "ISO", "DAT", "DSF", "MDI", "E01", "Ex01", "EVTX", "QBB", "CPE", "FDB", "", "FLV", "ANM", "IFF", "AIFF", "DAX", "SWF", "EML", "GIF", "PAT", "GRB", "GX2", "G64", "PBD", "XPT", "SH3", "TIF", "MP3", "KOZ", "CRW", "TIF", "DB", "CAB", "LIT", "CHI", "DAT", "IPD", "JAR", "JG", "JG", "VMDK", "KGB", "SHD", "", "LNK", "OBJ", "DST", "GID", "IFF", "ANM", "E01", "PDB", "MAR", "MAR", "MAT", "MAR", "MTE", "DMP", "MLS", "MLS", "TIF", "TIF", "MMF", "NVRAM", "CAB", "ONEPKG", "PPZ", "SNP", "TLB", "HL7", "WIM", "CDR", "MID", "PCS", "DSN", "MLS", "MLS", "COM", "ACM", "AX", "CPL", "FON", "OCX", "OLB", "SCR", "VBX", "VXD", "API", "AX", "FLT", "ZAP", "PDB", "SLN", "WPL", "GDB", "DAT", "JNT", "NSF", "NTF", "COD", "attachment", "DBF", "OTF", "OGA", "DW4", "IDX", "PGM", "PAK", "DMP", "PAX", "DAT", "PGD", "IMG", "ZIP", "APK", "ZIP", "DOCX", "JAR", "KMZ", "KWD", "ODT", "OXPS", "SXC", "SXC", "WMZ", "XPI", "XPS", "XPT", "EPUB", "ZIP", "DOCX", "JAR", "ZIP", "ZIP", "ZIP", "ZIP", "GRP", "DAT", "PMOCCMOC", "DSF", "PUF", "", "QEL", "QEMU", "QCP", "ABD", "MSG", "DAT", "RDATA", "REG", "AD", "ANI", "CMX", "CDR", "DAT", "DS4", "4XM", "AVI", "RMI", "CAP", "RAR", "EML", "PF", "AST", "IMG", "SDPX", "SHW", "CPI", "FITS", "SIT", "SDR", "SPF", "SPVB", "DB", "CNV", "", "", "SIT", "CAL", "THP", "INFO", "UCE", "UFA", "DAT", "MF4", "PCH", "CTL", "MIF", "SCT", "WAV", "WEBP", "DAT", "WS2", "ZIP", "LWP", "EML", "CAP", "XPT", "DPX", "BDR", "ZOO", "SWF", "ECF", "VCW", "DUN", "SAM", "VMD", "CPX", "CFG", "PLS", "SAM", "HUS", "JAR", "CAS", "ARJ", "", "b64", "", "CAF", "DMG", "VHD", "CSH", "P10", "TORRENT", "dex", "AU", "DSW", "DMG", "SHD", "FLAC", "MP4", "M4A", "FLV", "MP4", "MP4", "M4V", "MOV", "SHD", "XCF", "SHD", "ICNS", "DBB", "MOV", "MOV", "MOV", "MOV", "MOV", "MOV", "TPL", "INFO", "", "", "DAT", "AC", "RAM", "DAT", "DAT", "PDB", "STL", "CAL", "PDB", "PRC", "TTF", "TAR", "EXR", "FLT", "WOFF2", "WOFF", "DMG", "XAR", "INFO", "LGC", "GDRAW", "PWI", "RTF", "CSD", "PSP", "ESD", "IMG", "", "OBJ", "ADX", "CIN", "WAB", "WPF", "PNG", "AW", "HAP", "SKR", "SKR", "JB2", "GPG", "PKR", "WAB", "", "", "DAT", "KTX", "QDF", "PPT", "", "PDB", "PWL", "DCX", "TIB", "CAL", "INS", "WRI", "DAT", "ACS", "EPS", "LBK", "CLASS", "NBU", "", "TIB", "JCEKS", "", "DOC", "DBX", "", "DOC", "AC_", "ADP", "APR", "DB", "MSC", "MSI", "MSP", "MTW", "MXD", "OPT", "PUB", "RVT", "SOU", "SPO", "VSD", "WPS", "FTR", "ARL", "", "WMF", "DOC", "CPL", "EFX", "INFO", "PWL", "ONE", "COM", "COM", "COM", "IMG", "", "", "DOC", "RPM", "", "WSF", "WSC", "YTT", "", "", "", "", "DAT", "XZ", "PUB", "DB", "PUB", "MSG", "QBM", "SUO", "PPT", "XLS", "PPT", "XLS", "PPT", "OPT", "XLS", "XLS", "XLS", "XLS", "PPT", "", "", "", "GHO", "", "SYS", "WKS", "QRP", "CPI", "SYS", "WP", "JPE", "JFIF", "AAC", "AAC", "REG", "", "", "MOF", "SYS"]
        // Completed first set of extensions, use next vectors for rest.
    ];
    
    for h in header_list[0] {
        if h == file.hex {
            let i = header_list.get(h);
            if 
        }
    }

    true
}

fn check_query(sha256: &str, api_key: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let url = "https://mb-api.abuse.ch/api/v1/";
    let client = Client::builder().build()?;
    let form = [
        ("query", "sha256_hash"),
        ("hash", sha256),
    ];

    let resp = client.post(url)
        .header(api_key, "my-malware-checker/1.0",)
        .form(&form)
        .send()?
        .error_for_status()?;


    let text = resp.text()?;
    let mb_resp: MBResponse = serde_json::from_str(&text)?;

    // Helper function to check if the response status is "ok" and data is not empty
    fn is_response_ok(resp: &MBResponse) -> bool {
        resp.query_status.to_lowercase() == "ok" && !resp.data.is_empty()
    }

    Ok(is_response_ok(&mb_resp))
}

#[derive(Deserialize, Debug)]
struct MBResponse {
    query_status: String,
    #[serde(default)]
    data: Vec<serde_json::Value>,
}