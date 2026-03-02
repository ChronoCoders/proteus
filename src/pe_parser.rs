use goblin::pe::PE;
use md5::Context;
use std::fs;

#[derive(Debug, Clone)]
pub struct RichHeaderEntry {
    pub comp_id: u32,
    pub count: u32,
    pub prod_id: u16,
    pub build_id: u16,
}

#[derive(Debug, Clone)]
pub struct RichHeaderInfo {
    pub key: u32,
    pub entries: Vec<RichHeaderEntry>,
}

pub struct PEAnalysis {
    pub entropy: f64,
    pub suspicious_imports: Vec<String>,
    pub num_sections: usize,
    pub import_count: usize,
    pub export_count: usize,
    pub section_entropies: Vec<f64>,
    pub imphash: String,
    pub rich_header: Option<RichHeaderInfo>,
}

pub fn parse_rich_header(buffer: &[u8]) -> Option<RichHeaderInfo> {
    // Rich header is usually in the DOS stub, before the PE header.
    // Search for "Rich" signature (0x68636952)
    let rich_sig = 0x68636952u32;
    let dans_sig = 0x536e6144u32; // "DanS"

    // Limit search to DOS stub/early headers (e.g., first 4KB)
    let search_limit = std::cmp::min(buffer.len(), 4096);
    let mut rich_offset = None;

    // Search for "Rich" (4-byte aligned usually, but let's scan bytes)
    // Using windows so little-endian
    for i in (0..search_limit).step_by(4) {
        if i + 4 > buffer.len() {
            break;
        }
        let val = u32::from_le_bytes(buffer[i..i + 4].try_into().ok()?);
        if val == rich_sig {
            rich_offset = Some(i);
            break;
        }
    }

    let rich_offset = rich_offset?;

    // Key is the DWORD after "Rich"
    if rich_offset + 8 > buffer.len() {
        return None;
    }
    let key = u32::from_le_bytes(buffer[rich_offset + 4..rich_offset + 8].try_into().ok()?);

    // Search backwards for "DanS" XORed with key
    let mut dans_offset = None;
    for i in (0..rich_offset).rev().step_by(4) {
        if i + 4 > buffer.len() {
            continue;
        }
        let val = u32::from_le_bytes(buffer[i..i + 4].try_into().ok()?);
        if (val ^ key) == dans_sig {
            dans_offset = Some(i);
            break;
        }
    }

    let dans_offset = dans_offset?;

    // Parse entries between DanS and Rich
    // Start after DanS (skip 12 bytes of padding usually? No, records start immediately after DanS signature + 3 zero dwords?
    // Actually standard is: DanS, then XORed data, then Rich, then Key.
    // The data is arrays of 8-byte records.

    // let start_data = dans_offset + 16; // Skip DanS (4) + 3 zero DWORDs padding (12) usually found?
    // Wait, the "DanS" is the start marker. The data follows.
    // But typically there are 3 padding DWORDs XORed with Key after DanS?
    // Let's look at the structure more carefully.
    // DanS ^ Key | Pad ^ Key | Pad ^ Key | Pad ^ Key | ... records ... | Rich | Key
    // Actually the padding is variable. But we iterate until we hit Rich.

    let mut entries = Vec::new();
    let mut current = dans_offset + 4; // Start right after DanS

    while current < rich_offset {
        if current + 8 > buffer.len() {
            break;
        }

        let raw_comp_id = u32::from_le_bytes(buffer[current..current + 4].try_into().ok()?);
        let raw_count = u32::from_le_bytes(buffer[current + 4..current + 8].try_into().ok()?);

        let comp_id = raw_comp_id ^ key;
        let count = raw_count ^ key;

        // Check sanity (comp_id high word is prod_id, low is build_id)
        // DanS padding usually decodes to zeros?
        // Let's include valid-looking entries.

        // prod_id is high 16 bits, build_id is low 16 bits
        let prod_id = (comp_id >> 16) as u16;
        let build_id = (comp_id & 0xFFFF) as u16;

        // Padding entries often decode to garbage or specific patterns, but typically "DanS" is followed by 3 zero dwords (XORed).
        // If comp_id and count are valid, add them.
        // A simple check: if it's the padding (which xors to 0), skip.
        if comp_id != 0 || count != 0 {
            entries.push(RichHeaderEntry {
                comp_id,
                count,
                prod_id,
                build_id,
            });
        }

        current += 8;
    }

    Some(RichHeaderInfo { key, entries })
}

pub fn calculate_imphash(pe: &PE) -> String {
    let mut hasher = Context::new();
    let mut first = true;

    for import in &pe.imports {
        let mut import_str = String::new();
        if !first {
            import_str.push(',');
        }

        // Format: dll.function or dll.ordinal
        // Standard imphash uses lowercase DLL name (without extension usually, but pefile keeps it) and function name
        // However, python's pefile implementation:
        // lower(dll_name) . "." . lower(function_name)

        let dll_name = import.dll.to_lowercase();
        // Remove extension if present to match some implementations, but pefile keeps it usually.
        // Let's stick to: lower(dll) . "." . lower(func)

        let func_name = import.name.to_lowercase();

        import_str.push_str(&dll_name);
        import_str.push('.');
        import_str.push_str(&func_name);

        hasher.consume(import_str.as_bytes());
        first = false;
    }

    hex::encode(*hasher.compute())
}

pub fn analyze_pe(path: &str) -> Result<PEAnalysis, Box<dyn std::error::Error>> {
    let buffer = fs::read(path)?;
    let pe = PE::parse(&buffer)?;

    let entropy = crate::entropy::calculate_entropy(&buffer);

    // Calculate Imphash
    let imphash = calculate_imphash(&pe);

    // Parse Rich Header
    let rich_header = parse_rich_header(&buffer);

    let suspicious_apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "LoadLibrary",
        "GetProcAddress",
        "WinExec",
        "ShellExecute",
        "URLDownloadToFile",
        "CreateProcess",
        "OpenProcess",
        "ReadProcessMemory",
        "SetWindowsHookEx",
        "GetAsyncKeyState",
        "InternetOpen",
    ];

    let mut suspicious_imports = Vec::new();
    let import_count = pe.imports.len();

    for import in &pe.imports {
        let import_name = import.name.as_ref();
        if suspicious_apis.contains(&import_name) {
            suspicious_imports.push(import_name.to_string());
        }
    }

    let export_count = pe.exports.len();

    let mut section_entropies = Vec::new();
    for section in &pe.sections {
        if let Ok(Some(data)) = section.data(&buffer) {
            section_entropies.push(crate::entropy::calculate_entropy(&data));
        }
    }

    Ok(PEAnalysis {
        entropy,
        suspicious_imports,
        num_sections: pe.sections.len(),
        import_count,
        export_count,
        section_entropies,
        imphash,
        rich_header,
    })
}
