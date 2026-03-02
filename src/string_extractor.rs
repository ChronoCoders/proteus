use std::collections::HashSet;

pub struct StringAnalysis {
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub registry_keys: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub file_paths: Vec<String>,
    pub encoded_strings: usize,
    pub total_strings: usize,
}

pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if (32..=126).contains(&byte) {
            current.push(byte as char);
        } else if current.len() >= min_length {
            strings.push(current.clone());
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= min_length {
        strings.push(current);
    }

    strings
}

pub fn extract_wide_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut i = 0;

    while i < data.len().saturating_sub(1) {
        if (32..=126).contains(&data[i]) && data[i + 1] == 0 {
            current.push(data[i] as char);
            i += 2;
        } else if current.len() >= min_length {
            strings.push(current.clone());
            current.clear();
            i += 1;
        } else {
            current.clear();
            i += 1;
        }
    }

    if current.len() >= min_length {
        strings.push(current);
    }

    strings
}

pub fn analyze_strings(data: &[u8]) -> StringAnalysis {
    let ascii_strings = extract_strings(data, 4);
    let wide_strings = extract_wide_strings(data, 4);

    let mut all_strings: HashSet<String> = HashSet::new();
    all_strings.extend(ascii_strings);
    all_strings.extend(wide_strings);

    let mut urls = Vec::new();
    let mut ips = Vec::new();
    let mut registry_keys = Vec::new();
    let mut suspicious_strings = Vec::new();
    let mut file_paths = Vec::new();
    let mut encoded_count = 0;

    let suspicious_keywords = [
        "cmd",
        "powershell",
        "eval",
        "exec",
        "system",
        "shell",
        "download",
        "upload",
        "exploit",
        "payload",
        "inject",
        "allocate",
        "virtualalloc",
        "CreateRemoteThread",
        "keylog",
        "screenshot",
        "webcam",
        "ransomware",
        "encrypt",
        "bitcoin",
        "wallet",
        "miner",
        "cryptonight",
        "monero",
        "privilege",
        "admin",
        "root",
        "bypass",
        "disable",
        "defender",
        "firewall",
        "antivirus",
        "sandbox",
        "vm",
    ];

    for s in all_strings.iter() {
        let lower = s.to_lowercase();

        if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
            urls.push(s.clone());
        }

        if is_ip_address(&lower) {
            ips.push(s.clone());
        }

        if lower.contains("hkey_") || lower.contains("\\registry\\") || lower.contains("software\\")
        {
            registry_keys.push(s.clone());
        }

        if lower.contains(":\\") || lower.contains("/usr/") || lower.contains("/etc/") {
            file_paths.push(s.clone());
        }

        for keyword in &suspicious_keywords {
            if lower.contains(keyword) {
                suspicious_strings.push(s.clone());
                break;
            }
        }

        if is_likely_encoded(s) {
            encoded_count += 1;
        }
    }

    StringAnalysis {
        urls,
        ips,
        registry_keys,
        suspicious_strings: suspicious_strings
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect(),
        file_paths,
        encoded_strings: encoded_count,
        total_strings: all_strings.len(),
    }
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn is_likely_encoded(s: &str) -> bool {
    if s.len() < 20 {
        return false;
    }

    let base64_chars = s
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    let ratio = base64_chars as f64 / s.len() as f64;

    ratio > 0.9 && s.len().is_multiple_of(4)
}
