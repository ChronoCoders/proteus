use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PackerSignature {
    pub name: String,
    pub patterns: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PackerInfo {
    pub detected: bool,
    pub packer_name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

pub struct PackerDetector {
    signatures: HashMap<String, PackerSignature>,
}

impl PackerDetector {
    pub fn new() -> Self {
        let mut signatures = HashMap::new();

        // UPX Packer
        signatures.insert(
            "UPX".to_string(),
            PackerSignature {
                name: "UPX".to_string(),
                patterns: vec![
                    b"UPX0".to_vec(),
                    b"UPX1".to_vec(),
                    b"UPX2".to_vec(),
                    b".UPX".to_vec(),
                ],
            },
        );

        // ASPack
        signatures.insert(
            "ASPack".to_string(),
            PackerSignature {
                name: "ASPack".to_string(),
                patterns: vec![b".aspack".to_vec(), b".adata".to_vec(), b"ASPack".to_vec()],
            },
        );

        // Themida
        signatures.insert(
            "Themida".to_string(),
            PackerSignature {
                name: "Themida/WinLicense".to_string(),
                patterns: vec![
                    b".themida".to_vec(),
                    b"Themida".to_vec(),
                    b"WinLicense".to_vec(),
                ],
            },
        );

        // VMProtect
        signatures.insert(
            "VMProtect".to_string(),
            PackerSignature {
                name: "VMProtect".to_string(),
                patterns: vec![
                    b".vmp0".to_vec(),
                    b".vmp1".to_vec(),
                    b".vmp2".to_vec(),
                    b"VMProtect".to_vec(),
                ],
            },
        );

        // PECompact
        signatures.insert(
            "PECompact".to_string(),
            PackerSignature {
                name: "PECompact".to_string(),
                patterns: vec![b"PECompact".to_vec(), b"pec1".to_vec(), b"pec2".to_vec()],
            },
        );

        // MPRESS
        signatures.insert(
            "MPRESS".to_string(),
            PackerSignature {
                name: "MPRESS".to_string(),
                patterns: vec![
                    b".MPRESS1".to_vec(),
                    b".MPRESS2".to_vec(),
                    b"MPRESS".to_vec(),
                ],
            },
        );

        // NSPack
        signatures.insert(
            "NSPack".to_string(),
            PackerSignature {
                name: "NSPack".to_string(),
                patterns: vec![b".nsp0".to_vec(), b".nsp1".to_vec(), b".nsp2".to_vec()],
            },
        );

        // FSG
        signatures.insert(
            "FSG".to_string(),
            PackerSignature {
                name: "FSG".to_string(),
                patterns: vec![b"FSG!".to_vec(), b".fsg".to_vec()],
            },
        );

        // PEtite
        signatures.insert(
            "PEtite".to_string(),
            PackerSignature {
                name: "PEtite".to_string(),
                patterns: vec![b".petite".to_vec(), b"PEtite".to_vec()],
            },
        );

        // Armadillo
        signatures.insert(
            "Armadillo".to_string(),
            PackerSignature {
                name: "Armadillo".to_string(),
                patterns: vec![b".armadil".to_vec(), b"Armadillo".to_vec()],
            },
        );

        PackerDetector { signatures }
    }

    pub fn detect(&self, data: &[u8], entropy: f64) -> PackerInfo {
        let mut detected_packers = Vec::new();
        let mut indicators = Vec::new();

        // Signature-based detection
        for (name, signature) in &self.signatures {
            for pattern in &signature.patterns {
                if self.search_pattern(data, pattern) {
                    detected_packers.push(name.clone());
                    indicators.push(format!("Signature match: {}", signature.name));
                    break;
                }
            }
        }

        // Entropy-based detection
        if entropy > 7.8 {
            indicators.push(format!("Very high entropy: {:.2}", entropy));
        } else if entropy > 7.5 {
            indicators.push(format!("High entropy: {:.2}", entropy));
        }

        // Determine result
        if !detected_packers.is_empty() {
            let packer_name = detected_packers[0].clone();
            let confidence = if entropy > 7.5 { 0.95 } else { 0.85 };

            PackerInfo {
                detected: true,
                packer_name: self
                    .signatures
                    .get(&packer_name)
                    .map(|s| s.name.clone())
                    .unwrap_or(packer_name),
                confidence,
                indicators,
            }
        } else if entropy > 7.8 {
            // High entropy but no signature match = unknown packer
            PackerInfo {
                detected: true,
                packer_name: "Unknown Packer".to_string(),
                confidence: 0.70,
                indicators,
            }
        } else {
            PackerInfo {
                detected: false,
                packer_name: "None".to_string(),
                confidence: 0.0,
                indicators: vec![],
            }
        }
    }

    fn search_pattern(&self, data: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || data.len() < pattern.len() {
            return false;
        }

        data.windows(pattern.len()).any(|window| window == pattern)
    }
}

impl Default for PackerDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upx_detection() {
        let detector = PackerDetector::new();
        let data = b"Some data UPX0 more data UPX1";
        let result = detector.detect(data, 7.9);

        assert!(result.detected);
        assert!(result.packer_name.contains("UPX"));
    }

    #[test]
    fn test_high_entropy_unknown_packer() {
        let detector = PackerDetector::new();
        let data = b"Random data without signature";
        let result = detector.detect(data, 7.9);

        assert!(result.detected);
        assert_eq!(result.packer_name, "Unknown Packer");
    }

    #[test]
    fn test_no_packer() {
        let detector = PackerDetector::new();
        let data = b"Normal unpacked executable";
        let result = detector.detect(data, 6.5);

        assert!(!result.detected);
    }
}
