use crate::packer_detector::{PackerDetector, PackerInfo};

pub struct HeuristicAnalyzer {
    packer_detector: PackerDetector,
}

impl HeuristicAnalyzer {
    pub fn new() -> Self {
        HeuristicAnalyzer {
            packer_detector: PackerDetector::new(),
        }
    }

    pub fn analyze(
        &self,
        entropy: f64,
        import_count: usize,
        export_count: usize,
        suspicious_apis: &[String],
        data: &[u8],
    ) -> (f64, Vec<String>, PackerInfo) {
        let mut score: f64 = 0.0;
        let mut indicators = Vec::new();

        // Packer detection
        let packer_info = self.packer_detector.detect(data, entropy);

        if packer_info.detected {
            score += 15.0;
            indicators.push(format!(
                "Packed with {} ({:.0}% confidence)",
                packer_info.packer_name,
                packer_info.confidence * 100.0
            ));
        }

        // Entropy-based scoring
        if entropy > 7.8 {
            score += 25.0;
            indicators.push(format!("Very high entropy: {:.2}", entropy));
        } else if entropy > 7.5 {
            score += 20.0;
            indicators.push(format!("High entropy: {:.2}", entropy));
        } else if entropy > 7.2 {
            score += 10.0;
            indicators.push(format!("Elevated entropy: {:.2}", entropy));
        }

        // Import/Export analysis
        if import_count == 0 {
            score += 20.0;
            indicators.push("No imports (suspicious)".to_string());
        } else if import_count < 5 {
            score += 10.0;
            indicators.push(format!("Very few imports: {}", import_count));
        }

        if export_count > 100 {
            score += 5.0;
            indicators.push(format!("Many exports: {}", export_count));
        }

        // Suspicious API analysis
        if !suspicious_apis.is_empty() {
            let api_score = (suspicious_apis.len() as f64 * 3.0).min(30.0);
            score += api_score;

            for api in suspicious_apis.iter().take(10) {
                indicators.push(format!("Suspicious API: {}", api));
            }

            if suspicious_apis.len() > 10 {
                indicators.push(format!(
                    "... and {} more suspicious APIs",
                    suspicious_apis.len() - 10
                ));
            }
        }

        score = score.min(100.0);

        (score, indicators, packer_info)
    }
}

impl Default for HeuristicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packed_malware_high_score() {
        let analyzer = HeuristicAnalyzer::new();
        let data = b"UPX0 packed malware";
        let suspicious = vec!["VirtualAlloc".to_string(), "CreateRemoteThread".to_string()];

        let (score, indicators, packer) = analyzer.analyze(7.9, 3, 0, &suspicious, data);

        assert!(score > 50.0);
        assert!(packer.detected);
        assert!(!indicators.is_empty());
    }

    #[test]
    fn test_clean_file_low_score() {
        let analyzer = HeuristicAnalyzer::new();
        let data = b"Normal executable data";

        let (score, _, packer) = analyzer.analyze(6.5, 50, 10, &[], data);

        assert!(score < 20.0);
        assert!(!packer.detected);
    }
}
