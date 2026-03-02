#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;
use rayon::prelude::*;

#[pyclass]
#[derive(Clone)]
pub struct PackerInfo {
    #[pyo3(get)]
    pub detected: bool,
    #[pyo3(get)]
    pub packer_name: String,
    #[pyo3(get)]
    pub confidence: f64,
    #[pyo3(get)]
    pub indicators: Vec<String>,
}

#[pyclass]
#[derive(Clone)]
pub struct RichHeaderEntry {
    #[pyo3(get)]
    pub comp_id: u32,
    #[pyo3(get)]
    pub count: u32,
    #[pyo3(get)]
    pub prod_id: u16,
    #[pyo3(get)]
    pub build_id: u16,
}

#[pyclass]
#[derive(Clone)]
pub struct RichHeaderInfo {
    #[pyo3(get)]
    pub key: u32,
    #[pyo3(get)]
    pub entries: Vec<RichHeaderEntry>,
}

#[pyclass]
pub struct FileAnalysis {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub file_type: String,
    #[pyo3(get)]
    pub entropy: f64,
    #[pyo3(get)]
    pub threat_score: f64,
    #[pyo3(get)]
    pub suspicious_indicators: Vec<String>,
    #[pyo3(get)]
    pub import_count: usize,
    #[pyo3(get)]
    pub export_count: usize,
    #[pyo3(get)]
    pub section_count: usize,
    #[pyo3(get)]
    pub max_section_entropy: f64,
    #[pyo3(get)]
    pub packer: PackerInfo,
    #[pyo3(get)]
    pub imphash: String,
    #[pyo3(get)]
    pub rich_header: Option<RichHeaderInfo>,
}

#[pyclass]
pub struct StringAnalysisResult {
    #[pyo3(get)]
    pub urls: Vec<String>,
    #[pyo3(get)]
    pub ips: Vec<String>,
    #[pyo3(get)]
    pub registry_keys: Vec<String>,
    #[pyo3(get)]
    pub suspicious_strings: Vec<String>,
    #[pyo3(get)]
    pub file_paths: Vec<String>,
    #[pyo3(get)]
    pub encoded_strings: usize,
    #[pyo3(get)]
    pub total_strings: usize,
}

#[pyfunction]
pub fn analyze_file(path: String) -> PyResult<FileAnalysis> {
    use std::fs;

    let file_type = detect_file_type(&path);

    let data = fs::read(&path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let (
        entropy,
        threat_score,
        indicators,
        import_count,
        export_count,
        section_count,
        max_section_entropy,
        packer_info,
        imphash,
        rich_header,
    ) = match file_type.as_str() {
        "PE" => {
            let analysis = crate::pe_parser::analyze_pe(&path)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

            let analyzer = crate::heuristics::HeuristicAnalyzer::new();
            let (score, mut heuristic_indicators, packer_result) = analyzer.analyze(
                analysis.entropy,
                analysis.import_count,
                analysis.export_count,
                &analysis.suspicious_imports,
                &data,
            );

            heuristic_indicators.extend(analysis.suspicious_imports.clone());

            let max_entropy = analysis
                .section_entropies
                .iter()
                .cloned()
                .fold(0.0f64, f64::max);

            (
                analysis.entropy,
                score,
                heuristic_indicators,
                analysis.import_count,
                analysis.export_count,
                analysis.num_sections,
                max_entropy,
                PackerInfo {
                    detected: packer_result.detected,
                    packer_name: packer_result.packer_name,
                    confidence: packer_result.confidence,
                    indicators: packer_result.indicators,
                },
                analysis.imphash,
                analysis.rich_header.map(|rh| RichHeaderInfo {
                    key: rh.key,
                    entries: rh
                        .entries
                        .into_iter()
                        .map(|e| RichHeaderEntry {
                            comp_id: e.comp_id,
                            count: e.count,
                            prod_id: e.prod_id,
                            build_id: e.build_id,
                        })
                        .collect(),
                }),
            )
        }
        "ELF" => {
            let analysis = crate::elf_parser::analyze_elf(&path)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

            let analyzer = crate::heuristics::HeuristicAnalyzer::new();
            let (score, mut heuristic_indicators, packer_result) =
                analyzer.analyze(analysis.entropy, 0, 0, &analysis.suspicious_symbols, &data);

            heuristic_indicators.extend(analysis.suspicious_symbols.clone());

            (
                analysis.entropy,
                score,
                heuristic_indicators,
                0,
                0,
                0,
                0.0,
                PackerInfo {
                    detected: packer_result.detected,
                    packer_name: packer_result.packer_name,
                    confidence: packer_result.confidence,
                    indicators: packer_result.indicators,
                },
                String::new(),
                None,
            )
        }
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Unsupported file type",
            ))
        }
    };

    Ok(FileAnalysis {
        path,
        file_type,
        entropy,
        threat_score,
        suspicious_indicators: indicators,
        import_count,
        export_count,
        section_count,
        max_section_entropy,
        packer: packer_info,
        imphash,
        rich_header,
    })
}

#[pyfunction]
pub fn batch_analyze(paths: Vec<String>) -> PyResult<Vec<FileAnalysis>> {
    let results: Vec<_> = paths
        .par_iter()
        .filter_map(|path| analyze_file(path.clone()).ok())
        .collect();

    Ok(results)
}

#[pyfunction]
pub fn extract_strings_from_file(path: String) -> PyResult<StringAnalysisResult> {
    use std::fs;

    let data = fs::read(&path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let analysis = crate::string_extractor::analyze_strings(&data);

    Ok(StringAnalysisResult {
        urls: analysis.urls,
        ips: analysis.ips,
        registry_keys: analysis.registry_keys,
        suspicious_strings: analysis.suspicious_strings,
        file_paths: analysis.file_paths,
        encoded_strings: analysis.encoded_strings,
        total_strings: analysis.total_strings,
    })
}

fn detect_file_type(path: &str) -> String {
    use std::fs::File;
    use std::io::Read;

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return "Unknown".to_string(),
    };

    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return "Unknown".to_string();
    }

    if magic[0] == 0x4D && magic[1] == 0x5A {
        "PE".to_string()
    } else if magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46 {
        "ELF".to_string()
    } else {
        "Unknown".to_string()
    }
}
