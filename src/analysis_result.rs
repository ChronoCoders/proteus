use pyo3::prelude::*;

#[pyclass]
#[derive(Clone)]
pub struct PackerResult {
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
pub struct AnalysisResult {
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
    pub packer: PackerResult,
}

impl AnalysisResult {
    pub fn new(
        path: String,
        file_type: String,
        entropy: f64,
        threat_score: f64,
        suspicious_indicators: Vec<String>,
        import_count: usize,
        export_count: usize,
        section_count: usize,
        max_section_entropy: f64,
        packer: PackerResult,
    ) -> Self {
        AnalysisResult {
            path,
            file_type,
            entropy,
            threat_score,
            suspicious_indicators,
            import_count,
            export_count,
            section_count,
            max_section_entropy,
            packer,
        }
    }
}
