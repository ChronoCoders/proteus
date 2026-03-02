use pyo3::prelude::*;

mod elf_parser;
mod entropy;
mod heuristics;
mod packer_detector;
mod pe_parser;
mod python_bindings;
mod string_extractor;

#[pymodule]
fn proteus(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<python_bindings::FileAnalysis>()?;
    m.add_class::<python_bindings::StringAnalysisResult>()?;
    m.add_function(wrap_pyfunction!(python_bindings::analyze_file, m)?)?;
    m.add_function(wrap_pyfunction!(python_bindings::batch_analyze, m)?)?;
    m.add_function(wrap_pyfunction!(
        python_bindings::extract_strings_from_file,
        m
    )?)?;
    Ok(())
}
