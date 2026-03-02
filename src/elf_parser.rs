use goblin::elf::Elf;
use std::fs;

pub struct ELFAnalysis {
    pub entropy: f64,
    pub suspicious_symbols: Vec<String>,
    #[allow(dead_code)]
    pub stripped: bool,
}

pub fn analyze_elf(path: &str) -> Result<ELFAnalysis, Box<dyn std::error::Error>> {
    let buffer = fs::read(path)?;
    let elf = Elf::parse(&buffer)?;

    let entropy = crate::entropy::calculate_entropy(&buffer);

    let suspicious_funcs = [
        "execve", "system", "fork", "ptrace", "mprotect", "mmap", "dlopen", "socket", "bind",
    ];

    let mut suspicious_symbols = Vec::new();
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if suspicious_funcs.iter().any(|&f| name.contains(f)) {
                suspicious_symbols.push(name.to_string());
            }
        }
    }

    let stripped = elf.syms.is_empty();

    Ok(ELFAnalysis {
        entropy,
        suspicious_symbols,
        stripped,
    })
}
