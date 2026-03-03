# PROTEUS

**Advanced zero-day static analysis engine built with Rust and Python**

[Features](#features) • [Quick Start](#quick-start) • [Dashboard](#web-dashboard) • [Documentation](https://github.com/ChronoCoders/proteus/wiki) • [Contributing](#contributing) • [License](#license)

---

**Advanced Zero-Day Static Analysis Engine**

Proteus is a high-performance malware analysis tool built with Rust and Python, designed to detect zero-day threats through static analysis, heuristics, and machine learning.

## Features

### Core Analysis
- **PE/ELF Binary Analysis** - Deep inspection of Windows and Linux executables
- **Entropy Calculation** - Detect packed/encrypted malware (section-level granularity)
- **Heuristic Scoring** - Intelligent threat assessment with configurable thresholds
- **String Extraction** - ASCII and wide string analysis with pattern detection
- **IOC Detection** - Automatic extraction of URLs, IPs, registry keys, file paths
- **High Performance** - Rust-powered core with parallel processing via Rayon
- **Batch Processing** - Scan entire directories efficiently

### Detection Engines
- **ML Detection** - Random Forest (96% accuracy) + Isolation Forest anomaly detection
- **YARA Engine** - 40+ industry-standard detection rules
  - **Ransomware**: WannaCry, Ryuk, Maze, Locky families
  - **RAT Detection**: NanoCore, njRAT, DarkComet, Quasar, AsyncRAT
  - **Banking Trojans**: Emotet, TrickBot, Dridex, Zeus, Formbook, AgentTesla
  - **Packer Detection**: UPX, ASPack, Themida, VMProtect, PECompact, MPRESS
  - **Suspicious Behaviors**: Code injection, credential dumping, keyloggers, browser theft
- **Multi-Layer Analysis** - Combine heuristic + ML + YARA for maximum accuracy

### Advanced Features
- **ML Ready** - Feature extraction pipeline for machine learning
- **Feature Engineering** - 16+ features including entropy, imports, exports, strings
- **Detection Metrics** - Built-in accuracy, precision, recall tracking
- **Extensible** - Modular architecture for custom analyzers

## Web Dashboard

Proteus v0.3.0 includes a modern web interface for easy analysis.

### Launching the Dashboard

1. **Start the API Server:**
   ```bash
   # Windows
   .\venv\Scripts\activate
   python -m uvicorn server:app --reload --port 8000
   
   # Linux/Mac
   source venv/bin/activate
   python -m uvicorn server:app --reload --port 8000
   ```

2. **Open Browser:**
   Navigate to `http://localhost:8000`

### Features
- **Drag & Drop Analysis**: Upload PE/ELF files instantly
- **Live Stats**: Monitor system health, rule counts, and detection rates
- **History**: Local storage tracking of past scans
- **Visual Reports**: Beautiful breakdown of entropy, threat scores, and indicators

## Detection Metrics (Real-World Dataset)

| Metric | Value |
|--------|-------|
| Test Accuracy | 96.22% |
| Precision (Malicious) | 95% |
| Recall (Malicious) | 97% |
| F1-Score | 0.96 |
| False Positive Rate | 0.97% |
| Training Dataset | 1,190 samples |
| Real Malware Samples | 576 |
| Clean Samples | 614 |

## Quick Start

### Prerequisites

- **Rust** 1.83+ ([Install](https://rustup.rs/))
- **Python** 3.10+ ([Install](https://www.python.org/downloads/))
- **Windows** 10/11 or **Linux**
- **YARA** 4.5+ (Optional, required for Rust build)
- **MalwareBazaar API** (Optional, for dataset collection - included in code)

### Installation

```bash
git clone https://github.com/ChronoCoders/proteus.git
cd proteus

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

maturin develop --release
```

### Basic Usage

**Analyze a single file:**
```bash
python cli.py file C:\path\to\sample.exe
```

**Analyze with ML prediction:**
```bash
python cli.py file C:\path\to\sample.exe --ml
```

**Analyze with YARA rules:**
```bash
python cli.py file C:\path\to\sample.exe --yara
```

**Complete analysis (Heuristic + ML + YARA):**
```bash
python cli.py file C:\path\to\sample.exe --ml --yara
```

**Full analysis with strings:**
```bash
python cli.py file C:\path\to\sample.exe --ml --yara --strings
```

**String-only analysis:**
```bash
python cli.py strings C:\path\to\sample.exe
```

**Batch scan directory:**
```bash
python cli.py dir C:\path\to\samples --output results.json
```

### Collecting Real Malware Dataset

**Collect malware samples from MalwareBazaar (default: 50 samples per tag, ~500 total):**
```bash
python malware_collector.py
```

**Collect with custom sample count:**
```bash
# Collect 100 samples per tag (~1000 total)
python malware_collector.py --samples=100

# Collect 20 samples per tag (~200 total)
python malware_collector.py --samples=20
```

**Enable verbose debugging mode:**
```bash
python malware_collector.py --verbose
```

**Combine options:**
```bash
python malware_collector.py --samples=100 --verbose
```

**Features:**
- Automatic AES-encrypted ZIP extraction
- Retry logic for failed downloads (2 attempts per sample)
- Real-time progress tracking
- Graceful interrupt handling (Ctrl+C saves progress)
- Metadata persistence (resume capability)
- 10 malware categories: ransomware, trojan, rat, stealer, backdoor, loader, miner, banker, spyware, worm

**Collection Statistics:**
- Default: ~500 samples in ~17 minutes
- Large: ~1000 samples in ~33 minutes
- Custom: configurable via `--samples=N`

### Building Test Dataset
```bash
python test_dataset_builder.py
```

### Training ML Models
```bash
python ml_trainer.py
```

## Documentation

### Example Output
```
╔═══════════════════════════════════════╗
║         PROTEUS v0.2.0                ║
║   Zero-Day Static Analysis Engine     ║
╚═══════════════════════════════════════╝

[*] Analysis: suspicious.exe
[+] Type: PE
[+] Entropy: 7.85
[+] Threat Score: 66.00/100
[+] Verdict: MALICIOUS
[!] Suspicious Indicators:
    - VirtualAlloc
    - CreateRemoteThread
    - WriteProcessMemory

[*] YARA Scan:
[!] YARA Matches: 3
    Rule: Suspicious_Code_Injection
      Severity: HIGH
      Family: suspicious
    Rule: Emotet_Trojan
      Severity: CRITICAL
      Family: trojan
    Rule: UPX_Packer
      Severity: MEDIUM
      Family: packer

[*] ML Analysis:
[+] ML Prediction: MALICIOUS
[+] Confidence: 100.00%
[+] Probabilities:
    Clean: 0.00%
    Malicious: 100.00%

[*] String Analysis:
[+] Total strings: 342
[+] Encoded strings: 15

[!] URLs (2):
    http://malicious-c2.com/payload
    https://evil.net/download

[!] Suspicious strings (8):
    cmd.exe /c powershell
    Disable-WindowsDefender
    keylogger.dll
```

### Architecture
```
proteus/
├── src/                      # Rust core engine
│   ├── lib.rs                # Module entry point
│   ├── pe_parser.rs          # PE file parsing (goblin)
│   ├── elf_parser.rs         # ELF file parsing
│   ├── entropy.rs            # Shannon entropy calculation
│   ├── heuristics.rs         # Threat scoring algorithms
│   ├── string_extractor.rs   # String analysis engine
│   └── python_bindings.rs    # PyO3 FFI bindings
├── python/                   # Python orchestration
│   ├── __init__.py
│   ├── analyzer.py           # Main analyzer class
│   ├── ml_detector.py        # ML model integration
│   ├── yara_engine.py        # YARA rule engine
│   ├── config.py             # Configuration management
│   ├── validators.py         # Security validators
│   └── rate_limiter.py       # API rate limiting
├── yara_rules/               # YARA detection rules
│   ├── ransomware.yar        # Ransomware signatures
│   ├── rats.yar              # RAT detection
│   ├── trojans.yar           # Banking trojans
│   ├── packers.yar           # Packer detection
│   └── suspicious_behavior.yar # Behavioral analysis
├── cli.py                    # Command-line interface
├── malware_collector.py      # MalwareBazaar dataset collector
├── ml_trainer.py             # ML training pipeline
├── test_dataset_builder.py   # Dataset generation
├── requirements.txt          # Python dependencies
├── Cargo.toml                # Rust dependencies
└── pyproject.toml            # Python project configuration
```

### Feature Extraction

Proteus extracts 16+ features per sample:

**Binary Features:**
- Global entropy
- Section count
- Max section entropy
- Import count
- Export count
- Suspicious API count

**String Features:**
- Total strings
- URL count
- IP count
- Registry key count
- Suspicious keyword count
- File path count
- Encoded string count
- Encoded ratio
- Suspicious ratio

### Threat Detection Patterns

**High Entropy Indicators:**
- Entropy > 7.8: Likely packed/encrypted
- Entropy > 7.5: Suspicious compression
- Entropy > 7.2: Elevated entropy

**Suspicious APIs (PE):**
```
VirtualAlloc, VirtualProtect, WriteProcessMemory,
CreateRemoteThread, LoadLibrary, GetProcAddress,
WinExec, ShellExecute, URLDownloadToFile,
CreateProcess, OpenProcess, ReadProcessMemory,
SetWindowsHookEx, GetAsyncKeyState, InternetOpen
```

**Suspicious Symbols (ELF):**
```
execve, system, fork, ptrace, mprotect,
mmap, dlopen, socket, bind
```

**Suspicious Keywords (Strings):**
```
cmd, powershell, eval, exec, system, shell,
download, upload, exploit, payload, inject,
keylog, screenshot, webcam, ransomware,
encrypt, bitcoin, miner, bypass, disable
```

## Development

### Build & Test
```bash
maturin develop

maturin develop --release

cargo test

python -m pytest

cargo clippy
mypy .
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- **Rust:** Follow `rustfmt` and `clippy` recommendations
- **Python:** Follow PEP 8, type hints required
- **No comments in code** (self-documenting code preferred)
- Use latest stable versions of dependencies

## Roadmap

### v0.2.0 (Current)
- [x] YARA rule engine (40+ detection rules)
- [x] Ransomware, RAT, Trojan, Packer detection
- [x] Suspicious behavior analysis
- [x] CLI --yara flag integration
- [x] Multi-layer detection (Heuristic + ML + YARA)

### v0.3.0 (Current)
- [x] **Web Dashboard** - Modern SPA with real-time stats and drag-drop analysis
- [x] **Sandbox Integration** - Dockerized dynamic analysis environment
- [x] **Real ML Models** - Random Forest trained on 1000+ real samples
- [x] **Deep Static Analysis** - Imphash, Rich Header, and Authenticode support
- [x] **API Server** - FastAPI backend for programmatic scanning

### v0.4.0 (Planned)
- [ ] Advanced packer detection enhancements
- [ ] Digital signature validation
- [ ] PE resource section analysis
- [ ] Retrain ML models with larger real-world dataset (1000+ samples)
- [ ] Custom YARA rule support via CLI

### v0.5.0 (Future)
- [ ] HTML report generation
- [ ] REST API server
- [ ] Web dashboard
- [ ] Real-time monitoring
- [ ] PCAP analysis integration
- [ ] Behavior monitoring (dynamic analysis)

## Performance

**Benchmarks (Intel i7, 16GB RAM):**
- Single file analysis: ~50ms
- Batch processing (100 files): ~3 seconds
- String extraction: ~20ms
- ML prediction: ~5ms
- YARA scanning: ~100ms

## Limitations

**Current Version (v0.2.0):**
- ML models require training on collected real-world samples
- No dynamic analysis capabilities
- Windows-focused (PE analysis more mature than ELF)
- Dataset collection requires MalwareBazaar API access

**Recommended Use:**
- Educational purposes
- Research projects
- Malware analysis training
- Static analysis component in larger systems
- Dataset collection for ML training

## Security & Legal

**Important Notes:**
- Always analyze malware in isolated environments (VMs/sandboxes)
- Do not use on production systems without proper testing
- Obey local laws regarding malware possession and analysis
- This tool is for educational and research purposes only

**Disclaimer:**
The authors are not responsible for misuse of this tool. Users are solely responsible for ensuring their usage complies with applicable laws and regulations.

## License

MIT License - see [LICENSE](LICENSE) file for details

Copyright (c) 2025 ChronoCoders

## Authors

**ChronoCoders Team**
- Advanced static analysis engine
- ML integration
- YARA rule engine
- Performance optimization

## Acknowledgments

- **goblin** - Excellent binary parsing library
- **PyO3** - Seamless Rust-Python integration
- **Rayon** - Parallel processing made easy
- **scikit-learn** - ML algorithms
- **pyzipper** - AES-encrypted ZIP extraction
- **MalwareBazaar** - Real-world malware sample repository
- **YARA** - Industry-standard malware detection framework

---

## Additional Resources

- [Documentation](https://github.com/ChronoCoders/proteus/wiki)
- [API Reference](https://github.com/ChronoCoders/proteus/wiki/API)
- [Examples](https://github.com/ChronoCoders/proteus/tree/main/examples)
- [Contributing Guide](CONTRIBUTING.md)

---

**If you find Proteus useful, please star the repository!**

**Found a bug?** [Open an issue](https://github.com/ChronoCoders/proteus/issues)

**Have a feature request?** [Start a discussion](https://github.com/ChronoCoders/proteus/discussions)
