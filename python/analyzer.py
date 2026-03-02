import proteus
from pathlib import Path
from typing import List, Dict, Optional
from python.cuckoo_sandbox import CuckooSandbox
from python.archive_handler import analyze_any_file


class ProteusAnalyzer:
    def __init__(
        self,
        cuckoo_enabled: bool = False,
        cuckoo_url: str = "http://localhost:8090",
        cuckoo_api_token: Optional[str] = None,
    ):
        self.threshold = 25.0  # Lower threshold prioritizes catching all malware over false positives
        self.cuckoo_enabled = cuckoo_enabled
        self.cuckoo = None
        if cuckoo_enabled:
            self.cuckoo = CuckooSandbox(base_url=cuckoo_url, api_token=cuckoo_api_token)

    def analyze_single(self, file_path: str, use_sandbox: bool = False) -> Dict:
        """
        Analyze a single file with optional Cuckoo Sandbox integration.
        Supports PE, ELF, ZIP archives, and generic file analysis.

        Args:
            file_path: Path to file to analyze
            use_sandbox: If True and Cuckoo is enabled, perform dynamic analysis

        Returns:
            Analysis result dictionary with optional sandbox data
        """
        # Use enhanced analyzer that handles ZIP and unknown types
        result = analyze_any_file(file_path)

        analysis = {
            "path": result["path"],
            "type": result["file_type"],
            "entropy": result["entropy"],
            "score": result["threat_score"],
            "indicators": result["suspicious_indicators"],
            "verdict": (
                "MALICIOUS" if result["threat_score"] > self.threshold else "CLEAN"
            ),
            "packer": result["packer"],
            "sandbox": None,
        }

        # Add extracted files info if it's an archive
        if "extracted_files" in result:
            analysis["extracted_files"] = result["extracted_files"]

        # Perform sandbox analysis if enabled and requested
        if use_sandbox and self.cuckoo_enabled and self.cuckoo:
            try:
                sandbox_result = self.cuckoo.quick_scan(file_path)
                if sandbox_result:
                    analysis["sandbox"] = sandbox_result
                    # Adjust threat score based on sandbox findings
                    sandbox_score = sandbox_result.get("score", 0.0)
                    if sandbox_score > 5.0:
                        # Boost score if sandbox detected malicious behavior
                        analysis["score"] = min(
                            100.0, analysis["score"] + (sandbox_score * 0.3)
                        )
                        # Update verdict if sandbox score is high
                        if sandbox_score > 7.0:
                            analysis["verdict"] = "MALICIOUS"
            except Exception as e:
                print(f"[!] Sandbox analysis failed: {e}")
                analysis["sandbox"] = {"error": str(e)}

        return analysis

    def analyze_directory(self, dir_path: str) -> List[Dict]:
        files = [str(p) for p in Path(dir_path).rglob("*") if p.is_file()]
        results = proteus.batch_analyze(files)

        return [
            {
                "path": r.path,
                "type": r.file_type,
                "entropy": r.entropy,
                "score": r.threat_score,
                "indicators": r.suspicious_indicators,
                "verdict": "MALICIOUS" if r.threat_score > self.threshold else "CLEAN",
                "packer": {
                    "detected": r.packer.detected,
                    "name": r.packer.packer_name,
                    "confidence": r.packer.confidence,
                    "indicators": r.packer.indicators,
                },
                "imphash": r.imphash,
                "rich_header": r.rich_header,
            }
            for r in results
        ]
