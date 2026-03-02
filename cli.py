#!/usr/bin/env python3

import sys
import json
from pathlib import Path
from typing import Optional


def check_proteus_module():
    try:
        import proteus
        from python.analyzer import ProteusAnalyzer

        return True
    except ImportError as e:
        print(f"[!] Error: {e}")
        print("\n[*] Solution:")
        print("    1. Activate venv: venv\\Scripts\\activate")
        print("    2. Build module: maturin develop --release")
        return False


def print_banner():
    banner = """
===========================================
         PROTEUS v0.3.0
   Zero-Day Static Analysis Engine
===========================================
"""
    print(banner)


def analyze_file_cmd(
    file_path: str,
    show_strings: bool = False,
    use_ml: bool = False,
    use_yara: bool = False,
    use_sandbox: bool = False,
):
    if not Path(file_path).exists():
        print(f"[!] Error: File not found - {file_path}")
        return

    try:
        import proteus
        from python.analyzer import ProteusAnalyzer
        from python.config import ConfigManager
        import os

        # Load configuration for Cuckoo Sandbox
        config = ConfigManager.create_proteus_config()
        cuckoo_enabled = os.getenv("CUCKOO_ENABLED", "false").lower() == "true"
        cuckoo_url = os.getenv("CUCKOO_URL", config.cuckoo_url)
        cuckoo_token = os.getenv("CUCKOO_API_TOKEN", config.cuckoo_api_token)

        analyzer = ProteusAnalyzer(
            cuckoo_enabled=cuckoo_enabled,
            cuckoo_url=cuckoo_url,
            cuckoo_api_token=cuckoo_token,
        )
        result = analyzer.analyze_single(file_path, use_sandbox=use_sandbox)

        print(f"\n[*] Analysis: {file_path}")
        print(f"[+] Type: {result['type']}")
        print(f"[+] Entropy: {result['entropy']:.2f}")
        print(f"[+] Threat Score: {result['score']:.2f}/100")
        print(f"[+] Verdict: {result['verdict']}")

        # New: Imphash and Rich Header
        if "imphash" in result and result["imphash"]:
             print(f"[+] Imphash: {result['imphash']}")

        if "rich_header" in result and result["rich_header"]:
             rh = result["rich_header"]
             print(f"[+] Rich Header: Key={rh.key:08X}, Entries={len(rh.entries)}")

        if result["indicators"]:
            print("[!] Suspicious Indicators:")
            for indicator in result["indicators"]:
                print(f"    - {indicator}")

        # Display sandbox results if available
        if use_sandbox and result.get("sandbox"):
            sandbox = result["sandbox"]
            if "error" in sandbox:
                print(f"\n[!] Sandbox Error: {sandbox['error']}")
            else:
                print("\n[*] Sandbox Analysis:")
                print(f"[+] Sandbox Score: {sandbox.get('score', 0.0):.1f}/10")

                if sandbox.get("signatures"):
                    print(
                        f"\n[!] Behavioral Signatures ({len(sandbox['signatures'])}):"
                    )
                    for sig in sandbox["signatures"][:10]:
                        severity = sig.get("severity", "unknown").upper()
                        print(f"    [{severity}] {sig.get('name', 'Unknown')}")

                if sandbox.get("processes"):
                    print(f"\n[*] Processes Created ({len(sandbox['processes'])}):")
                    for proc in sandbox["processes"][:5]:
                        print(f"    - {proc.get('name')} (PID: {proc.get('pid')})")

                network = sandbox.get("network", {})
                if network.get("dns") or network.get("http"):
                    print("\n[!] Network Activity:")
                    if network.get("dns"):
                        print(f"    DNS Queries: {len(network['dns'])}")
                        for dns in network["dns"][:3]:
                            print(f"      - {dns.get('domain')} -> {dns.get('ip')}")
                    if network.get("http"):
                        print(f"    HTTP Requests: {len(network['http'])}")
                        for http in network["http"][:3]:
                            print(
                                f"      - {http.get('method')} {http.get('host')}{http.get('uri')}"
                            )

                files = sandbox.get("files", {})
                if files.get("created"):
                    print(f"\n[*] Files Created: {len(files['created'])}")
                    for f in files["created"][:5]:
                        print(f"    - {f}")
        elif use_sandbox:
            print("\n[!] Sandbox analysis requested but Cuckoo is not enabled")
            print("    Set CUCKOO_ENABLED=true to enable")

        if use_yara:
            try:
                from python.yara_engine import ProteusYaraEngine

                print("\n[*] YARA Scan:")
                yara_engine = ProteusYaraEngine()
                if yara_engine.load_rules():
                    yara_result = yara_engine.scan_file(file_path)

                    if yara_result.get("error"):
                        print(f"[!] YARA Error: {yara_result['error']}")
                    elif yara_result["match_count"] == 0:
                        print("[+] No YARA rules matched")
                    else:
                        print(f"[!] YARA Matches: {yara_result['match_count']}")
                        for match in yara_result["matches"]:
                            print(f"    Rule: {match['rule']}")
                            if match.get("meta"):
                                meta = match["meta"]
                                if "severity" in meta:
                                    print(f"      Severity: {meta['severity'].upper()}")
                                if "family" in meta:
                                    print(f"      Family: {meta['family']}")
                else:
                    print("[!] Failed to load YARA rules")

            except Exception as e:
                print(f"[!] YARA scan failed: {e}")

        if use_ml:
            try:
                from python.ml_detector import ProteusMLDetector

                print("\n[*] ML Analysis:")
                detector = ProteusMLDetector()
                detector.load_model()

                ml_result = detector.predict(file_path)

                if "error" in ml_result:
                    print(f"[!] ML Error: {ml_result['error']}")
                else:
                    print(f"[+] ML Prediction: {ml_result['prediction'].upper()}")
                    print(f"[+] Confidence: {ml_result['confidence'] * 100:.2f}%")
                    print("[+] Probabilities:")
                    print(
                        f"    Clean: {ml_result['probabilities']['clean'] * 100:.2f}%"
                    )
                    print(
                        f"    Malicious: {ml_result['probabilities']['malicious'] * 100:.2f}%"
                    )
                    if ml_result["is_anomaly"]:
                        print(
                            f"[!] Anomaly detected (score: {ml_result['anomaly_score']:.2f})"
                        )

            except Exception as e:
                print(f"[!] ML Analysis failed: {e}")

        if show_strings:
            print("\n[*] String Analysis:")
            string_result = proteus.extract_strings_from_file(file_path)

            print(f"[+] Total strings: {string_result.total_strings}")
            print(f"[+] Encoded strings: {string_result.encoded_strings}")

            if string_result.urls:
                print(f"\n[!] URLs ({len(string_result.urls)}):")
                for url in string_result.urls[:5]:
                    print(f"    {url}")

            if string_result.ips:
                print(f"\n[!] IPs ({len(string_result.ips)}):")
                for ip in string_result.ips[:5]:
                    print(f"    {ip}")

            if string_result.suspicious_strings:
                print(
                    f"\n[!] Suspicious strings ({len(string_result.suspicious_strings)}):"
                )
                for s in string_result.suspicious_strings[:10]:
                    print(f"    {s}")

    except Exception as e:
        print(f"[!] Error: {e}")


def analyze_directory_cmd(dir_path: str, output: Optional[str] = None):
    if not Path(dir_path).exists():
        print(f"[!] Error: Directory not found - {dir_path}")
        return

    try:
        from python.analyzer import ProteusAnalyzer

        analyzer = ProteusAnalyzer()
        results = analyzer.analyze_directory(dir_path)

        malicious = [r for r in results if r["verdict"] == "MALICIOUS"]
        clean = [r for r in results if r["verdict"] == "CLEAN"]

        print(f"\n[*] Scanned: {len(results)} files")
        print(f"[+] Clean: {len(clean)}")
        print(f"[!] Malicious: {len(malicious)}")

        if malicious:
            print("\n[!] Malicious Files:")
            for r in malicious:
                print(f"    {Path(r['path']).name} (Score: {r['score']:.2f})")

        if output:
            with open(output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n[*] Results saved: {output}")

    except Exception as e:
        print(f"[!] Error: {e}")


def strings_cmd(file_path: str):
    if not Path(file_path).exists():
        print(f"[!] Error: File not found - {file_path}")
        return

    try:
        import proteus

        result = proteus.extract_strings_from_file(file_path)

        print(f"\n[*] String Analysis: {file_path}")
        print(f"[+] Total strings: {result.total_strings}")
        print(f"[+] Encoded strings: {result.encoded_strings}")

        if result.urls:
            print(f"\n[!] URLs found ({len(result.urls)}):")
            for url in result.urls[:10]:
                print(f"    {url}")

        if result.ips:
            print(f"\n[!] IP addresses ({len(result.ips)}):")
            for ip in result.ips[:10]:
                print(f"    {ip}")

        if result.registry_keys:
            print(f"\n[!] Registry keys ({len(result.registry_keys)}):")
            for key in result.registry_keys[:10]:
                print(f"    {key}")

        if result.suspicious_strings:
            print(f"\n[!] Suspicious strings ({len(result.suspicious_strings)}):")
            for s in result.suspicious_strings[:20]:
                print(f"    {s}")

        if result.file_paths:
            print(f"\n[*] File paths ({len(result.file_paths)}):")
            for path in result.file_paths[:10]:
                print(f"    {path}")

    except Exception as e:
        print(f"[!] Error: {e}")


def main():
    print_banner()

    if not check_proteus_module():
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python cli.py file <path> [--strings] [--ml] [--yara] [--sandbox]")
        print("  python cli.py dir <path> [--output results.json]")
        print("  python cli.py strings <path>")
        print("\nOptions:")
        print("  --strings  : Show detailed string analysis")
        print("  --ml       : Use machine learning detection")
        print("  --yara     : Run YARA rule matching")
        print("  --sandbox  : Perform dynamic analysis with Cuckoo Sandbox")
        sys.exit(1)

    command = sys.argv[1]

    if command == "file":
        if len(sys.argv) < 3:
            print("[!] Error: File path required")
            sys.exit(1)
        show_strings = "--strings" in sys.argv
        use_ml = "--ml" in sys.argv
        use_yara = "--yara" in sys.argv
        use_sandbox = "--sandbox" in sys.argv
        analyze_file_cmd(sys.argv[2], show_strings, use_ml, use_yara, use_sandbox)

    elif command == "dir":
        if len(sys.argv) < 3:
            print("[!] Error: Directory path required")
            sys.exit(1)
        output = (
            sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--output" else None
        )
        analyze_directory_cmd(sys.argv[2], output)

    elif command == "strings":
        if len(sys.argv) < 3:
            print("[!] Error: File path required")
            sys.exit(1)
        strings_cmd(sys.argv[2])

    else:
        print(f"[!] Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
