import yara
from pathlib import Path
from typing import List, Dict, Optional, Any


class ProteusYaraEngine:
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, yara.Rules] = {}
        self.compiled_rules: Optional[yara.Rules] = None

    def load_rules(self) -> bool:
        if not self.rules_dir.exists():
            print(f"[!] Rules directory not found: {self.rules_dir}")
            return False

        rule_files = list(self.rules_dir.glob("*.yar"))

        if not rule_files:
            print(f"[!] No YARA rules found in {self.rules_dir}")
            return False

        print(f"[*] Loading YARA rules from {self.rules_dir}")

        rule_sources = {}
        for rule_file in rule_files:
            try:
                rule_sources[str(rule_file)] = str(rule_file)
                print(f"    [+] Loaded: {rule_file.name}")
            except (OSError, PermissionError) as e:
                print(f"    [!] Error loading {rule_file.name}: {e}")

        if not rule_sources:
            print("[!] No valid rules loaded")
            return False

        try:
            self.compiled_rules = yara.compile(filepaths=rule_sources)
            print(f"[+] Successfully compiled {len(rule_sources)} rule files")
            return True
        except yara.SyntaxError as e:
            print(f"[!] YARA syntax error: {e}")
            return False
        except yara.Error as e:
            print(f"[!] YARA error: {e}")
            return False

    def load_custom_rule(self, rule_path: str) -> bool:
        try:
            custom_rule = yara.compile(filepath=rule_path)
            self.rules[rule_path] = custom_rule
            print(f"[+] Loaded custom rule: {rule_path}")
            return True
        except yara.SyntaxError as e:
            print(f"[!] YARA syntax error in {rule_path}: {e}")
            return False
        except yara.Error as e:
            print(f"[!] Error loading custom rule {rule_path}: {e}")
            return False

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if self.compiled_rules is None:
            return {"error": "No rules loaded", "matches": []}

        try:
            matches = self.compiled_rules.match(file_path)

            results: Dict[str, Any] = {
                "file": file_path,
                "matches": [],
                "match_count": len(matches),
                "threat_detected": len(matches) > 0,
            }

            for match in matches:
                match_data: Dict[str, Any] = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [],
                }

                for string_match in match.strings:
                    instances_list = []
                    for instance in string_match.instances:
                        instances_list.append(
                            {
                                "offset": instance.offset,
                                "matched_data": instance.matched_data.decode(
                                    "utf-8", errors="ignore"
                                )[:100],
                            }
                        )

                    match_data["strings"].append(
                        {
                            "identifier": string_match.identifier,
                            "instances": instances_list,
                        }
                    )

                results["matches"].append(match_data)

            return results

        except yara.Error as e:
            return {"error": f"YARA error: {str(e)}", "file": file_path, "matches": []}
        except (OSError, PermissionError) as e:
            return {
                "error": f"File access error: {str(e)}",
                "file": file_path,
                "matches": [],
            }

    def scan_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        dir_path_obj = Path(dir_path)

        if not dir_path_obj.exists():
            print(f"[!] Directory not found: {dir_path_obj}")
            return results

        files = [f for f in dir_path_obj.rglob("*") if f.is_file()]
        print(f"[*] Scanning {len(files)} files...")

        for file in files:
            try:
                result = self.scan_file(str(file))
                if result.get("threat_detected"):
                    results.append(result)
            except (OSError, PermissionError) as e:
                print(f"[!] Error scanning {file}: {e}")

        return results

    def get_rule_info(self) -> Dict[str, Any]:
        if self.compiled_rules is None:
            return {"error": "No rules loaded"}

        rule_files = list(self.rules_dir.glob("*.yar"))
        info = {
            "rules_directory": str(self.rules_dir),
            "rule_files": len(rule_files),
            "files": [f.name for f in rule_files],
        }

        return info

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded YARA rules (alias for get_rule_info)."""
        return self.get_rule_info()

    def format_match_report(self, result: Dict[str, Any]) -> str:
        if "error" in result:
            return f"[!] Error: {result['error']}"

        report = []
        report.append(f"\n[*] YARA Scan Results: {Path(result['file']).name}")
        report.append(f"[+] Matches: {result['match_count']}")

        if result["match_count"] == 0:
            report.append("[+] No threats detected")
            return "\n".join(report)

        report.append("\n[!] Threats Detected:")

        for match in result["matches"]:
            report.append(f"\n  Rule: {match['rule']}")

            if match.get("meta"):
                meta = match["meta"]
                if "description" in meta:
                    report.append(f"    Description: {meta['description']}")
                if "severity" in meta:
                    report.append(f"    Severity: {meta['severity'].upper()}")
                if "family" in meta:
                    report.append(f"    Family: {meta['family']}")

            if match["strings"]:
                report.append(f"    Matched Strings ({len(match['strings'])}):")
                for string in match["strings"][:5]:
                    report.append(f"      {string['identifier']}")
                    if string["instances"]:
                        first_instance = string["instances"][0]
                        report.append(f"        Offset: 0x{first_instance['offset']:X}")

        return "\n".join(report)


def main():
    import sys

    print("===========================================")
    print("   PROTEUS YARA Engine Test")
    print("===========================================\n")

    engine = ProteusYaraEngine()

    if not engine.load_rules():
        print("[!] Failed to load rules")
        return

    info = engine.get_rule_info()
    print("\n[*] Rule Info:")
    print(f"    Files: {info['rule_files']}")
    print(f"    Names: {', '.join(info['files'])}")

    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        print(f"\n[*] Testing with: {test_file}")
        result = engine.scan_file(test_file)
        print(engine.format_match_report(result))


if __name__ == "__main__":
    main()
