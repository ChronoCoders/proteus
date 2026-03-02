"""
Archive Handler for Proteus
Handles ZIP and other archive formats, especially password-protected malware samples.
"""

import os
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import Dict, Any
import proteus


class ArchiveHandler:
    """Handle archive files (ZIP, RAR, etc.) and extract for analysis."""

    # Common passwords for malware archives
    COMMON_PASSWORDS = [
        b"infected",  # MalwareBazaar default
        b"",  # Try no password (empty)
        b"malware",
        b"virus",
        b"password",
        b"infected123",
        b"mal",
        b"1234",
    ]

    @staticmethod
    def is_zip_file(file_path: str) -> bool:
        """Check if file is a ZIP archive."""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                # ZIP magic: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
                return magic[:2] == b"PK"
        except Exception:
            return False

    @staticmethod
    def extract_zip(zip_path: str, extract_dir: str) -> bool:
        """
        Extract ZIP file, trying common passwords if encrypted.

        Args:
            zip_path: Path to ZIP file
            extract_dir: Directory to extract to

        Returns:
            True if extraction succeeded, False otherwise
        """
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Try extraction with common passwords first
                extracted = False
                for pwd in ArchiveHandler.COMMON_PASSWORDS:
                    try:
                        zf.extractall(extract_dir, pwd=pwd if pwd else None)
                        if pwd:
                            print(f"[+] Extracted with password: {pwd.decode()}")
                        else:
                            print("[+] Extracted without password")
                        extracted = True
                        break
                    except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                        continue
                    except Exception:
                        continue

                if not extracted:
                    print("[!] Could not extract: password protected or corrupted")
                    return False

                return True
        except zipfile.BadZipFile:
            print(f"[!] Invalid ZIP file: {zip_path}")
            return False
        except Exception as e:
            print(f"[!] Extraction error: {e}")
            return False

    @staticmethod
    def analyze_archive(archive_path: str) -> Dict[str, Any]:
        """
        Analyze an archive file by extracting and analyzing contents.

        Args:
            archive_path: Path to archive file

        Returns:
            Analysis results dictionary
        """
        temp_dir = None
        try:
            # Create temporary directory for extraction
            temp_dir = tempfile.mkdtemp(prefix="proteus_extract_")

            # Extract archive
            if not ArchiveHandler.extract_zip(archive_path, temp_dir):
                # If extraction failed, analyze the archive itself generically
                return ArchiveHandler.analyze_generic(archive_path)

            # Find extracted files
            extracted_files = []
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Skip small files (< 1KB, likely just metadata)
                    if os.path.getsize(file_path) > 1024:
                        extracted_files.append(file_path)

            if not extracted_files:
                print("[!] No significant files found in archive")
                return ArchiveHandler.analyze_generic(archive_path)

            # Analyze extracted files
            print(f"[*] Found {len(extracted_files)} file(s) in archive")
            results = []

            for file_path in extracted_files:
                try:
                    # Try to analyze with Proteus
                    result = proteus.analyze_file(file_path)
                    results.append(
                        {
                            "file": Path(file_path).name,
                            "type": result.file_type,
                            "entropy": result.entropy,
                            "score": result.threat_score,
                            "indicators": result.suspicious_indicators,
                            "packer": {
                                "detected": result.packer.detected,
                                "name": result.packer.packer_name,
                                "confidence": result.packer.confidence,
                            },
                        }
                    )
                except ValueError:
                    # Not PE/ELF, try generic analysis
                    generic = ArchiveHandler.analyze_generic(file_path)
                    results.append(
                        {
                            "file": Path(file_path).name,
                            "type": "Generic",
                            "entropy": generic["entropy"],
                            "score": generic["threat_score"],
                            "indicators": generic["suspicious_indicators"],
                            "packer": {
                                "detected": False,
                                "name": "None",
                                "confidence": 0.0,
                            },
                        }
                    )
                except Exception as e:
                    print(f"[!] Error analyzing {file_path}: {e}")
                    continue

            if not results:
                return ArchiveHandler.analyze_generic(archive_path)

            # Aggregate results - use highest threat score
            max_score_file = max(results, key=lambda x: x["score"])

            return {
                "path": archive_path,
                "file_type": f"Archive ({len(results)} files)",
                "entropy": max_score_file["entropy"],
                "threat_score": max_score_file["score"],
                "suspicious_indicators": max_score_file["indicators"],
                "import_count": 0,
                "export_count": 0,
                "section_count": 0,
                "max_section_entropy": max_score_file["entropy"],
                "packer": max_score_file["packer"],
                "extracted_files": results,
                "imphash": None,
                "rich_header": None,
            }

        finally:
            # Cleanup
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass

    @staticmethod
    def analyze_generic(file_path: str) -> Dict[str, Any]:
        """
        Generic analysis for unsupported file types.
        Uses entropy and string analysis to detect suspicious content.

        Args:
            file_path: Path to file

        Returns:
            Analysis results dictionary
        """
        try:
            # Read file
            with open(file_path, "rb") as f:
                data = f.read()

            # Calculate entropy
            from collections import Counter
            import math

            if len(data) == 0:
                entropy = 0.0
            else:
                byte_counts = Counter(data)
                total_bytes = len(data)
                entropy = -sum(
                    (count / total_bytes) * math.log2(count / total_bytes)
                    for count in byte_counts.values()
                )

            # Extract strings for suspicious content
            try:
                strings_result = proteus.extract_strings_from_file(file_path)
                suspicious_count = len(strings_result.suspicious_strings)
                url_count = len(strings_result.urls)
                ip_count = len(strings_result.ips)
            except Exception:
                suspicious_count = 0
                url_count = 0
                ip_count = 0

            # Build indicators
            indicators = []

            # Unknown files start with baseline suspicion score
            # (any unknown file deserves scrutiny)
            score = 25.0

            # High entropy is suspicious
            if entropy > 7.5:
                indicators.append(f"Very high entropy: {entropy:.2f}")
                score += 35.0
            elif entropy > 7.2:
                indicators.append(f"High entropy: {entropy:.2f}")
                score += 25.0
            elif entropy > 6.8:
                indicators.append(f"Elevated entropy: {entropy:.2f}")
                score += 15.0
            elif entropy > 6.5:
                indicators.append(f"Above average entropy: {entropy:.2f}")
                score += 5.0

            # Suspicious strings - any amount is concerning
            if suspicious_count > 10:
                indicators.append(f"Many suspicious strings: {suspicious_count}")
                score += min(suspicious_count * 3, 40)
            elif suspicious_count > 5:
                indicators.append(f"Suspicious strings found: {suspicious_count}")
                score += min(suspicious_count * 2, 30)
            elif suspicious_count > 0:
                indicators.append(f"Suspicious strings found: {suspicious_count}")
                score += suspicious_count * 2

            # Network indicators - highly suspicious
            if url_count > 5:
                indicators.append(f"Many URLs found: {url_count}")
                score += min(url_count * 7, 35)
            elif url_count > 0:
                indicators.append(f"URLs found: {url_count}")
                score += min(url_count * 7, 25)

            if ip_count > 3:
                indicators.append(f"Many IP addresses: {ip_count}")
                score += min(ip_count * 7, 30)
            elif ip_count > 0:
                indicators.append(f"IP addresses found: {ip_count}")
                score += min(ip_count * 7, 20)

            # File size suspicion (very small or very large)
            file_size = len(data)
            if file_size < 1024:
                indicators.append("Suspiciously small file")
                score += 5
            elif file_size > 10 * 1024 * 1024:  # > 10MB
                indicators.append("Large file size")
                score += 5

            score = min(score, 100.0)

            return {
                "path": file_path,
                "file_type": "Generic/Unknown",
                "entropy": entropy,
                "threat_score": score,
                "suspicious_indicators": indicators,
                "import_count": 0,
                "export_count": 0,
                "section_count": 0,
                "max_section_entropy": entropy,
                "packer": {"detected": False, "name": "None", "confidence": 0.0},
                "imphash": None,
                "rich_header": None,
            }

        except Exception as e:
            print(f"[!] Generic analysis error: {e}")
            return {
                "path": file_path,
                "file_type": "Error",
                "entropy": 0.0,
                "threat_score": 0.0,
                "suspicious_indicators": [f"Analysis error: {str(e)}"],
                "import_count": 0,
                "export_count": 0,
                "section_count": 0,
                "max_section_entropy": 0.0,
                "packer": {"detected": False, "name": "None", "confidence": 0.0},
                "imphash": None,
                "rich_header": None,
            }


def analyze_any_file(file_path: str) -> Dict[str, Any]:
    """
    Analyze any file type - PE, ELF, Archive, or Generic.

    Args:
        file_path: Path to file to analyze

    Returns:
        Analysis results dictionary
    """
    # Check if it's a ZIP archive
    if ArchiveHandler.is_zip_file(file_path):
        print(f"[*] Detected ZIP archive: {file_path}")
        return ArchiveHandler.analyze_archive(file_path)

    # Try standard Proteus analysis (PE/ELF)
    try:
        result = proteus.analyze_file(file_path)

        # Enhance with string analysis to catch hidden threats
        try:
            strings_result = proteus.extract_strings_from_file(file_path)
            suspicious_count = len(strings_result.suspicious_strings)
            url_count = len(strings_result.urls)
            ip_count = len(strings_result.ips)

            # Boost score if strings reveal threats that PE analysis missed
            # Use lighter weights for PE files (they naturally have more strings)
            score_boost = 0
            indicators = list(result.suspicious_indicators)

            # If PE analysis scored very low but we find suspicious content,
            # add baseline boost (possible stealthy malware)
            if result.threat_score < 15 and (suspicious_count >= 20 or url_count >= 3):
                score_boost += 15
                indicators.append("Low-scoring PE with suspicious content")

            # Only boost if we have MANY suspicious strings (not just a few)
            if suspicious_count >= 50:
                score_boost += 25
                indicators.append(f"Excessive suspicious strings: {suspicious_count}")
            elif suspicious_count >= 30:
                score_boost += 15
                indicators.append(f"Many suspicious strings: {suspicious_count}")
            elif suspicious_count >= 20:
                score_boost += 10
                indicators.append(f"Suspicious strings found: {suspicious_count}")

            # URLs are common in legitimate software (help links, update servers)
            # But still somewhat suspicious, especially combined with other indicators
            if url_count > 20:
                score_boost += 15
                indicators.append(f"Excessive URLs: {url_count}")
            elif url_count >= 10:
                score_boost += 8
                indicators.append(f"Many URLs found: {url_count}")
            elif url_count >= 3:
                score_boost += 5
                indicators.append(f"URLs found: {url_count}")

            # IPs are more suspicious in PE files
            if ip_count > 5:
                score_boost += 15
                indicators.append(f"Many IP addresses: {ip_count}")
            elif ip_count > 2:
                score_boost += 8
                indicators.append(f"IP addresses found: {ip_count}")

            final_score = min(result.threat_score + score_boost, 100.0)
        except Exception:
            # String extraction failed, use original score
            final_score = result.threat_score
            indicators = result.suspicious_indicators

        return {
            "path": result.path,
            "file_type": result.file_type,
            "entropy": result.entropy,
            "threat_score": final_score,
            "suspicious_indicators": indicators,
            "import_count": result.import_count,
            "export_count": result.export_count,
            "section_count": result.section_count,
            "max_section_entropy": result.max_section_entropy,
            "packer": {
                "detected": result.packer.detected,
                "name": result.packer.packer_name,
                "confidence": result.packer.confidence,
                "indicators": result.packer.indicators,
            },
            "imphash": result.imphash,
            "rich_header": result.rich_header,
        }
    except ValueError:
        # Unsupported file type, use generic analysis
        print("[*] Unknown file type, using generic analysis")
        return ArchiveHandler.analyze_generic(file_path)
    except (RuntimeError, Exception) as e:
        # Corrupted file or parsing error, use generic analysis
        print(f"[!] Parse error ({type(e).__name__}), using generic analysis")
        return ArchiveHandler.analyze_generic(file_path)
