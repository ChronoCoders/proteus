import re
from pathlib import Path
from typing import Optional


class SecurityValidator:
    ALLOWED_EXTENSIONS = {
        ".exe",
        ".dll",
        ".malware",
        ".bin",
        ".elf",
        ".so",
        ".pdf",
        ".doc",
        ".docx",
        ".zip",
        ".rar",
        ".7z",
        ".apk",
        ".dex",
        ".jar",
        ".class",
        ".pyc",
        ".sh",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
    }
    MAX_FILE_SIZE_MB = 100
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
    DANGEROUS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

    @staticmethod
    def validate_file_path(path: str, check_size: bool = True) -> Optional[Path]:
        try:
            p = Path(path).resolve()

            if not p.exists():
                return None

            if not p.is_file():
                return None

            if p.suffix.lower() not in SecurityValidator.ALLOWED_EXTENSIONS:
                return None

            if check_size:
                max_size = SecurityValidator.MAX_FILE_SIZE_MB * 1024 * 1024
                if p.stat().st_size > max_size:
                    return None

            return p

        except (OSError, ValueError):
            return None

    @staticmethod
    def validate_sha256(hash_str: str) -> bool:
        if not hash_str:
            return False
        return bool(SecurityValidator.SHA256_PATTERN.match(hash_str))

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        return SecurityValidator.DANGEROUS_CHARS.sub("_", filename)

    @staticmethod
    def validate_directory_path(path: str) -> Optional[Path]:
        try:
            p = Path(path).resolve()

            if not p.exists():
                return None

            if not p.is_dir():
                return None

            return p

        except (OSError, ValueError):
            return None

    @staticmethod
    def is_safe_output_path(output_path: Path, base_dir: Path) -> bool:
        try:
            output_resolved = output_path.resolve()
            base_resolved = base_dir.resolve()

            return output_resolved.is_relative_to(base_resolved)

        except (ValueError, OSError):
            return False
