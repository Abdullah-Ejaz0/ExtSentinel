"""Runtime settings, overridable through environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("EXTSENTINEL_DATA_DIR", _BACKEND_DIR / "data"))
    )
    # Chrome version reported to the Web Store update server. Some packages
    # are only served to sufficiently recent browsers.
    chrome_version: str = field(default_factory=lambda: os.environ.get("EXTSENTINEL_CHROME_VERSION", "140.0.0.0"))
    download_timeout: float = field(default_factory=lambda: _env_float("EXTSENTINEL_DOWNLOAD_TIMEOUT", 60.0))

    # Limits that protect the backend from hostile packages (zip bombs, huge files).
    max_download_bytes: int = field(default_factory=lambda: _env_int("EXTSENTINEL_MAX_DOWNLOAD_BYTES", 150 * 1024 * 1024))
    max_unpacked_bytes: int = field(default_factory=lambda: _env_int("EXTSENTINEL_MAX_UNPACKED_BYTES", 400 * 1024 * 1024))
    max_file_count: int = field(default_factory=lambda: _env_int("EXTSENTINEL_MAX_FILE_COUNT", 20_000))
    max_single_file_bytes: int = field(default_factory=lambda: _env_int("EXTSENTINEL_MAX_FILE_BYTES", 60 * 1024 * 1024))

    # JavaScript parser: "auto" (tree-sitter if it can be loaded, else esprima), "tree-sitter" or "esprima".
    parser: str = field(default_factory=lambda: os.environ.get("EXTSENTINEL_PARSER", "auto"))
    # JS files larger than this skip full parsing and use the regex scanner.
    max_ast_bytes: int = field(default_factory=lambda: _env_int("EXTSENTINEL_MAX_AST_BYTES", 30_000_000))
    max_esprima_bytes: int = field(default_factory=lambda: _env_int("EXTSENTINEL_MAX_ESPRIMA_BYTES", 6_000_000))

    report_cache_seconds: int = field(default_factory=lambda: _env_int("EXTSENTINEL_REPORT_CACHE_SECONDS", 6 * 3600))
    analysis_workers: int = field(default_factory=lambda: _env_int("EXTSENTINEL_WORKERS", 4))


settings = Settings()
