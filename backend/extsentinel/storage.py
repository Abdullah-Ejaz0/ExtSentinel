"""On-disk store for downloaded packages and their reports.

Layout:
    data/packages/<extension_id>/<version>.crx
    data/reports/<extension_id>/<version>.<mode>.json

Every audited version is kept so later versions can be compared against it.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from .config import Settings, settings as default_settings
from .models import ExtensionReport

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _safe(part: str) -> str:
    cleaned = _SAFE.sub("_", part)[:100]
    return cleaned if cleaned.strip(".") else "_"


class Store:
    def __init__(self, cfg: Settings = default_settings) -> None:
        self.root = Path(cfg.data_dir)
        self.cache_seconds = cfg.report_cache_seconds

    def _pkg_path(self, ext_id: str, version: str) -> Path:
        return self.root / "packages" / _safe(ext_id) / f"{_safe(version)}.crx"

    def _report_path(self, ext_id: str, version: str, mode: str) -> Path:
        return self.root / "reports" / _safe(ext_id) / f"{_safe(version)}.{_safe(mode)}.json"

    def save_package(self, ext_id: str, version: str, data: bytes) -> None:
        path = self._pkg_path(ext_id, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)

    def save_report(self, report: ExtensionReport) -> None:
        path = self._report_path(report.extension_id, report.version, report.mode)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(path)

    def load_report(self, ext_id: str, version: str, mode: str = "dataflow") -> ExtensionReport | None:
        path = self._report_path(ext_id, version, mode)
        if not path.is_file():
            return None
        return ExtensionReport.model_validate_json(path.read_text(encoding="utf-8"))

    def fresh_report(self, ext_id: str, mode: str = "dataflow") -> ExtensionReport | None:
        """Most recent report for this ID if it is younger than the cache window."""
        folder = self.root / "reports" / _safe(ext_id)
        if not folder.is_dir():
            return None
        candidates = sorted(folder.glob(f"*.{_safe(mode)}.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates or time.time() - candidates[0].stat().st_mtime > self.cache_seconds:
            return None
        return ExtensionReport.model_validate_json(candidates[0].read_text(encoding="utf-8"))

    def versions(self, ext_id: str) -> list[str]:
        folder = self.root / "packages" / _safe(ext_id)
        if not folder.is_dir():
            return []
        return sorted((p.stem for p in folder.glob("*.crx")), key=_version_key)


def _version_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.]", v))
