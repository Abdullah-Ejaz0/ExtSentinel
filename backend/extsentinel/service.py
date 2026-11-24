"""High-level operations used by the API and the CLI."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import Settings, settings as default_settings
from .engine import analyze_package
from .fetcher import download_crx, validate_extension_id
from .models import ExtensionReport
from .package import load_directory, unpack
from .storage import Store


class Auditor:
    def __init__(self, cfg: Settings = default_settings) -> None:
        self.cfg = cfg
        self.store = Store(cfg)

    def audit_webstore(self, ext_id: str, force: bool = False, mode: str = "dataflow") -> ExtensionReport:
        ext_id = validate_extension_id(ext_id)
        if not force:
            cached = self.store.fresh_report(ext_id, mode)
            if cached is not None:
                return cached
        data = download_crx(ext_id, self.cfg)
        return self._analyze_bytes(data, ext_id, "webstore", mode)

    def audit_upload(self, data: bytes, mode: str = "dataflow") -> ExtensionReport:
        ext_id = "local-" + hashlib.sha256(data).hexdigest()[:16]
        return self._analyze_bytes(data, ext_id, "upload", mode)

    def audit_directory(self, path: Path, mode: str = "dataflow", save: bool = False) -> ExtensionReport:
        pkg = load_directory(path, self.cfg)
        report = analyze_package(pkg, f"local-{pkg.sha256[:16]}", "local", self.cfg, mode)
        if save:
            self.store.save_report(report)
        return report

    def _analyze_bytes(self, data: bytes, ext_id: str, source: str, mode: str) -> ExtensionReport:
        pkg = unpack(data, self.cfg)
        report = analyze_package(pkg, ext_id, source, self.cfg, mode)
        self.store.save_package(ext_id, report.version, data)
        self.store.save_report(report)
        return report
