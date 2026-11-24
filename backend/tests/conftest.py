from __future__ import annotations

import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from extsentinel.config import Settings
from extsentinel.engine import analyze_package
from extsentinel.js.parser import tree_sitter_available, tree_sitter_unavailable_reason
from extsentinel.package import load_directory


def write_extension(root: Path, files: dict[str, str | dict]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(content) if isinstance(content, dict) else content, encoding="utf-8")
    return root


def make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def make_crx3(zip_bytes: bytes, header: bytes = b"\x0a\x02\x08\x01") -> bytes:
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


BACKENDS = [
    pytest.param(
        "tree-sitter",
        marks=pytest.mark.skipif(not tree_sitter_available(), reason=f"tree-sitter unavailable: {tree_sitter_unavailable_reason()}"),
    ),
    "esprima",
]


@pytest.fixture(params=BACKENDS)
def backend(request) -> str:
    """Every analysis test runs once per parser backend."""
    return request.param


@pytest.fixture
def cfg(tmp_path, backend) -> Settings:
    return Settings(data_dir=tmp_path / "data", parser=backend)


@pytest.fixture
def analyze(tmp_path, cfg):
    def _run(files: dict, mode: str = "dataflow"):
        root = write_extension(tmp_path / "ext", files)
        return analyze_package(load_directory(root, cfg), "test", "local", cfg, mode)

    return _run


def rule_ids(report) -> set[str]:
    return {f.rule_id for f in report.findings}


def finding(report, rule_id: str):
    matches = [f for f in report.findings if f.rule_id == rule_id]
    assert matches, f"{rule_id} not in {sorted(rule_ids(report))}"
    return matches[0]
