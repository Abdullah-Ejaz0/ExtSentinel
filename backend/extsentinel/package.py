"""CRX/ZIP parsing and safe in-memory unpacking.

Packages are untrusted input. Nothing is written to disk during unpacking:
members are read into memory with per-file, total-size and file-count limits,
and paths that try to escape the package root are dropped.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings, settings as default_settings

CRX_MAGIC = b"Cr24"
ZIP_MAGIC = b"PK\x03\x04"


class PackageError(Exception):
    """The package is malformed, too large, or not an extension."""


def crx_to_zip(data: bytes) -> bytes:
    """Strip the CRX2/CRX3 header and return the embedded ZIP archive.

    CRX3: "Cr24" | uint32 version=3 | uint32 header_len | header (protobuf) | zip
    CRX2: "Cr24" | uint32 version=2 | uint32 key_len | uint32 sig_len | key | sig | zip
    Plain ZIP input is returned unchanged so uploads of zipped folders work.
    """
    if data[:4] == ZIP_MAGIC:
        return data
    if data[:4] != CRX_MAGIC:
        raise PackageError("not a CRX or ZIP file")
    if len(data) < 16:
        raise PackageError("truncated CRX header")
    version = struct.unpack_from("<I", data, 4)[0]
    if version == 3:
        header_len = struct.unpack_from("<I", data, 8)[0]
        start = 12 + header_len
    elif version == 2:
        key_len, sig_len = struct.unpack_from("<II", data, 8)
        start = 16 + key_len + sig_len
    else:
        raise PackageError(f"unsupported CRX version {version}")
    if start >= len(data) or data[start : start + 4] != ZIP_MAGIC:
        raise PackageError("CRX payload is not a ZIP archive")
    return data[start:]


def normalize_path(name: str) -> str | None:
    """Return a safe package-relative POSIX path, or None if it escapes the root."""
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    norm = posixpath.normpath(name)
    if norm in (".", "..") or norm.startswith("../"):
        return None
    return norm


@dataclass
class ExtensionPackage:
    files: dict[str, bytes]
    sha256: str
    warnings: list[str] = field(default_factory=list)
    _lower_index: dict[str, str] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self._lower_index = {p.lower(): p for p in self.files}

    def find(self, path: str) -> str | None:
        """Look up a path, tolerating case differences (Chrome on Windows/macOS does)."""
        norm = normalize_path(path)
        if norm is None:
            return None
        if norm in self.files:
            return norm
        return self._lower_index.get(norm.lower())

    def text(self, path: str) -> str | None:
        real = self.find(path)
        if real is None:
            return None
        return decode_text(self.files[real])

    def resolve_ref(self, base_file: str, ref: str) -> str | None:
        """Resolve a reference such as <script src> relative to the file that contains it."""
        ref = ref.split("#", 1)[0].split("?", 1)[0].strip()
        if not ref or "://" in ref or ref.startswith("//") or ref.startswith("data:"):
            return None
        if ref.startswith("/"):
            candidate = ref.lstrip("/")
        else:
            candidate = posixpath.join(posixpath.dirname(base_file), ref)
        return self.find(candidate)


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def _strip_single_root(files: dict[str, bytes]) -> dict[str, bytes]:
    """Zipped folders often wrap everything in one top-level directory."""
    if "manifest.json" in files:
        return files
    roots = {p.split("/", 1)[0] for p in files}
    if len(roots) == 1:
        root = next(iter(roots)) + "/"
        if root + "manifest.json" in files:
            return {p[len(root) :]: data for p, data in files.items() if p.startswith(root)}
    return files


def unpack(data: bytes, cfg: Settings = default_settings) -> ExtensionPackage:
    zip_bytes = crx_to_zip(data)
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise PackageError(f"corrupt ZIP archive: {exc}") from exc

    members = [info for info in archive.infolist() if not info.is_dir()]
    if len(members) > cfg.max_file_count:
        raise PackageError(f"package has {len(members)} files (limit {cfg.max_file_count})")

    files: dict[str, bytes] = {}
    warnings: list[str] = []
    total = 0
    for info in members:
        name = normalize_path(info.filename)
        if name is None:
            warnings.append(f"skipped unsafe path in archive: {info.filename!r}")
            continue
        if info.file_size > cfg.max_single_file_bytes:
            warnings.append(f"skipped oversized file: {name} ({info.file_size} bytes)")
            continue
        try:
            with archive.open(info) as fh:
                # Declared sizes can lie, so cap the actual read too.
                content = fh.read(cfg.max_single_file_bytes + 1)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError) as exc:
            warnings.append(f"could not read {name}: {exc}")
            continue
        if len(content) > cfg.max_single_file_bytes:
            warnings.append(f"skipped oversized file: {name}")
            continue
        total += len(content)
        if total > cfg.max_unpacked_bytes:
            raise PackageError("unpacked size exceeds limit (possible zip bomb)")
        files[name] = content

    files = _strip_single_root(files)
    if "manifest.json" not in files:
        raise PackageError("package has no manifest.json at its root")
    return ExtensionPackage(files=files, sha256=hashlib.sha256(data).hexdigest(), warnings=warnings)


def load_directory(path: Path, cfg: Settings = default_settings) -> ExtensionPackage:
    """Load an unpacked extension folder (used for local test extensions)."""
    path = path.resolve()
    if not (path / "manifest.json").is_file():
        raise PackageError(f"{path} has no manifest.json")
    files: dict[str, bytes] = {}
    digest = hashlib.sha256()
    total = 0
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = file.relative_to(path).as_posix()
        if rel.startswith(".git/") or "/node_modules/" in f"/{rel}":
            continue
        if len(files) >= cfg.max_file_count:
            raise PackageError("too many files")
        content = file.read_bytes()
        total += len(content)
        if total > cfg.max_unpacked_bytes:
            raise PackageError("folder exceeds size limit")
        files[rel] = content
        digest.update(rel.encode() + b"\0" + content)
    return ExtensionPackage(files=files, sha256=digest.hexdigest())
