import struct

import pytest

from extsentinel.config import Settings
from extsentinel.fetcher import InvalidExtensionId, validate_extension_id
from extsentinel.package import PackageError, crx_to_zip, normalize_path, unpack

from .conftest import make_crx3, make_zip

MANIFEST = '{"name": "x", "version": "1.0", "manifest_version": 3}'


def test_crx3_header_is_stripped():
    z = make_zip({"manifest.json": MANIFEST})
    assert crx_to_zip(make_crx3(z)) == z


def test_crx2_header_is_stripped():
    z = make_zip({"manifest.json": MANIFEST})
    crx2 = b"Cr24" + struct.pack("<III", 2, 3, 2) + b"KEY" + b"SG" + z
    assert crx_to_zip(crx2) == z


def test_rejects_non_package():
    with pytest.raises(PackageError):
        crx_to_zip(b"<html>not found</html>")


def test_unpack_strips_wrapper_folder_and_drops_traversal():
    data = make_zip({"myext/manifest.json": MANIFEST, "myext/a.js": "1", "../../evil.txt": "x"})
    pkg = unpack(data)
    assert set(pkg.files) == {"manifest.json", "a.js"}


def test_traversal_paths_rejected():
    assert normalize_path("../x") is None
    assert normalize_path("/etc/passwd") is None
    assert normalize_path("C:/Windows/x") is None
    assert normalize_path("a/./b/../c.js") == "a/c.js"


def test_zip_bomb_limit():
    cfg = Settings(max_unpacked_bytes=1000)
    data = make_zip({"manifest.json": MANIFEST, "big.js": "a" * 5000})
    with pytest.raises(PackageError, match="zip bomb"):
        unpack(data, cfg)


def test_missing_manifest():
    with pytest.raises(PackageError):
        unpack(make_zip({"a.js": "1"}))


def test_extension_id_validation():
    assert validate_extension_id("  CJPALHDLNBPAFIAMEJDNHCPHJBKEIAGM ") == "cjpalhdlnbpafiamejdnhcphjbkeiagm"
    with pytest.raises(InvalidExtensionId):
        validate_extension_id("../../etc/passwd")
