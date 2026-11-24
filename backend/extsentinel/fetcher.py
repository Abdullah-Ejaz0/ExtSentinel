"""Download extension packages from the Chrome Web Store update service."""

from __future__ import annotations

import re

import httpx

from .config import Settings, settings as default_settings

UPDATE_URL = "https://clients2.google.com/service/update2/crx"
EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")


class FetchError(Exception):
    """Network or server failure while downloading."""


class ExtensionNotFound(FetchError):
    """The Web Store has no package for this ID (removed, private, or never published)."""


class InvalidExtensionId(ValueError):
    pass


def validate_extension_id(ext_id: str) -> str:
    ext_id = ext_id.strip().lower()
    if not EXTENSION_ID_RE.fullmatch(ext_id):
        raise InvalidExtensionId(f"invalid Chrome extension ID: {ext_id!r} (expected 32 letters a-p)")
    return ext_id


def download_crx(ext_id: str, cfg: Settings = default_settings, client: httpx.Client | None = None) -> bytes:
    ext_id = validate_extension_id(ext_id)
    params = {
        "response": "redirect",
        "prodversion": cfg.chrome_version,
        "acceptformat": "crx2,crx3",
        "x": f"id={ext_id}&installsource=ondemand&uc",
    }
    headers = {"User-Agent": f"Mozilla/5.0 Chrome/{cfg.chrome_version} ExtSentinel/0.1"}
    own_client = client is None
    client = client or httpx.Client(timeout=cfg.download_timeout, follow_redirects=True)
    try:
        with client.stream("GET", UPDATE_URL, params=params, headers=headers) as resp:
            if resp.status_code in (204, 404):
                raise ExtensionNotFound(f"{ext_id} is not available on the Chrome Web Store")
            if resp.status_code != 200:
                raise FetchError(f"Web Store returned HTTP {resp.status_code} for {ext_id}")
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) > cfg.max_download_bytes:
                    raise FetchError(f"package for {ext_id} exceeds {cfg.max_download_bytes} bytes")
    except httpx.HTTPError as exc:
        raise FetchError(f"download failed for {ext_id}: {exc}") from exc
    finally:
        if own_client:
            client.close()
    if not buf:
        raise ExtensionNotFound(f"{ext_id} is not available on the Chrome Web Store")
    return bytes(buf)
