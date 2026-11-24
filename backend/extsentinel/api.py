"""FastAPI application.

Run:  uvicorn extsentinel.api:app --port 8000
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import __version__
from .config import settings
from .fetcher import ExtensionNotFound, FetchError, InvalidExtensionId, validate_extension_id
from .models import ExtensionReport
from .package import PackageError
from .service import Auditor

app = FastAPI(title="ExtSentinel analysis backend", version=__version__)
app.add_middleware(
    CORSMiddleware,
    # The Chrome extension calls the API from its own origin; local tools from localhost.
    allow_origin_regex=r"^(chrome-extension://[a-p]{32}|http://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

auditor = Auditor(settings)
_executor = ThreadPoolExecutor(max_workers=settings.analysis_workers, thread_name_prefix="analysis")
Mode = Literal["dataflow", "keyword"]
MAX_BATCH = 50


class AnalyzeRequest(BaseModel):
    extension_ids: list[str] = Field(min_length=1, max_length=MAX_BATCH)
    force: bool = False
    mode: Mode = "dataflow"


class AnalyzeResponse(BaseModel):
    reports: list[ExtensionReport]
    errors: dict[str, str]


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, InvalidExtensionId):
        return HTTPException(400, str(exc))
    if isinstance(exc, ExtensionNotFound):
        return HTTPException(404, str(exc))
    if isinstance(exc, FetchError):
        return HTTPException(502, str(exc))
    if isinstance(exc, (PackageError, ValueError)):
        return HTTPException(422, str(exc))
    return HTTPException(500, f"analysis failed: {type(exc).__name__}")


async def _run(fn, *args):
    return await asyncio.get_running_loop().run_in_executor(_executor, fn, *args)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    ids = list(dict.fromkeys(i.strip().lower() for i in req.extension_ids))
    results = await asyncio.gather(
        *(_run(auditor.audit_webstore, i, req.force, req.mode) for i in ids), return_exceptions=True
    )
    reports, errors = [], {}
    for ext_id, res in zip(ids, results):
        if isinstance(res, Exception):
            errors[ext_id] = _http_error(res).detail
        else:
            reports.append(res)
    return AnalyzeResponse(reports=reports, errors=errors)


@app.get("/api/extensions/{ext_id}/report", response_model=ExtensionReport)
async def report(ext_id: str, force: bool = False, mode: Mode = "dataflow") -> ExtensionReport:
    try:
        return await _run(auditor.audit_webstore, ext_id, force, mode)
    except Exception as exc:
        raise _http_error(exc) from exc


@app.get("/api/extensions/{ext_id}/versions")
async def versions(ext_id: str) -> dict:
    try:
        ext_id = validate_extension_id(ext_id)
    except InvalidExtensionId as exc:
        raise _http_error(exc) from exc
    return {"extension_id": ext_id, "versions": auditor.store.versions(ext_id)}


@app.get("/api/extensions/{ext_id}/versions/{version}", response_model=ExtensionReport)
async def version_report(ext_id: str, version: str, mode: Mode = "dataflow") -> ExtensionReport:
    try:
        ext_id = validate_extension_id(ext_id)
    except InvalidExtensionId as exc:
        raise _http_error(exc) from exc
    rep = auditor.store.load_report(ext_id, version, mode)
    if rep is None:
        raise HTTPException(404, "no stored report for that version")
    return rep


@app.post("/api/analyze/upload", response_model=ExtensionReport)
async def analyze_upload(file: UploadFile = File(...), mode: Mode = Query("dataflow")) -> ExtensionReport:
    """Analyse a .crx or .zip that is not on the Web Store (e.g. our own test extensions)."""
    limit = settings.max_download_bytes
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"file exceeds {limit} bytes")
    try:
        return await _run(auditor.audit_upload, data, mode)
    except Exception as exc:
        raise _http_error(exc) from exc
