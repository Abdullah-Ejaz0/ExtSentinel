"""Command-line interface.

    python -m extsentinel <extension-id | path/to/folder | file.crx | file.zip> [--mode keyword] [--json]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .fetcher import EXTENSION_ID_RE
from .models import ExtensionReport
from .service import Auditor

_SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": "- ", "info": "  "}


def _print_report(r: ExtensionReport) -> None:
    print(f"{r.name} {r.version}  (MV{r.manifest_version}, {r.extension_id}, mode={r.mode})")
    cov = r.coverage
    print(f"coverage: {cov.parsed_files}/{cov.js_files} scripts parsed"
          + (f", obfuscated: {', '.join(cov.obfuscated_files)}" if cov.obfuscated_files else ""))
    print()
    for f in r.findings:
        print(f"{_SEV_MARK[f.severity.value]}[{f.severity.value:8}|{f.confidence.value:9}] {f.title}")
        for ev in f.evidence[:4]:
            loc = f"{ev.file}:{ev.line}" if ev.line else (ev.file or "")
            print(f"      {loc:38} {ev.note or ''}")
    for w in r.warnings:
        print(f"warning: {w}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="extsentinel", description="Static security analysis of a Chrome extension")
    ap.add_argument("target", help="Web Store extension ID, unpacked folder, .crx or .zip")
    ap.add_argument("--mode", choices=["dataflow", "keyword"], default="dataflow")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    ap.add_argument("--force", action="store_true", help="ignore cached reports")
    args = ap.parse_args(argv)

    auditor = Auditor()
    target = args.target
    path = Path(target)
    if path.is_dir():
        report = auditor.audit_directory(path, args.mode)
    elif path.is_file():
        report = auditor.audit_upload(path.read_bytes(), args.mode)
    elif EXTENSION_ID_RE.fullmatch(target.lower()):
        report = auditor.audit_webstore(target, args.force, args.mode)
    else:
        print(f"not an extension ID, folder or file: {target}", file=sys.stderr)
        return 2
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
