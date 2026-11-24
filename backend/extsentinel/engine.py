"""Analysis orchestration: package -> ExtensionReport."""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from . import __version__
from .behaviors import (
    Context,
    capability_findings,
    code_exec_findings,
    flow_findings,
    keyword_findings,
    message_relay_findings,
    page_leak_findings,
    unused_permission_findings,
)
from .config import Settings, settings as default_settings
from .findings import FindingCollector
from .js.libraries import detect_library
from .js.parser import parse, resolve_backend, tree_sitter_unavailable_reason
from .js.scanner import scan
from .js.taint import EMPTY, FileAnalysis, FileAnalyzer, Step, Val, extend_trace, union
from .manifest import ManifestInfo, analyze_manifest, page_scripts, parse_manifest
from .models import (
    AnalysisCoverage,
    Category,
    Confidence,
    Evidence,
    ExtensionReport,
    FileReport,
    ScriptContext,
    Severity,
)
from .obfuscation import ObfuscationResult, analyze_text
from .package import ExtensionPackage

CS, BG, PAGE, WAR, UNK = (
    ScriptContext.CONTENT_SCRIPT,
    ScriptContext.BACKGROUND,
    ScriptContext.EXTENSION_PAGE,
    ScriptContext.WEB_ACCESSIBLE,
    ScriptContext.UNKNOWN,
)
_JS_EXT = (".js", ".mjs", ".cjs")
MODES = ("dataflow", "keyword")


@dataclass
class _Script:
    name: str  # package path, or "page.html#inline1" for inline scripts
    text: str  # source (inline scripts are padded with newlines so line numbers match the HTML file)
    display_file: str  # file the user should open
    size: int


class _Analysis:
    """State for one package analysis run."""

    def __init__(self, pkg: ExtensionPackage, cfg: Settings, mode: str) -> None:
        self.pkg = pkg
        self.cfg = cfg
        self.warnings: list[str] = list(pkg.warnings)
        self.mode = mode
        self.info: ManifestInfo = parse_manifest(pkg)
        self.out = FindingCollector()
        self.scripts: dict[str, _Script] = {}
        self.contexts: dict[str, set[ScriptContext]] = {}
        self.page_remote_scripts: list[tuple[str, str, int, set[ScriptContext]]] = []
        self.asts: dict[str, object] = {}
        self.parse_errors: dict[str, str] = {}
        self.syntax_error_files: list[str] = []
        self.backend = resolve_backend(cfg.parser)
        if self.backend == "esprima" and cfg.parser == "auto":
            self.warnings.append(
                "tree-sitter could not be loaded; used the esprima fallback parser "
                f"({tree_sitter_unavailable_reason()})"
            )
        self.analyses: dict[str, FileAnalysis] = {}
        self.obf: dict[str, ObfuscationResult] = {}
        self.libraries: dict[str, str] = {}

    # -- discovery --

    def collect_scripts(self) -> None:
        for path, data in self.pkg.files.items():
            if path.lower().endswith(_JS_EXT):
                text = self.pkg.text(path) or ""
                self.scripts[path] = _Script(path, text, path, len(data))

    def assign_contexts(self) -> None:
        info = self.info

        def tag(path: str | None, ctx: ScriptContext) -> None:
            if path and path in self.scripts:
                self.contexts.setdefault(path, set()).add(ctx)

        for cs in info.content_scripts:
            for js in cs.js:
                tag(self.pkg.find(js), CS)
        for js in info.background_scripts:
            tag(self.pkg.find(js), BG)
        for page in info.background_pages:
            self._html_scripts(page, BG)
        for page in info.extension_pages:
            self._html_scripts(page, PAGE)
        # Other HTML files in the package (e.g. pages opened with chrome.tabs.create).
        for path in self.pkg.files:
            if path.lower().endswith((".html", ".htm")) and path not in info.background_pages:
                self._html_scripts(path, PAGE)
        patterns = [p.lstrip("/") for p in info.web_accessible]
        for path in self.scripts:
            if any(fnmatch.fnmatch(path, p) for p in patterns):
                tag(path, WAR)

    def _html_scripts(self, page: str, ctx: ScriptContext) -> None:
        real = self.pkg.find(page)
        if real is None:
            return
        html = self.pkg.text(real) or ""
        parsed = page_scripts(html)
        for src, line in parsed.srcs:
            target = self.pkg.resolve_ref(real, src)
            if target and target in self.scripts:
                self.contexts.setdefault(target, set()).add(ctx)
            elif src.strip().lower().startswith(("http:", "https:", "//")):
                self.page_remote_scripts.append((real, src, line, {ctx}))
        for i, (code, line) in enumerate(parsed.inline, 1):
            name = f"{real}#inline{i}"
            if name not in self.scripts:
                self.scripts[name] = _Script(name, "\n" * (line - 1) + code, real, len(code))
            self.contexts.setdefault(name, set()).add(ctx)

    def propagate_references(self) -> None:
        """Runtime references discovered in code: executeScript files are content scripts;
        importScripts / ES imports share the importer's context."""
        for _ in range(5):
            changed = False
            for name, fa in self.analyses.items():
                base = self.scripts[name].display_file
                for ref in fa.injected_files:
                    target = self._resolve_code_ref(base, ref, from_root=True)
                    if target and CS not in self.contexts.setdefault(target, set()):
                        self.contexts[target].add(CS)
                        changed = True
                own = self.contexts.get(name, set())
                for ref in fa.imported_files:
                    target = self._resolve_code_ref(base, ref, from_root=False)
                    if target and not own <= self.contexts.setdefault(target, set()):
                        self.contexts[target] |= own
                        changed = True
            if not changed:
                break
        for name in self.scripts:
            if not self.contexts.get(name):
                self.contexts[name] = {UNK}

    def _resolve_code_ref(self, base: str, ref: str, from_root: bool) -> str | None:
        if "://" in ref or ref.startswith("//"):
            return None
        if from_root or ref.startswith("/"):
            found = self.pkg.find(ref.lstrip("/"))
            if found:
                return found
        return self.pkg.resolve_ref(base, ref)

    # -- per-file analysis --

    def parse_and_scan(self) -> None:
        for name, script in self.scripts.items():
            self.obf[name] = analyze_text(script.text)
            lib = detect_library(name, script.text)
            if lib:
                self.libraries[name] = lib
            if self.mode == "keyword":
                self.analyses[name] = scan(name, script.text)
                continue
            limit = self.cfg.max_ast_bytes if self.backend == "tree-sitter" else self.cfg.max_esprima_bytes
            if len(script.text) > limit:
                self.parse_errors[name] = f"file larger than {limit} bytes; regex scan only"
                continue
            result = parse(script.text, self.backend)
            if result.error:
                self.parse_errors[name] = result.error
            if result.ast is not None:
                self.asts[name] = result.ast
                if result.syntax_errors:
                    self.syntax_error_files.append(name)

    def run_taint(self, names, incoming: Val | None = None) -> None:
        for name in names:
            script = self.scripts[name]
            ast = self.asts.get(name)
            if ast is None:
                self.analyses[name] = scan(name, script.text, self.parse_errors.get(name))
                continue
            rounds = 5 if script.size < 300_000 else 2
            self.analyses[name] = FileAnalyzer(name, ast, incoming, max_rounds=rounds).run()
            if self.analyses[name].partial:
                self.warnings.append(f"{name}: analysis budget exhausted; results for this file are partial")

    def incoming_messages(self) -> Val:
        """Data content scripts send to the background, with the hop added to each trace."""
        vals = []
        for name, fa in self.analyses.items():
            ctx = self.contexts.get(name, set())
            in_pages = bool(ctx & {CS, WAR, UNK}) or bool(fa.injected_ranges)
            if not in_pages:
                continue
            for step, val in fa.message_sends:
                if val.taint:
                    hop = Step(step.file, step.line, step.col, step.pos, "passes it to the background script")
                    vals.append(extend_trace(val, hop))
        return union(*vals) if vals else EMPTY

    # -- reporting helpers --

    def snippet(self, file: str, line: int, col: int) -> str | None:
        script = self.scripts.get(file)
        text = script.text if script else self.pkg.text(file)
        if not text or line <= 0:
            return None
        lines = text.splitlines()
        if line > len(lines):
            return None
        s = lines[line - 1]
        if len(s) > 160:
            start = max(0, col - 60)
            s = ("…" if start else "") + s[start : start + 160] + "…"
        return s.strip()[:200]

    def display_name(self, name: str) -> str:
        return self.scripts[name].display_file if name in self.scripts else name


def analyze_package(
    pkg: ExtensionPackage,
    extension_id: str,
    source: str,
    cfg: Settings = default_settings,
    mode: str = "dataflow",
) -> ExtensionReport:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    a = _Analysis(pkg, cfg, mode)
    analyze_manifest(a.info, pkg, a.out)
    a.collect_scripts()
    a.assign_contexts()
    a.parse_and_scan()

    if mode == "dataflow":
        a.run_taint(list(a.scripts))
    a.propagate_references()

    if mode == "dataflow":
        incoming = a.incoming_messages()
        if incoming.taint:
            receivers = [n for n in a.scripts if a.contexts[n] & {BG, PAGE} and n in a.asts]
            a.run_taint(receivers, incoming)

    obfuscated = {n for n, r in a.obf.items() if r.obfuscated and n not in a.libraries}
    csp = a.info.raw.get("content_security_policy")
    csp_text = csp if isinstance(csp, str) else ""
    ctx = Context(
        info=a.info,
        contexts=a.contexts,
        injected_ranges={n: fa.injected_ranges for n, fa in a.analyses.items() if fa.injected_ranges},
        libraries=a.libraries,
        obfuscated=obfuscated,
        snippet=a.snippet,
        eval_allowed_in_pages=a.info.manifest_version == 2 and "'unsafe-eval'" in csp_text,
        remote_scripts_allowed_in_pages=a.info.manifest_version == 2 and bool(re.search(r"script-src[^;]*https?:", csp_text)),
    )
    analyses = list(a.analyses.values())

    if mode == "keyword":
        keyword_findings(analyses, ctx, a.out)
    else:
        exfiltrated = flow_findings(analyses, ctx, a.out)
        bg_names = [n for n in a.scripts if BG in a.contexts[n]]
        background_parsed = all(a.analyses[n].parsed and not a.analyses[n].partial for n in bg_names)
        page_side = [a.analyses[n] for n in a.scripts if a.contexts[n] & {CS, WAR, UNK}]
        message_relay_findings(page_side, background_parsed, ctx, a.out)
        page_leak_findings(analyses, ctx, a.out)
        code_exec_findings(analyses, ctx, a.out)
        capability_findings(analyses, exfiltrated, ctx, a.out)
        complete = not obfuscated and all(fa.parsed and not fa.partial for n, fa in a.analyses.items() if n not in a.libraries)
        unused_permission_findings(analyses, ctx, complete, a.out)

    _remote_page_script_findings(a, ctx)
    _obfuscation_findings(a, obfuscated)

    files = [
        FileReport(
            path=name,
            size=script.size,
            contexts=sorted(a.contexts.get(name, {UNK}), key=lambda c: c.value),
            parsed=a.analyses[name].parsed if name in a.analyses else False,
            parse_error=a.parse_errors.get(name),
            library=a.libraries.get(name),
            minified=a.obf[name].minified,
            obfuscation_signals=a.obf[name].signals,
        )
        for name, script in sorted(a.scripts.items())
    ]
    fallback = sorted(n for n, fa in a.analyses.items() if not fa.parsed)
    coverage = AnalysisCoverage(
        parser=a.backend if mode == "dataflow" else "regex (keyword baseline)",
        files_with_syntax_errors=sorted(a.syntax_error_files),
        js_files=len(a.scripts),
        parsed_files=sum(1 for fa in a.analyses.values() if fa.parsed),
        fallback_files=fallback,
        obfuscated_files=sorted(obfuscated),
        library_files=sorted(a.libraries),
    )
    if fallback and mode == "dataflow":
        a.warnings.append(
            f"{len(fallback)} script(s) could not be parsed and were only pattern-scanned; "
            "data flows through them are not covered."
        )
    return ExtensionReport(
        extension_id=extension_id,
        name=a.info.name,
        version=a.info.version,
        manifest_version=a.info.manifest_version,
        description=a.info.description,
        source=source,
        package_sha256=pkg.sha256,
        analyzed_at=datetime.now(timezone.utc),
        analyzer_version=__version__,
        mode=mode,
        findings=a.out.results(),
        coverage=coverage,
        permissions=a.info.permissions,
        host_permissions=a.info.host_permissions,
        optional_permissions=a.info.optional_permissions + a.info.optional_host_permissions,
        files=files,
        warnings=a.warnings,
    )


def _remote_page_script_findings(a: _Analysis, ctx: Context) -> None:
    for page, src, line, _ in a.page_remote_scripts:
        allowed = ctx.remote_scripts_allowed_in_pages
        a.out.add(
            "REMOTE_SCRIPT_TAG", Category.CODE_EXECUTION, Severity.HIGH if allowed else Severity.INFO,
            "Its pages load code from a remote server" if allowed else "Its pages reference a remote script that Chrome blocks",
            f"{page} includes <script src=\"{src}\">. "
            + ("The extension's CSP permits it, so that server controls code running with extension privileges."
               if allowed else "The extension's content security policy does not allow remote scripts, so it will not load."),
            Evidence(file=page, line=line, snippet=a.snippet(page, line, 0)), Confidence.CONFIRMED,
        )  # fmt: skip


def _obfuscation_findings(a: _Analysis, obfuscated: set[str]) -> None:
    for name in sorted(obfuscated):
        r = a.obf[name]
        contexts = a.contexts.get(name, {UNK})
        sensitive_ctx = bool(contexts & {CS, BG, WAR})
        display = a.display_name(name)
        line = r.first_signal_line or 1
        if r.encoded_payloads:
            pl_line, preview = r.encoded_payloads[0]
            a.out.add(
                "ENCODED_CODE_PAYLOAD", Category.OBFUSCATION, Severity.HIGH,
                "Hides JavaScript inside encoded strings",
                f"{display} contains {len(r.encoded_payloads)} base64 block(s) that decode to JavaScript, e.g. {preview[:80]!r}. "
                "Legitimate extensions have no reason to ship code this way.",
                Evidence(file=display, line=pl_line, note="decoded: " + preview[:120]), Confidence.CONFIRMED,
            )  # fmt: skip
        other = [s for s in r.signals if "base64" not in s]
        if other:
            a.out.add(
                "OBFUSCATED_CODE", Category.OBFUSCATION, Severity.HIGH if sensitive_ctx else Severity.MEDIUM,
                "Contains deliberately obfuscated code",
                f"{display} shows measured signs of obfuscation (not just minification): {'; '.join(other)}. "
                "Obfuscation hides behaviour from reviewers and limits how much of this file the analysis can verify.",
                Evidence(file=display, line=line, snippet=a.snippet(name, line, 0), note="; ".join(other)), Confidence.CONFIRMED,
            )  # fmt: skip
    minified = [a.display_name(n) for n, r in a.obf.items() if r.minified and not r.has_source_map and n not in a.libraries and n not in obfuscated]
    if minified:
        a.out.add(
            "MINIFIED_CODE", Category.OBFUSCATION, Severity.INFO,
            f"{len(minified)} script(s) are minified without source maps",
            "Minification is normal for bundled extensions and is not suspicious in itself; it only makes manual review harder.",
            [Evidence(file=f) for f in minified[:5]], Confidence.CONFIRMED,
        )  # fmt: skip
