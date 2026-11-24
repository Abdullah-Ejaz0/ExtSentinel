"""Turn raw analysis facts (flows, code execution sites, capabilities) into
explained findings, calibrated by evidence.

Severity of a behavioural finding depends on four questions, each answered
from the code or manifest rather than assumed:

1. What data is involved?            -> label sensitivity (catalog.LABELS)
2. Can the source run where it is?   -> script context (page data only exists in content scripts)
3. Can it work at all?               -> required permission / CSP actually granted
4. Where does it go?                 -> destination: the extension's own declared sites,
                                        a third-party host, or an address computed at runtime
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .findings import FindingCollector
from .js import catalog as C
from .js.taint import CodeExec, FileAnalysis, Flow, Step, url_host
from .manifest import PERMISSIONS, ManifestInfo, host_matches
from .models import Category, Confidence, Evidence, ScriptContext, Severity

S = Severity
CS, BG, PAGE, WAR, UNK = (
    ScriptContext.CONTENT_SCRIPT,
    ScriptContext.BACKGROUND,
    ScriptContext.EXTENSION_PAGE,
    ScriptContext.WEB_ACCESSIBLE,
    ScriptContext.UNKNOWN,
)
PAGE_WORLD = {CS, WAR}


@dataclass
class Context:
    info: ManifestInfo
    contexts: dict[str, set[ScriptContext]]
    injected_ranges: dict[str, list[tuple[int, int]]]
    libraries: dict[str, str]
    obfuscated: set[str]
    snippet: Callable[[str, int, int], str | None]
    eval_allowed_in_pages: bool
    remote_scripts_allowed_in_pages: bool

    def step_contexts(self, step: Step) -> set[ScriptContext]:
        for start, end in self.injected_ranges.get(step.file, []):
            if start <= step.pos < end:
                return {CS}
        return self.contexts.get(step.file, {UNK})

    def evidence(self, step: Step, note: str | None = None) -> Evidence:
        return Evidence(file=step.file, line=step.line, snippet=self.snippet(step.file, step.line, step.col), note=note or step.note)


def _sev_for_destination(sensitivity: Severity, dest_class: str) -> Severity:
    if dest_class in ("third_party", "dynamic", "native"):
        return sensitivity
    if dest_class == "first_party":
        return sensitivity.lowered(2)
    return sensitivity.lowered(1)  # page origin / relative URL


def _classify_destination(flow: Flow, first_party: set[str]) -> tuple[str, str | None]:
    if "native program" in flow.step.note:
        return "native", None
    dest = flow.destination
    host = url_host(dest) if dest else None
    if host:
        return ("first_party" if host_matches(host, first_party) else "third_party"), host
    if dest and dest.startswith("/") and not dest.startswith("//"):
        return "page_origin", None
    return "dynamic", None


def _dest_phrase(dest_class: str, host: str | None) -> str:
    if dest_class == "native":
        return "a program installed on your computer"
    if host:
        return host
    if dest_class == "page_origin":
        return "the website you are on"
    return "a server whose address is built at runtime"


def _permission_gate(label: str, origin: Step, ctx: Context) -> tuple[str, str | None]:
    """Return ('ok'|'optional'|'missing', permission)."""
    lab = C.LABELS[label]
    perm = lab.permission
    if label == "BROWSING" and ("tab" in origin.note or "window" in origin.note):
        has_hosts = bool(ctx.info.host_permissions)
        state = ctx.info.granted("tabs")
        if state == "required" or has_hosts:
            return "ok", None
        return ("optional" if state == "optional" else "missing"), "tabs"
    if perm is None:
        return "ok", None
    state = ctx.info.granted(perm)
    if state == "required" or (perm == "webRequest" and ctx.info.granted("webRequestBlocking") == "required"):
        return "ok", perm
    return ("optional" if state == "optional" else "missing"), perm


def _trace_text(trace: tuple[Step, ...], sink: Step) -> str:
    parts = [f"{s.note.removeprefix('source: ')} ({s.file}:{s.line})" for s in trace]
    parts.append(f"{sink.note.removeprefix('sink: ')} ({sink.file}:{sink.line})")
    return " → ".join(parts)


# --- data flows -----------------------------------------------------------------


def flow_findings(analyses: list[FileAnalysis], ctx: Context, out: FindingCollector) -> set[str]:
    """Report sensitive data reaching the network. Returns labels with confirmed exfiltration."""
    first_party = ctx.info.first_party_hosts()
    exfiltrated: set[str] = set()
    for fa in analyses:
        for flow in fa.flows:
            if flow.sink != "network":
                continue
            for label, trace in flow.labels.items():
                lab = C.LABELS.get(label)
                if lab is None or lab.sensitivity is None:
                    continue
                origin = trace[0]
                origin_ctx = ctx.step_contexts(origin)
                confidence = Confidence.CONFIRMED
                caveats: list[str] = []
                if lab.page_derived:
                    if origin_ctx & PAGE_WORLD:
                        pass
                    elif UNK in origin_ctx:
                        confidence = Confidence.LIKELY
                        caveats.append(f"{origin.file} is not declared as a content script; it is assumed to be injected into pages at runtime")
                    else:
                        continue  # input typed into the extension's own popup/options page is not page data
                dest_class, host = _classify_destination(flow, first_party)
                if flow.dest_extension or (flow.navigation and dest_class in ("dynamic", "page_origin")):
                    # Opening one of the extension's own pages, or navigating a tab to an address
                    # derived from its own URL, does not send data to a server we can identify.
                    continue
                severity = _sev_for_destination(lab.sensitivity, dest_class)
                gate, perm = _permission_gate(label, origin, ctx)
                if gate == "missing":
                    severity = S.INFO
                    caveats.append(f"this cannot work as written: the \"{perm}\" permission is not declared")
                elif gate == "optional":
                    severity = severity.lowered()
                    caveats.append(f"only works if you grant the optional \"{perm}\" permission")
                if confidence == Confidence.LIKELY:
                    severity = severity.lowered()
                if gate != "missing":
                    exfiltrated.add(label)

                dest = _dest_phrase(dest_class, host)
                dest_note = {
                    "first_party": "This destination is one of the sites the extension declares it works with.",
                    "third_party": "This host is not among the sites the extension declares it works with.",
                    "dynamic": "The destination address is computed at runtime, so it cannot be verified statically.",
                    "page_origin": "The request goes to the website the user is already on.",
                    "native": "Data leaves the browser to a locally installed program.",
                }[dest_class]
                description = (
                    f"Data flow traced in the code: {_trace_text(trace, flow.step)}. {dest_note}"
                    + ("" if not caveats else " Note: " + "; ".join(caveats) + ".")
                )
                evidence = [ctx.evidence(s) for s in trace] + [ctx.evidence(flow.step)]
                tags = [f"label:{label}", f"dest_class:{dest_class}"] + ([f"dest_host:{host}"] if host else [])
                out.add(
                    f"EXFIL_{label}", Category.EXFILTRATION, severity,
                    f"Sends {lab.phrase} to {dest}", description, evidence, confidence, tags,
                )  # fmt: skip
    return exfiltrated


def message_relay_findings(
    content_analyses: list[FileAnalysis], background_parsed: bool, ctx: Context, out: FindingCollector
) -> None:
    """Content script passes sensitive page data to a background script that could not be analysed."""
    if background_parsed:
        return
    for fa in content_analyses:
        for flow in fa.flows:
            if flow.sink != "message":
                continue
            for label, trace in flow.labels.items():
                lab = C.LABELS.get(label)
                if lab is None or lab.sensitivity is None:
                    continue
                out.add(
                    f"RELAY_{label}", Category.EXFILTRATION, lab.sensitivity.lowered(),
                    f"Collects {lab.phrase} and passes it to its background script",
                    f"Data flow traced: {_trace_text(trace, flow.step)}. The background script could not be fully "
                    "analysed, so whether the data leaves the browser is unknown.",
                    [ctx.evidence(s) for s in trace] + [ctx.evidence(flow.step)], Confidence.LIKELY, [f"label:{label}"],
                )  # fmt: skip


def page_leak_findings(analyses: list[FileAnalysis], ctx: Context, out: FindingCollector) -> None:
    for fa in analyses:
        for flow in fa.flows:
            if flow.sink != "page_leak" or not ctx.step_contexts(flow.step) & PAGE_WORLD:
                continue  # window.postMessage only reaches web pages when called from a page script
            for label, trace in flow.labels.items():
                lab = C.LABELS.get(label)
                # Page-derived data posted back to the page is not a leak: the page already has it.
                if lab is None or lab.sensitivity is None or lab.page_derived:
                    continue
                out.add(
                    f"PAGE_LEAK_{label}", Category.EXFILTRATION, lab.sensitivity.lowered(),
                    f"Shares {lab.phrase} with the websites you visit",
                    f"Data flow traced: {_trace_text(trace, flow.step)}. Any script on the page can read data posted with window.postMessage.",
                    [ctx.evidence(s) for s in trace] + [ctx.evidence(flow.step)], Confidence.CONFIRMED, [f"label:{label}"],
                )  # fmt: skip


# --- code execution ---------------------------------------------------------------

_DYNAMIC_EXEC = {"eval", "function", "timer_string", "execute_script_code", "user_script", "debugger_eval", "document_write"}
_LOAD_EXEC = {"script_src", "import_scripts", "dynamic_import"}
_EXEC_TEXT = {
    "eval": "eval()",
    "function": "the Function constructor",
    "timer_string": "a string passed to setTimeout/setInterval",
    "execute_script_code": "chrome.tabs.executeScript({code})",
    "user_script": "chrome.userScripts",
    "debugger_eval": "the debugger (Runtime.evaluate)",
    "document_write": "document.write()",
    "script_src": "a <script> element",
    "import_scripts": "importScripts()",
    "dynamic_import": "import()",
    "script_text": "an inline <script> element",
}


def _blocked_by_csp(kind: str, contexts: set[ScriptContext], ctx: Context) -> bool:
    """Chrome refuses eval/remote scripts in extension pages unless the CSP was relaxed (MV2 only)."""
    if not contexts or not contexts <= {BG, PAGE}:
        return False
    if kind in {"eval", "function", "timer_string"}:
        return not ctx.eval_allowed_in_pages
    if kind in _LOAD_EXEC:
        return not ctx.remote_scripts_allowed_in_pages
    return False


def _where(contexts: set[ScriptContext]) -> str:
    if contexts & PAGE_WORLD:
        return "inside the web pages you visit"
    if BG in contexts:
        return "in its background script"
    if PAGE in contexts:
        return "in its own pages"
    return "in a script loaded at runtime"


def code_exec_findings(analyses: list[FileAnalysis], ctx: Context, out: FindingCollector) -> None:
    for fa in analyses:
        library = ctx.libraries.get(fa.path)
        for ce in fa.code_execs:
            contexts = ctx.step_contexts(ce.step)
            _one_exec(fa, ce, contexts, library, ctx, out)


def _one_exec(fa: FileAnalysis, ce: CodeExec, contexts, library, ctx: Context, out: FindingCollector) -> None:
    how = _EXEC_TEXT.get(ce.kind, ce.kind)
    where = _where(contexts)
    lib_note = f" The code is inside what its banner identifies as {library}; banners can be forged." if library else ""

    if not fa.parsed:
        out.add(
            "CODE_EXEC_UNVERIFIED", Category.CODE_EXECUTION, S.LOW,
            "Contains dynamic code execution that could not be analysed",
            f"{fa.path} uses {how} but could not be parsed, so the origin of the executed code is unknown.",
            ctx.evidence(ce.step), Confidence.POSSIBLE, [f"exec:{ce.kind}"],
        )  # fmt: skip
        return

    remote = ce.labels.get("REMOTE_DATA")
    untrusted = ce.labels.get("UNTRUSTED_PAGE") or ce.labels.get("EXTERNAL_MESSAGE")
    blocked = _blocked_by_csp(ce.kind, contexts, ctx)
    blocked_note = " Chrome's content security policy blocks this in extension pages, so it cannot run as written." if blocked else ""
    if ce.kind == "execute_script_code" and ctx.info.manifest_version == 3:
        blocked = True
        blocked_note = " chrome.tabs.executeScript does not exist in Manifest V3, so this code can never run."

    if remote:
        out.add(
            "REMOTE_CODE_EXECUTION", Category.CODE_EXECUTION, S.INFO if blocked else S.CRITICAL,
            "Has a code path that would run downloaded code, but Chrome blocks it" if blocked
            else "Downloads code from the internet and runs it",
            f"Data flow traced: {_trace_text(remote, ce.step)}. Code fetched at runtime is never reviewed by the "
            f"Web Store and can change at any time; it runs {where}.{blocked_note}",
            [ctx.evidence(s) for s in remote] + [ctx.evidence(ce.step)], Confidence.CONFIRMED, [f"exec:{ce.kind}"],
        )  # fmt: skip
        return
    if untrusted:
        out.add(
            "UNTRUSTED_CODE_EXECUTION", Category.CODE_EXECUTION, S.INFO if blocked else S.HIGH,
            "Has a code path where websites could choose the code it runs, but Chrome blocks it" if blocked
            else "Websites can make it run code of their choice",
            f"Data flow traced: {_trace_text(untrusted, ce.step)}. Messages from web pages reach {how}, so a malicious "
            f"site could run code with the extension's privileges.{blocked_note}",
            [ctx.evidence(s) for s in untrusted] + [ctx.evidence(ce.step)], Confidence.CONFIRMED, [f"exec:{ce.kind}"],
        )  # fmt: skip
        return

    if ce.kind in _LOAD_EXEC:
        if ce.is_extension_url:
            return
        target = ce.const if ce.const is not None else ce.prefix
        host = url_host(target) if target and target.strip().lower().startswith(("http", "//", "ws")) else None
        if ce.const is not None and host is None:
            return  # a file bundled with the extension
        if host:
            sev = S.INFO if blocked else (S.HIGH if contexts & (PAGE_WORLD | {BG, UNK}) else S.MEDIUM)
            conf = Confidence.CONFIRMED if ce.const is not None else Confidence.LIKELY
            out.add(
                "REMOTE_SCRIPT_LOAD", Category.CODE_EXECUTION, sev,
                f"Loads code from {host} and runs it {where}",
                f"{fa.path} loads a script from {target} via {how}. Remotely hosted code bypasses Web Store review."
                + blocked_note + lib_note,
                ctx.evidence(ce.step), conf, [f"exec:{ce.kind}", f"dest_host:{host}"],
            )  # fmt: skip
        else:
            out.add(
                "DYNAMIC_SCRIPT_LOAD", Category.CODE_EXECUTION, S.INFO if blocked else S.MEDIUM,
                f"Loads scripts from an address computed at runtime ({where})",
                f"{fa.path} loads a script via {how}, but the address is built at runtime and could not be resolved statically."
                + blocked_note + lib_note,
                ctx.evidence(ce.step), Confidence.POSSIBLE, [f"exec:{ce.kind}"],
            )  # fmt: skip
        return

    if ce.kind == "script_text":
        if ce.const is not None or not ce.labels:
            return  # injecting a fixed, bundled snippet into the page world is a common, reviewable pattern
    if ce.kind == "document_write":
        text = ce.const or ""
        if "<script" in text.lower() and ("http" in text.lower() or "//" in text):
            out.add(
                "REMOTE_SCRIPT_LOAD", Category.CODE_EXECUTION, S.HIGH,
                f"Writes a remote <script> tag {where}",
                f"{fa.path} uses document.write() to add a script loaded from another server." + lib_note,
                ctx.evidence(ce.step), Confidence.CONFIRMED, ["exec:document_write"],
            )  # fmt: skip
        return

    if ce.kind == "debugger_eval":
        out.add(
            "DEBUGGER_CODE_EXECUTION", Category.CODE_EXECUTION, S.HIGH,
            "Runs code inside pages through the browser debugger",
            f"{fa.path} sends Runtime.evaluate commands through chrome.debugger, which bypasses page and extension security boundaries.",
            ctx.evidence(ce.step), Confidence.CONFIRMED, ["exec:debugger_eval"],
        )  # fmt: skip
        return

    if ce.const is not None:
        if ce.const.strip() in C.BENIGN_CODE_STRINGS or library:
            return
        out.add(
            "STATIC_CODE_STRING", Category.CODE_EXECUTION, S.INFO,
            f"Runs a fixed code string with {how}",
            f"The executed code is a constant bundled with the extension (reviewable), e.g. {ce.const[:80]!r}.",
            ctx.evidence(ce.step), Confidence.CONFIRMED, [f"exec:{ce.kind}"],
        )  # fmt: skip
        return

    # No network or web-page data reaches this sink (storage is bridged, so fetch -> store -> eval
    # is still caught above). Without such evidence the risk is low but the code is unreviewable.
    severity = S.INFO if blocked else S.LOW
    if library:
        severity = severity.lowered()
    out.add(
        "DYNAMIC_CODE_EXECUTION", Category.CODE_EXECUTION, severity,
        f"Builds code at runtime and runs it with {how}",
        f"{fa.path} executes a string assembled at runtime {where}. No path from the network or web pages "
        f"into it was found, but the code it runs cannot be reviewed statically.{blocked_note}{lib_note}",
        ctx.evidence(ce.step), Confidence.POSSIBLE, [f"exec:{ce.kind}"],
    )  # fmt: skip


# --- capabilities without observed misuse ------------------------------------------


def capability_findings(analyses: list[FileAnalysis], exfiltrated: set[str], ctx: Context, out: FindingCollector) -> None:
    for fa in analyses:
        for listener in fa.listeners:
            contexts = ctx.step_contexts(listener.step)
            if not contexts & (PAGE_WORLD | {UNK}):
                continue  # a keyboard shortcut in the extension's own popup is not page monitoring
            if listener.event == "keyboard" and "KEYSTROKES" not in exfiltrated:
                if fa.parsed and not fa.partial:
                    out.add(
                        "KEY_LISTENER_IN_PAGES", Category.SURVEILLANCE, S.LOW,
                        "Listens to keyboard events on web pages",
                        "A keyboard listener is installed in pages, but the pressed keys are only compared "
                        "(e.g. for shortcuts) and never stored or sent anywhere in the analysed code.",
                        ctx.evidence(listener.step), Confidence.POSSIBLE, ["listener:keyboard"],
                    )  # fmt: skip
                else:
                    out.add(
                        "KEY_LISTENER_UNVERIFIED", Category.SURVEILLANCE, S.MEDIUM,
                        "Listens to keyboard events on web pages (could not verify what it does with them)",
                        f"{fa.path} registers a keyboard listener in pages but could not be fully analysed.",
                        ctx.evidence(listener.step), Confidence.POSSIBLE, ["listener:keyboard"],
                    )  # fmt: skip

        for label, steps in fa.sensitive_reads.items():
            lab = C.LABELS.get(label)
            if lab is None or lab.sensitivity is None or label in exfiltrated or not steps:
                continue
            contexts = ctx.step_contexts(steps[0])
            if lab.page_derived and not contexts & (PAGE_WORLD | {UNK}):
                continue
            if not fa.parsed or fa.partial or fa.path in ctx.obfuscated:
                if label in ("PASSWORD", "PAGE_COOKIES"):
                    out.add(
                        f"READS_{label}_UNVERIFIED", Category.DATA_ACCESS, S.MEDIUM,
                        f"Accesses {lab.phrase} (could not verify where the data goes)",
                        f"{fa.path} references {lab.phrase} but could not be fully analysed.",
                        [ctx.evidence(s) for s in steps], Confidence.POSSIBLE, [f"label:{label}"],
                    )  # fmt: skip
                continue
            out.add(
                f"READS_{label}_LOCAL", Category.DATA_ACCESS, S.INFO,
                f"Reads {lab.phrase}; no path to the network was found",
                "The data is read, but in the analysed code it is only used locally (not sent to any server).",
                [ctx.evidence(s) for s in steps], Confidence.CONFIRMED, [f"label:{label}"],
            )  # fmt: skip


def unused_permission_findings(analyses: list[FileAnalysis], ctx: Context, complete: bool, out: FindingCollector) -> None:
    """Over-permissioning: a granted capability that no code path uses."""
    if not complete:
        return
    used = set()
    for fa in analyses:
        used |= set(fa.capabilities)
    for perm in ctx.info.permissions:
        entry = PERMISSIONS.get(perm)
        if entry is None or entry[2] is None or entry[0].rank < S.LOW.rank:
            continue
        namespaces = entry[2].split("|")
        if any(u == ns or u.startswith(ns + ".") for u in used for ns in namespaces):
            continue
        out.add(
            "UNUSED_PERMISSION", Category.PERMISSION, S.LOW,
            f"Requests the \"{perm}\" permission but its code never uses it",
            f"No call to {' or '.join(namespaces)} exists in any script. Unused permissions widen the damage a "
            "compromised or sold extension could do in a future update.",
            Evidence(file="manifest.json", note=f"permissions: {perm}"), Confidence.LIKELY, [f"permission:{perm}"],
        )  # fmt: skip


# --- keyword baseline (for evaluation only) ----------------------------------------

_BASELINE_READS = {
    "PAGE_COOKIES": (S.MEDIUM, "Mentions document.cookie"),
    "PASSWORD": (S.HIGH, "Mentions password fields"),
    "CLIPBOARD": (S.MEDIUM, "Mentions clipboard reading"),
    "COOKIES": (S.HIGH, "Mentions chrome.cookies"),
    "HISTORY": (S.HIGH, "Mentions chrome.history"),
}


def keyword_findings(analyses: list[FileAnalysis], ctx: Context, out: FindingCollector) -> None:
    """Naive 'suspicious keyword' report: every match is a finding. Used as an evaluation baseline."""
    for fa in analyses:
        for ce in fa.code_execs:
            out.add(
                f"KW_EXEC_{ce.kind.upper()}", Category.CODE_EXECUTION, S.HIGH, f"Uses {_EXEC_TEXT.get(ce.kind, ce.kind)}",
                "Keyword match.", ctx.evidence(ce.step), Confidence.POSSIBLE,
            )  # fmt: skip
        for listener in fa.listeners:
            out.add(
                f"KW_LISTENER_{listener.event.upper()}", Category.SURVEILLANCE, S.HIGH, f"Has a {listener.event} listener",
                "Keyword match.", ctx.evidence(listener.step), Confidence.POSSIBLE,
            )  # fmt: skip
        for label, steps in fa.sensitive_reads.items():
            if label in _BASELINE_READS and steps:
                sev, title = _BASELINE_READS[label]
                out.add(f"KW_READ_{label}", Category.DATA_ACCESS, sev, title, "Keyword match.", ctx.evidence(steps[0]), Confidence.POSSIBLE)
        if fa.network_destinations and fa.sensitive_reads:
            out.add(
                "KW_EXFIL", Category.EXFILTRATION, S.HIGH, "Reads sensitive data and makes network requests",
                "Keyword co-occurrence in one file.", ctx.evidence(fa.network_destinations[0][1]), Confidence.POSSIBLE,
            )  # fmt: skip
