"""Regex scanner: fallback for scripts that cannot be parsed, and the
"keyword" baseline used in evaluation to measure what data-flow analysis adds.

It can only say a capability is *present*, never that data flows anywhere,
so everything it reports downstream carries Confidence.POSSIBLE.
"""

from __future__ import annotations

import bisect
import re

from . import catalog as C
from .taint import CodeExec, FileAnalysis, Listener, Step

_CHROME_API_RE = re.compile(r"\b(?:chrome|browser)\s*\.\s*([A-Za-z]+)\s*\.\s*([A-Za-z]+)(?:\s*\.\s*([A-Za-z]+))?")
_STR = r"""(?:'((?:\\.|[^'\\\n])*)'|"((?:\\.|[^"\\\n])*)"|`([^`$]*)`)"""

_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # (kind, detail, regex)
    ("exec", "eval", re.compile(r"(?<![\w$.])eval\s*\(\s*" + f"(?:{_STR})?")),
    ("exec", "function", re.compile(r"\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(\s*" + f"(?:{_STR})?")),
    ("exec", "timer_string", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*" + _STR)),
    ("exec", "import_scripts", re.compile(r"\bimportScripts\s*\(\s*" + f"(?:{_STR})?")),
    ("exec", "execute_script_code", re.compile(r"\.executeScript\s*\([^)]{0,200}?\bcode\s*:")),
    ("listener", "keyboard", re.compile(r"""addEventListener\s*\(\s*['"`]key(?:down|up|press)['"`]|\.onkey(?:down|up|press)\s*=""")),
    ("listener", "submit", re.compile(r"""addEventListener\s*\(\s*['"`]submit['"`]""")),
    ("read", "PAGE_COOKIES", re.compile(r"\bdocument\s*\.\s*cookie\b")),
    ("read", "PASSWORD", re.compile(r"""type\s*=\s*\\?['"]?password|\[type=\\?['"]?password""", re.I)),
    ("read", "CLIPBOARD", re.compile(r"\bclipboard\s*\.\s*read(?:Text)?\s*\(|execCommand\s*\(\s*['\"]paste")),
    ("net", "fetch", re.compile(r"(?<![\w$.])fetch\s*\(\s*" + f"(?:{_STR})?")),
    ("net", "XMLHttpRequest", re.compile(r"\bnew\s+XMLHttpRequest\b")),
    ("net", "sendBeacon", re.compile(r"\bsendBeacon\s*\(\s*" + f"(?:{_STR})?")),
    ("net", "WebSocket", re.compile(r"\bnew\s+WebSocket\s*\(\s*" + f"(?:{_STR})?")),
]


class _Lines:
    def __init__(self, text: str) -> None:
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def locate(self, pos: int) -> tuple[int, int]:
        idx = bisect.bisect_right(self.starts, pos) - 1
        return idx + 1, pos - self.starts[idx]


def _first_string(m: re.Match[str]) -> str | None:
    for g in m.groups():
        if g is not None:
            return g
    return None


def scan(path: str, text: str, parse_error: str | None = None) -> FileAnalysis:
    res = FileAnalysis(path=path, parsed=False, parse_error=parse_error)
    lines = _Lines(text)

    def step(pos: int, note: str) -> Step:
        line, col = lines.locate(pos)
        return Step(path, line, col, pos, note)

    for m in _CHROME_API_RE.finditer(text):
        parts = [p for p in m.groups() if p]
        api = "chrome." + ".".join(parts)
        sites = res.capabilities.setdefault(api, [])
        if len(sites) < 5:
            sites.append(step(m.start(), f"mentions {api}"))
        call_path = "chrome." + ".".join(parts[:2])
        if call_path in C.CALL_SOURCES:
            label, note = C.CALL_SOURCES[call_path]
            res.sensitive_reads.setdefault(label, []).append(step(m.start(), note))

    for kind, detail, rx in _PATTERNS:
        for count, m in enumerate(rx.finditer(text)):
            if count >= 20:
                break
            st = step(m.start(), f"matches pattern for {detail}")
            if kind == "exec":
                res.code_execs.append(CodeExec(detail, st, _first_string(m), None, {}))
            elif kind == "listener":
                res.listeners.append(Listener(detail, st))
            elif kind == "read":
                sites = res.sensitive_reads.setdefault(detail, [])
                if len(sites) < 5:
                    sites.append(st)
            elif kind == "net":
                res.network_destinations.append((_first_string(m), st))
    return res
