"""Obfuscation detection.

Minification is normal (almost every bundled extension is minified) and is
not treated as suspicious. Obfuscation - transformations whose purpose is to
stop a human or a scanner from reading the code - is. The detector therefore
separates the two and reports measured signals, not a guess:

* javascript-obfuscator style: many `_0x1a2b` identifiers, a large string
  array accessed through a decoder function.
* Dean Edwards packer: `eval(function(p,a,c,k,e,...`.
* JSFuck-style: code made almost entirely of `[]()!+`.
* Escaped strings: dense `\\xNN` escapes hiding string contents.
* Encoded payloads: long base64 literals that decode to JavaScript.
* High-entropy string literals (packed data).
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import dataclass, field

_HEX_IDENT_RE = re.compile(r"\b_0x[0-9a-fA-F]{4,6}\b")
_PACKER_RE = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[rd]\s*\)")
_JSFUCK_RE = re.compile(r"\[\]\[\(!\[\]\+\[\]\)")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_STRING_RE = re.compile(r"""'((?:\\.|[^'\\\n]){40,})'|"((?:\\.|[^"\\\n]){40,})\"""")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]{120,}={0,2}$")
_CODE_HINT_RE = re.compile(r"\b(?:function|return|var|let|const|document|window|eval|fetch|chrome)\b")
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=")
_FROMCHARCODE_RE = re.compile(r"fromCharCode\s*\(\s*(?:\d+\s*,\s*){20,}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass
class ObfuscationResult:
    minified: bool
    has_source_map: bool
    obfuscated: bool  # strong evidence of deliberate obfuscation
    signals: list[str] = field(default_factory=list)  # human-readable measured signals
    encoded_payloads: list[tuple[int, str]] = field(default_factory=list)  # (line, preview of decoded code)
    first_signal_line: int | None = None


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def analyze_text(text: str) -> ObfuscationResult:
    size = len(text)
    lines = text.count("\n") + 1
    avg_line = size / lines if lines else 0
    minified = size > 2000 and (avg_line > 250 or (lines < 5 and size > 5000))
    res = ObfuscationResult(minified=minified, has_source_map=bool(_SOURCEMAP_RE.search(text[-500:])), obfuscated=False)

    def strong(signal: str, pos: int | None) -> None:
        res.obfuscated = True
        res.signals.append(signal)
        if pos is not None and res.first_signal_line is None:
            res.first_signal_line = _line_of(text, pos)

    hex_idents = _HEX_IDENT_RE.findall(text)
    distinct = len(set(hex_idents))
    if distinct >= 15 or len(hex_idents) >= 100:
        m = _HEX_IDENT_RE.search(text)
        strong(f"{distinct} distinct _0x-style identifiers ({len(hex_idents)} uses), typical of javascript-obfuscator", m.start() if m else None)

    m = _PACKER_RE.search(text)
    if m:
        strong("packed with the p,a,c,k,e,r packer", m.start())

    m = _JSFUCK_RE.search(text)
    if m or (size > 1000 and sum(text.count(c) for c in "[]()!+") / size > 0.9):
        strong("written in JSFuck-style symbols", m.start() if m else 0)

    escapes = _HEX_ESCAPE_RE.findall(text)
    if len(escapes) >= 200 and len(escapes) * 4 / max(size, 1) > 0.05:
        m = _HEX_ESCAPE_RE.search(text)
        strong(f"{len(escapes)} \\x escapes hide string contents ({len(escapes) * 400 // max(size, 1)}% of the file)", m.start() if m else None)

    m = _FROMCHARCODE_RE.search(text)
    if m:
        res.signals.append("builds strings from long character-code lists (String.fromCharCode)")
        res.first_signal_line = res.first_signal_line or _line_of(text, m.start())

    high_entropy = 0
    for sm in _STRING_RE.finditer(text):
        s = sm.group(1) or sm.group(2) or ""
        if s.startswith(("data:image", "data:font", "data:application/font", "http")):
            continue
        if _B64_RE.match(s):
            decoded = _try_b64(s)
            if decoded and _CODE_HINT_RE.search(decoded) and _printable_ratio(decoded) > 0.9:
                res.encoded_payloads.append((_line_of(text, sm.start()), decoded[:120]))
                continue
        if len(s) >= 80 and shannon_entropy(s) >= 5.2:
            high_entropy += 1
    if res.encoded_payloads:
        strong(f"{len(res.encoded_payloads)} base64-encoded block(s) that decode to JavaScript", None)
        res.first_signal_line = res.first_signal_line or res.encoded_payloads[0][0]
    if high_entropy >= 5:
        res.signals.append(f"{high_entropy} long high-entropy string literals (packed or encrypted data)")
    return res


def _try_b64(s: str) -> str | None:
    try:
        return base64.b64decode(s, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _printable_ratio(s: str) -> float:
    return sum(ch.isprintable() or ch in "\n\r\t" for ch in s) / max(len(s), 1)
