"""Recognise well-known third-party libraries from their license banners.

Libraries such as lodash legitimately use `Function(...)`; recognising them
avoids blaming the extension for vendor code. A banner is trivially forged,
so recognition only *lowers* severity of code-execution findings by one step
and never suppresses data-flow findings. The report says so explicitly.
"""

from __future__ import annotations

import re

_BANNERS: list[tuple[str, re.Pattern[str]]] = [
    ("jQuery", re.compile(r"jQuery (?:JavaScript Library )?v?\d", re.I)),
    ("React", re.compile(r"@license React|react(?:-dom)?\.production\.min\.js")),
    ("Vue", re.compile(r"Vue\.js v\d")),
    ("Angular", re.compile(r"@license Angular")),
    ("lodash", re.compile(r"@license\s+Lodash|lodash\.com", re.I)),
    ("Underscore", re.compile(r"Underscore\.js \d")),
    ("Moment.js", re.compile(r"moment\.js|momentjs\.com")),
    ("Bootstrap", re.compile(r"Bootstrap v\d")),
    ("axios", re.compile(r"axios v\d")),
    ("DOMPurify", re.compile(r"DOMPurify")),
    ("webextension-polyfill", re.compile(r"webextension-polyfill")),
    ("core-js", re.compile(r"core-js")),
    ("Chart.js", re.compile(r"Chart\.js v\d")),
    ("Firebase", re.compile(r"@license\s+Copyright \d{4} Google LLC|firebase", re.I)),
    ("Sentry", re.compile(r"@sentry/")),
    ("highlight.js", re.compile(r"Highlight\.js v\d", re.I)),
    ("pdf.js", re.compile(r"pdfjsLib|Mozilla Foundation.*pdf\.js", re.I | re.S)),
]


def detect_library(path: str, text: str) -> str | None:
    head = text[:3000]
    for name, rx in _BANNERS:
        if rx.search(head):
            return name
    return None
