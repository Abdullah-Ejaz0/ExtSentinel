"""Parse JavaScript into an ESTree-shaped syntax tree.

Primary parser: tree-sitter (C library, fast, full modern syntax, recovers
from syntax errors so one broken region does not hide the rest of a file).
Its concrete syntax tree is converted to ESTree by ts_convert.py.

Fallback parser: esprima (pure Python, ES2017 plus the rewrites in
preprocess.py). Used only when tree-sitter cannot be loaded, e.g. where
Windows Application Control blocks its compiled module, or when explicitly
selected with EXTSENTINEL_PARSER=esprima.
"""

from __future__ import annotations

import re
import sys
import threading
import warnings
from dataclasses import dataclass
from typing import Any

from .preprocess import downlevel

# Both converters recurse over the tree; deeply nested (minified/obfuscated) code needs headroom.
# Python 3.11+ does not consume C stack for pure-Python recursion, so this is safe.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 20_000))

_MODULE_HINT = re.compile(r"^\s*(?:import\s*[\w{*'\"]|export\s)", re.M)
# A file counts as unparseable if more than this share of it sits inside tree-sitter ERROR regions.
MAX_ERROR_SHARE = 0.5


@dataclass
class ParseResult:
    ast: Any | None
    parser: str
    error: str | None = None  # failure reason, or a note about recovered syntax errors
    syntax_errors: int = 0


# --- tree-sitter -----------------------------------------------------------------

_ts_language = None
_ts_import_error: str | None = None
_ts_local = threading.local()  # tree-sitter Parser objects must not be shared across threads

try:
    import tree_sitter
    import tree_sitter_javascript

    _ts_language = tree_sitter.Language(tree_sitter_javascript.language())
except Exception as exc:  # ImportError, or OSError when the compiled module is blocked
    _ts_import_error = f"{type(exc).__name__}: {exc}"


def tree_sitter_available() -> bool:
    return _ts_language is not None


def tree_sitter_unavailable_reason() -> str | None:
    return _ts_import_error


def _ts_parser():
    parser = getattr(_ts_local, "parser", None)
    if parser is None:
        parser = tree_sitter.Parser(_ts_language)
        _ts_local.parser = parser
    return parser


def parse_tree_sitter(source: str) -> ParseResult:
    from .ts_convert import convert

    data = source.encode("utf-8", errors="replace")
    tree = _ts_parser().parse(data)
    try:
        ast, regions, error_bytes = convert(tree.root_node)
    except RecursionError:
        return ParseResult(ast=None, parser="tree-sitter", error="nesting too deep to convert")
    if data and error_bytes / len(data) > MAX_ERROR_SHARE:
        return ParseResult(ast=None, parser="tree-sitter", syntax_errors=regions,
                           error=f"{error_bytes * 100 // len(data)}% of the file is not valid JavaScript")  # fmt: skip
    note = f"{regions} syntax error region(s) skipped by tree-sitter error recovery" if regions else None
    return ParseResult(ast=ast, parser="tree-sitter", error=note, syntax_errors=regions)


# --- esprima ---------------------------------------------------------------------


def _esprima(source: str, module: bool) -> Any:
    import esprima

    opts = {"loc": True, "range": True}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # esprima compiles JS regexes with Python's re and warns on syntax differences
        return esprima.parseModule(source, opts) if module else esprima.parseScript(source, opts)


def parse_esprima(source: str) -> ParseResult:
    module_first = bool(_MODULE_HINT.search(source))
    order = (True, False) if module_first else (False, True)
    last_error: str | None = None
    # The rewritten form is plain ES2017, so try it first; raw is the fallback in case the rewrite
    # damaged an unusual construct.
    for rewritten in (True, False):
        text = downlevel(source) if rewritten else source
        for module in order:
            try:
                return ParseResult(ast=_esprima(text, module), parser="esprima")
            except RecursionError:
                return ParseResult(ast=None, parser="esprima", error="nesting too deep to parse")
            except Exception as exc:  # esprima raises its own Error subclasses
                if rewritten and (last_error is None or module == order[0]):
                    col = getattr(exc, "column", None)
                    last_error = f"{exc}" + (f" (col {col})" if col else "")
    return ParseResult(ast=None, parser="esprima", error=last_error)


# --- selection -------------------------------------------------------------------

BACKENDS = ("auto", "tree-sitter", "esprima")


def resolve_backend(preference: str) -> str:
    if preference not in BACKENDS:
        raise ValueError(f"parser must be one of {BACKENDS}")
    if preference == "auto":
        return "tree-sitter" if tree_sitter_available() else "esprima"
    if preference == "tree-sitter" and not tree_sitter_available():
        raise RuntimeError(f"tree-sitter was requested but cannot be loaded ({_ts_import_error})")
    return preference


def parse(source: str, backend: str = "auto") -> ParseResult:
    backend = resolve_backend(backend)
    return parse_tree_sitter(source) if backend == "tree-sitter" else parse_esprima(source)
