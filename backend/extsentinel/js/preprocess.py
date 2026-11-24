"""Rewrite post-ES2017 syntax into a form esprima (ES2017) can parse.

The rewrite only has to be good enough for *analysis*: data flow through
`a?.b` is the same as through `a.b`, `a ?? b` propagates taint like `a || b`,
and `await x` carries the same data as `x`. Every newline is preserved, so
line numbers in the rewritten source match the original file. Strings,
comments and template text are copied verbatim.

Handled: optional chaining, nullish coalescing, logical assignment, optional
catch binding, `for await`, top-level/any `await`, numeric separators, BigInt
literals, private names (`#x` -> `_x`), class fields (`x = v;` ->
`x(){return v;}`), static blocks, shebang lines, and regex literals (bodies
are replaced by a placeholder because esprima validates them with Python's
`re`, which rejects valid JS such as `\\p{L}`; regex contents carry no data
flow).
"""

from __future__ import annotations

import re

_IDENT_RE = re.compile(r"[A-Za-z_$\u0080-￿][\w$\u0080-￿]*")
_NUM_RE = re.compile(
    r"0[xX][0-9a-fA-F_]+n?|0[oO][0-7_]+n?|0[bB][01_]+n?"
    r"|\d[\d_]*(?:\.[\d_]*)?(?:[eE][+-]?\d[\d_]*)?n?"
    r"|\.\d[\d_]*(?:[eE][+-]?\d[\d_]*)?"
)
_WS_RE = re.compile(r"\s*")
_FIELD_INIT_RE = re.compile(r"[ \t]*=(?![=>])")
_FIELD_BARE_RE = re.compile(r"[ \t]*(?:;|\n|\r|\})")
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
_KEYWORDS_BEFORE_EXPR = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
}  # fmt: skip
_MEMBER_MODIFIERS = {"static", "get", "set", "async", "accessor"}
_ASI_BLOCKERS = set("=+-*/%&|^!?:,(.[{<>~")


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch in "_$" or ord(ch) > 127


def _skip_string(src: str, i: int, quote: str) -> int:
    j, n = i + 1, len(src)
    while j < n:
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == quote or ch == "\n":
            return j + 1 if ch == quote else j
        j += 1
    return n


def _scan_template(src: str, j: int) -> tuple[int, bool]:
    """Scan template text from j. Returns (index after stop, closed?) where
    closed=False means we stopped just after a `${`."""
    n = len(src)
    while j < n:
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "`":
            return j + 1, True
        if ch == "$" and j + 1 < n and src[j + 1] == "{":
            return j + 2, False
        j += 1
    return n, True


def _skip_regex(src: str, i: int) -> tuple[int, int] | None:
    """Return (end_of_body, end_of_flags) for a regex literal at i, or None."""
    j, n, in_class = i + 1, len(src), False
    while j < n:
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return None
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            body_end = j + 1
            k = body_end
            while k < n and src[k].isalpha():
                k += 1
            return body_end, k
        j += 1
    return None


def downlevel(src: str) -> str:  # noqa: C901 - a single-pass scanner is clearest as one loop
    out: list[str] = []
    n = len(src)
    i = 0
    if src.startswith("#!"):
        out.append("//")
        i = 2
    last_sig = ""  # last significant char of code we emitted
    last_word = ""
    brace_depth = 0
    template_stack: list[int] = []
    paren_depth = 0  # ( and [ nesting, so parameter defaults are not mistaken for fields
    class_stack: list[tuple[int, int]] = []  # (brace depth inside the class body, paren depth there)
    pending_class = False
    open_field_depth: int | None = None  # class-body depth of a field whose `}` is still owed

    def close_field() -> None:
        nonlocal open_field_depth
        out.append("}")
        open_field_depth = None

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        in_class_body = bool(class_stack) and class_stack[-1] == (brace_depth, paren_depth)

        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(src[i:j])
            i = j
            continue
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j])
            i = j
            continue
        if c in "'\"":
            j = _skip_string(src, i, c)
            out.append(src[i:j])
            i, last_sig, last_word = j, c, ""
            continue
        if c == "`":
            j, closed = _scan_template(src, i + 1)
            out.append(src[i:j])
            i, last_sig, last_word = j, "`", ""
            if not closed:
                template_stack.append(brace_depth)
                last_sig = "{"
            continue
        if c == "/":
            if last_sig == "" or last_sig in _REGEX_PRECEDERS or last_word in _KEYWORDS_BEFORE_EXPR:
                span = _skip_regex(src, i)
                if span is not None:
                    _, flags_end = span
                    out.append("/x/")
                    i, last_sig, last_word = flags_end, ")", ""
                    continue
        if c == "\n" and open_field_depth is not None and brace_depth == open_field_depth and last_sig not in _ASI_BLOCKERS:
            close_field()  # field initializer ended by automatic semicolon insertion
        if (c.isdigit() or (c == "." and nxt.isdigit())) and not (i > 0 and _is_ident_char(src[i - 1])):
            m = _NUM_RE.match(src, i)
            if m:
                tok = m.group().replace("_", "")
                if tok.endswith("n"):
                    tok = tok[:-1]
                out.append(tok)
                i, last_sig, last_word = m.end(), "0", ""
                continue
        if c == "#" and nxt and _is_ident_char(nxt):
            # Private name: treat as a normal identifier (handled below as `_name`).
            m = _IDENT_RE.match(src, i + 1)
            if m:
                word, end = "_" + m.group(), m.end()
                if in_class_body and open_field_depth is None and last_sig != ".":
                    init = _FIELD_INIT_RE.match(src, end)
                    if _emit_field(out, src, end, word):
                        if init:
                            open_field_depth = brace_depth
                            i, last_sig, last_word = init.end(), "{", "return"
                        else:
                            i, last_sig, last_word = end, "}", ""
                        continue
                out.append(word)
                i, last_sig, last_word = end, "a", word
                continue
        if _is_ident_char(c) and not c.isdigit():
            m = _IDENT_RE.match(src, i)
            if m:
                word = m.group()
                end = m.end()
                after_dot = last_sig == "."
                if word == "catch" and not after_dot:
                    ws = _WS_RE.match(src, end)
                    if ws and ws.end() < n and src[ws.end()] == "{":
                        out.append("catch(__es_err)")
                        i, last_sig, last_word = end, ")", ""
                        continue
                if word == "for":
                    ws = _WS_RE.match(src, end)
                    if ws and src.startswith("await", ws.end()):
                        out.append("for")
                        out.append(src[end : ws.end()])
                        i, last_sig, last_word = ws.end() + len("await"), "a", "for"
                        continue
                if word == "await" and not after_dot and end < n and (src[end].isspace() or src[end] in "([`'\""):
                    i = end  # `await x` carries the same data as `x`
                    continue
                if word == "class" and not after_dot and not re.match(r"\s*:", src[end : end + 3]):
                    pending_class = True
                if in_class_body and not after_dot:
                    if word == "static":
                        ws = _WS_RE.match(src, end)
                        if ws and ws.end() < n and src[ws.end()] == "{":
                            out.append("static __es_static()")  # static initialization block
                            i, last_sig, last_word = end, ")", ""
                            continue
                    if open_field_depth is None and word not in _MEMBER_MODIFIERS and _emit_field(out, src, end, word):
                        init = _FIELD_INIT_RE.match(src, end)
                        if init:
                            open_field_depth = brace_depth
                            i = init.end()
                            last_sig, last_word = "{", "return"
                        else:
                            i = end
                            last_sig, last_word = "}", ""
                        continue
                out.append(word)
                i, last_sig, last_word = end, "a", word
                continue
        if c == "?":
            if nxt == "." and not (i + 2 < n and src[i + 2].isdigit()):
                after = src[i + 2] if i + 2 < n else ""
                out.append("" if after in "([" else ".")
                i, last_sig, last_word = i + 2, ".", ""
                continue
            if src.startswith("??=", i):
                out.append("=")
                i, last_sig, last_word = i + 3, "=", ""
                continue
            if nxt == "?":
                out.append("||")
                i, last_sig, last_word = i + 2, "|", ""
                continue
        if src.startswith("||=", i) or src.startswith("&&=", i):
            out.append("=")
            i, last_sig, last_word = i + 3, "=", ""
            continue
        if c == ";" and open_field_depth is not None and brace_depth == open_field_depth:
            out.append(";")
            close_field()
            i, last_sig, last_word = i + 1, ";", ""
            continue
        if c in "([":
            paren_depth += 1
        elif c in ")]":
            paren_depth = max(0, paren_depth - 1)
            if c == "]" and open_field_depth is None and class_stack and class_stack[-1] == (brace_depth, paren_depth):
                init = _FIELD_INIT_RE.match(src, i + 1)
                if init:  # computed class field: [key] = value
                    out.append("](){return ")
                    open_field_depth = brace_depth
                    i, last_sig, last_word = init.end(), "{", "return"
                    continue
                if _FIELD_BARE_RE.match(src, i + 1):  # computed class field without initializer: [key];
                    out.append("](){}")
                    i, last_sig, last_word = i + 1, "}", ""
                    continue
        if c == "{":
            brace_depth += 1
            if pending_class:
                class_stack.append((brace_depth, paren_depth))
                pending_class = False
        elif c == "}":
            if template_stack and template_stack[-1] == brace_depth:
                template_stack.pop()
                j, closed = _scan_template(src, i + 1)
                out.append(src[i:j])
                i, last_sig, last_word = j, "`", ""
                if not closed:
                    template_stack.append(brace_depth)
                    last_sig = "{"
                continue
            if class_stack and class_stack[-1] == (brace_depth, paren_depth):
                if open_field_depth is not None:
                    close_field()
                class_stack.pop()
            brace_depth -= 1
        out.append(c)
        if not c.isspace():
            last_sig, last_word = c, ""
        i += 1
    return "".join(out)


def _emit_field(out: list[str], src: str, end: int, name: str) -> bool:
    """If `name` at class-body level starts a field declaration, emit its method form."""
    if _FIELD_INIT_RE.match(src, end):
        out.append(f"{name}(){{return ")
        return True
    if _FIELD_BARE_RE.match(src, end):
        out.append(f"{name}(){{}}")
        return True
    return False
