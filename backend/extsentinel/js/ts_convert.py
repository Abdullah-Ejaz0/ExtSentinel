"""Convert a tree-sitter-javascript syntax tree into ESTree-shaped nodes.

The taint engine is written against ESTree (the standard JavaScript AST
format). tree-sitter produces a concrete syntax tree with its own node names,
so this module maps one onto the other. Only the shape the engine reads is
produced; anything unrecognised becomes an `Unknown` node that the engine
treats as carrying no data.

tree-sitter is error-tolerant: a syntax error yields an ERROR node around the
broken region while the rest of the file still parses. ERROR regions are
converted best-effort (their children are analysed as statements), and the
number of error bytes is reported so the engine can judge coverage.
"""

from __future__ import annotations

import re
from typing import Any

_SKIP = {"comment", "html_comment", "hash_bang_line"}
_LOGICAL = {"&&", "||", "??"}
_FUNCTION_TYPES = {"function_expression", "function", "generator_function"}
_DECLARATION_TYPES = {"lexical_declaration", "variable_declaration", "using_declaration"}


class Pos:
    __slots__ = ("line", "column")

    def __init__(self, line: int, column: int) -> None:
        self.line = line
        self.column = column


class Loc:
    __slots__ = ("start",)

    def __init__(self, start: Pos) -> None:
        self.start = start


class N:
    """Minimal ESTree node. Missing attributes read as None, as optional ESTree fields do."""

    def __init__(self, type: str, src=None, **fields: Any) -> None:
        self.type = type
        if src is not None:
            row, col = _point(src.start_point)
            self.loc = Loc(Pos(row + 1, col))
            self.range = (src.start_byte, src.end_byte)
        else:
            self.loc = None
            self.range = None
        self.__dict__.update(fields)

    def __getattr__(self, name: str) -> Any:  # only called for attributes not set
        if name.startswith("__"):
            raise AttributeError(name)
        return None

    def __repr__(self) -> str:
        return f"N({self.type})"


class TemplateValue:
    __slots__ = ("cooked", "raw")

    def __init__(self, cooked: str | None, raw: str) -> None:
        self.cooked = cooked
        self.raw = raw


def _point(p) -> tuple[int, int]:
    try:
        return p.row, p.column
    except AttributeError:
        return p[0], p[1]


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


_ESCAPE_RE = re.compile(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|\r\n|[\s\S])")
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "\n": "", "\r\n": "", "\u2028": "", "\u2029": ""}


def js_unescape(raw: str) -> str:
    def repl(m: re.Match[str]) -> str:
        esc = m.group(1)
        if esc in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[esc]
        if esc.startswith("u{"):
            cp = int(esc[2:-1], 16)
            return chr(cp) if cp <= 0x10FFFF else "\ufffd"
        if esc.startswith("u") and len(esc) == 5:
            return chr(int(esc[1:], 16))
        if esc.startswith("x") and len(esc) == 3:
            return chr(int(esc[1:], 16))
        if esc[0] in "01234567":
            return chr(int(esc, 8) & 0xFF)
        return esc

    s = _ESCAPE_RE.sub(repl, raw)
    # Join UTF-16 surrogate pairs ("\uD83D\uDE00") and replace lone surrogates.
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _number(text: str) -> float | int | None:
    t = text.replace("_", "")
    if t.endswith("n"):
        t = t[:-1]
    try:
        lower = t.lower()
        if lower.startswith("0x"):
            return int(t[2:], 16)
        if lower.startswith("0o"):
            return int(t[2:], 8)
        if lower.startswith("0b"):
            return int(t[2:], 2)
        if len(t) > 1 and t[0] == "0" and t.isdigit():
            return int(t, 8)  # legacy octal
        value = float(t)
        return int(value) if value.is_integer() and "e" not in lower and "." not in t else value
    except ValueError:
        return None


class Converter:
    def __init__(self) -> None:
        self.error_regions = 0
        self.error_bytes = 0
        self._error_ends: list[int] = []  # end bytes of enclosing ERROR regions (avoid double counting)

    # -- helpers --

    @staticmethod
    def kids(node) -> list:
        return [c for c in node.named_children if c.type not in _SKIP]

    def first_kid(self, node):
        k = self.kids(node)
        return k[0] if k else None

    def note_error(self, node) -> None:
        while self._error_ends and node.start_byte >= self._error_ends[-1]:
            self._error_ends.pop()
        if self._error_ends:  # nested inside an ERROR already counted
            return
        self.error_regions += 1
        self.error_bytes += node.end_byte - node.start_byte
        self._error_ends.append(node.end_byte)

    # -- program / statements --

    def program(self, root) -> N:
        if root.type == "ERROR":
            self.note_error(root)
        return N("Program", root, body=self.stmts(self.kids(root)), sourceType="script")

    def stmts(self, nodes) -> list[N]:
        out: list[N] = []
        for n in nodes:
            s = self.stmt(n)
            if s is None:
                continue
            if isinstance(s, list):
                out.extend(s)
            else:
                out.append(s)
        return out

    def block(self, node) -> N:
        if node is None:
            return N("BlockStatement", body=[])
        if node.type != "statement_block":
            s = self.stmt(node)
            return N("BlockStatement", node, body=s if isinstance(s, list) else ([s] if s else []))
        return N("BlockStatement", node, body=self.stmts(self.kids(node)))

    def stmt(self, n):  # noqa: C901 - one dispatch table reads best as a single method
        if n is None:
            return None
        t = n.type
        f = n.child_by_field_name
        if t == "expression_statement":
            inner = self.first_kid(n)
            return N("ExpressionStatement", n, expression=self.expr(inner)) if inner is not None else None
        if t in _DECLARATION_TYPES:
            return self.var_decl(n)
        if t in ("function_declaration", "generator_function_declaration"):
            name = f("name")
            return N("FunctionDeclaration", n, id=self.ident(name) if name else None,
                     params=self.params(f("parameters")), body=self.block(f("body")))  # fmt: skip
        if t == "class_declaration":
            return self.class_(n, "ClassDeclaration")
        if t == "statement_block":
            return self.block(n)
        if t == "return_statement":
            arg = self.first_kid(n)
            return N("ReturnStatement", n, argument=self.expr(arg) if arg is not None else None)
        if t == "if_statement":
            alt = f("alternative")
            return N("IfStatement", n, test=self.expr(f("condition")), consequent=self.stmt_one(f("consequence")),
                     alternate=self.stmt_one(self.first_kid(alt)) if alt is not None else None)  # fmt: skip
        if t == "for_statement":
            init = f("initializer")
            if init is None or init.type == "empty_statement":
                init_node = None
            elif init.type in _DECLARATION_TYPES:
                init_node = self.var_decl(init)
            else:
                init_node = self.expr(init)
            cond = next((c for c in n.children_by_field_name("condition") if c.is_named and c.type != "empty_statement"), None)
            if cond is not None and cond.type == "expression_statement":
                cond = self.first_kid(cond)
            inc = f("increment")
            return N("ForStatement", n, init=init_node, test=self.expr(cond) if cond is not None else None,
                     update=self.expr(inc) if inc is not None else None, body=self.stmt_one(f("body")))  # fmt: skip
        if t == "for_in_statement":
            left = f("left")
            if n.children_by_field_name("kind"):
                left_node = N("VariableDeclaration", left,
                              declarations=[N("VariableDeclarator", left, id=self.pattern(left), init=None)])  # fmt: skip
            else:
                left_node = self.pattern(left)
            op = f("operator")
            kind = "ForOfStatement" if op is not None and _text(op) == "of" else "ForInStatement"
            return N(kind, n, left=left_node, right=self.expr(f("right")), body=self.stmt_one(f("body")))
        if t == "while_statement":
            return N("WhileStatement", n, test=self.expr(f("condition")), body=self.stmt_one(f("body")))
        if t == "do_statement":
            return N("DoWhileStatement", n, test=self.expr(f("condition")), body=self.stmt_one(f("body")))
        if t == "try_statement":
            handler = f("handler")
            fin = f("finalizer")
            h = None
            if handler is not None:
                param = handler.child_by_field_name("parameter")
                h = N("CatchClause", handler, param=self.pattern(param) if param is not None else None,
                      body=self.block(handler.child_by_field_name("body")))  # fmt: skip
            return N("TryStatement", n, block=self.block(f("body")), handler=h,
                     finalizer=self.block(fin.child_by_field_name("body")) if fin is not None else None)  # fmt: skip
        if t == "switch_statement":
            cases = []
            body = f("body")
            for c in self.kids(body) if body is not None else []:
                test = c.child_by_field_name("value") if c.type == "switch_case" else None
                cases.append(N("SwitchCase", c, test=self.expr(test) if test is not None else None,
                               consequent=self.stmts(c.children_by_field_name("body"))))  # fmt: skip
            return N("SwitchStatement", n, discriminant=self.expr(f("value")), cases=cases)
        if t == "throw_statement":
            return N("ThrowStatement", n, argument=self.expr(self.first_kid(n)))
        if t == "labeled_statement":
            return N("LabeledStatement", n, body=self.stmt_one(f("body")))
        if t == "with_statement":
            return N("WithStatement", n, object=self.expr(f("object")), body=self.stmt_one(f("body")))
        if t == "import_statement":
            return N("ImportDeclaration", n, source=self.literal_string(f("source")))
        if t == "export_statement":
            decl, value, source = f("declaration"), f("value"), f("source")
            if decl is not None:
                return N("ExportNamedDeclaration", n, declaration=self.stmt_one(decl), source=None)
            if value is not None:
                return N("ExportDefaultDeclaration", n, declaration=self.expr(value))
            if source is not None:
                return N("ExportAllDeclaration", n, source=self.literal_string(source))
            return None
        if t in ("break_statement", "continue_statement", "empty_statement", "debugger_statement"):
            return None
        if t == "ERROR":
            self.note_error(n)
            return self.stmts(self.kids(n))
        # Expressions where a statement was expected (error recovery).
        e = self.expr(n)
        return N("ExpressionStatement", n, expression=e) if e.type != "Unknown" else None

    def stmt_one(self, n):
        s = self.stmt(n)
        if isinstance(s, list):
            return N("BlockStatement", n, body=s)
        return s

    def var_decl(self, n) -> N:
        decls = []
        for d in self.kids(n):
            if d.type != "variable_declarator":
                continue
            value = d.child_by_field_name("value")
            decls.append(N("VariableDeclarator", d, id=self.pattern(d.child_by_field_name("name")),
                           init=self.expr(value) if value is not None else None))  # fmt: skip
        return N("VariableDeclaration", n, declarations=decls)

    def class_(self, n, kind: str) -> N:
        name = n.child_by_field_name("name")
        heritage = next((c for c in n.named_children if c.type == "class_heritage"), None)
        sup = self.first_kid(heritage) if heritage is not None else None
        members = []
        body = n.child_by_field_name("body")
        for m in self.kids(body) if body is not None else []:
            if m.type == "method_definition":
                key, computed = self.prop_key(m.child_by_field_name("name"))
                fn = N("FunctionExpression", m, id=None, params=self.params(m.child_by_field_name("parameters")),
                       body=self.block(m.child_by_field_name("body")))  # fmt: skip
                members.append(N("MethodDefinition", m, key=key, computed=computed, value=fn,
                                 static=any(c.type == "static" for c in m.children)))  # fmt: skip
            elif m.type == "field_definition":
                key, computed = self.prop_key(m.child_by_field_name("property"))
                value = m.child_by_field_name("value")
                members.append(N("PropertyDefinition", m, key=key, computed=computed,
                                 value=self.expr(value) if value is not None else None))  # fmt: skip
            elif m.type == "class_static_block":
                members.append(N("StaticBlock", m, body=self.block(m.child_by_field_name("body")).body))
        return N(kind, n, id=self.ident(name) if name is not None else None,
                 superClass=self.expr(sup) if sup is not None else None, body=N("ClassBody", body, body=members))  # fmt: skip

    def params(self, n) -> list[N]:
        if n is None:
            return []
        return [self.pattern(c) for c in self.kids(n)]

    # -- expressions --

    def ident(self, n) -> N:
        return N("Identifier", n, name=_text(n))

    def literal_string(self, n) -> N:
        raw = _text(n)
        inner = raw[1:-1] if len(raw) >= 2 and raw[0] in "'\"" else raw
        return N("Literal", n, value=js_unescape(inner), raw=raw)

    def prop_key(self, n) -> tuple[N, bool]:
        if n is None:
            return N("Unknown"), False
        t = n.type
        if t == "computed_property_name":
            return self.expr(self.first_kid(n)), True
        if t == "string":
            return self.literal_string(n), False
        if t == "number":
            return N("Literal", n, value=_number(_text(n))), False
        return self.ident(n), False

    def template(self, n) -> N:
        quasis: list[N] = []
        exprs: list[N] = []
        raw_parts: list[str] = []
        for c in n.named_children:
            if c.type == "template_substitution":
                raw = "".join(raw_parts)
                quasis.append(N("TemplateElement", c, value=TemplateValue(js_unescape(raw), raw)))
                raw_parts = []
                inner = self.first_kid(c)
                exprs.append(self.expr(inner) if inner is not None else N("Unknown"))
            elif c.type in ("string_fragment", "escape_sequence"):
                raw_parts.append(_text(c))
        raw = "".join(raw_parts)
        quasis.append(N("TemplateElement", n, value=TemplateValue(js_unescape(raw), raw)))
        return N("TemplateLiteral", n, quasis=quasis, expressions=exprs)

    def function(self, n, kind: str) -> N:
        f = n.child_by_field_name
        if kind == "ArrowFunctionExpression":
            single = f("parameter")
            params = [self.pattern(single)] if single is not None else self.params(f("parameters"))
            body = f("body")
            body_node = self.block(body) if body is not None and body.type == "statement_block" else self.expr(body)
            return N(kind, n, id=None, params=params, body=body_node, expression=body_node.type != "BlockStatement")
        return N(kind, n, id=None, params=self.params(f("parameters")), body=self.block(f("body")))

    def expr(self, n) -> N:  # noqa: C901
        if n is None:
            return N("Unknown")
        t = n.type
        f = n.child_by_field_name
        if t in ("identifier", "property_identifier", "shorthand_property_identifier", "private_property_identifier",
                 "shorthand_property_identifier_pattern", "statement_identifier", "meta_property"):  # fmt: skip
            return self.ident(n)
        if t == "undefined":
            return N("Identifier", n, name="undefined")
        if t == "this":
            return N("ThisExpression", n)
        if t == "super":
            return N("Identifier", n, name="super")
        if t == "string":
            return self.literal_string(n)
        if t == "number":
            return N("Literal", n, value=_number(_text(n)))
        if t in ("true", "false"):
            return N("Literal", n, value=t == "true")
        if t == "null":
            return N("Literal", n, value=None)
        if t == "regex":
            return N("Literal", n, value=None, regex=True)
        if t == "template_string":
            return self.template(n)
        if t == "parenthesized_expression":
            return self.expr(self.first_kid(n))
        if t == "member_expression":
            prop = f("property")
            return N("MemberExpression", n, object=self.expr(f("object")),
                     property=self.ident(prop) if prop is not None else N("Unknown"), computed=False)  # fmt: skip
        if t == "subscript_expression":
            return N("MemberExpression", n, object=self.expr(f("object")), property=self.expr(f("index")), computed=True)
        if t == "call_expression":
            fn, args = f("function"), f("arguments")
            callee = N("Import", fn) if fn is not None and fn.type == "import" else self.expr(fn)
            if args is not None and args.type == "template_string":
                return N("TaggedTemplateExpression", n, tag=callee, quasi=self.template(args))
            return N("CallExpression", n, callee=callee, arguments=[self.expr(a) for a in self.kids(args)] if args is not None else [])
        if t == "new_expression":
            args = f("arguments")
            return N("NewExpression", n, callee=self.expr(f("constructor")),
                     arguments=[self.expr(a) for a in self.kids(args)] if args is not None else [])  # fmt: skip
        if t == "assignment_expression":
            return N("AssignmentExpression", n, operator="=", left=self.pattern(f("left")), right=self.expr(f("right")))
        if t == "augmented_assignment_expression":
            return N("AssignmentExpression", n, operator=_text(f("operator")), left=self.pattern(f("left")), right=self.expr(f("right")))
        if t == "binary_expression":
            op = _text(f("operator"))
            return N("LogicalExpression" if op in _LOGICAL else "BinaryExpression", n, operator=op,
                     left=self.expr(f("left")), right=self.expr(f("right")))  # fmt: skip
        if t == "unary_expression":
            return N("UnaryExpression", n, operator=_text(f("operator")), argument=self.expr(f("argument")))
        if t == "update_expression":
            return N("UpdateExpression", n, operator=_text(f("operator")), argument=self.expr(f("argument")))
        if t == "ternary_expression":
            return N("ConditionalExpression", n, test=self.expr(f("condition")),
                     consequent=self.expr(f("consequence")), alternate=self.expr(f("alternative")))  # fmt: skip
        if t == "sequence_expression":
            return N("SequenceExpression", n, expressions=[self.expr(c) for c in self.kids(n)])
        if t == "object":
            return N("ObjectExpression", n, properties=[self.object_member(c) for c in self.kids(n)])
        if t == "array":
            return N("ArrayExpression", n, elements=[self.expr(c) for c in self.kids(n)])
        if t == "spread_element":
            return N("SpreadElement", n, argument=self.expr(self.first_kid(n)))
        if t == "await_expression":
            return N("AwaitExpression", n, argument=self.expr(self.first_kid(n)))
        if t == "yield_expression":
            return N("YieldExpression", n, argument=self.expr(self.first_kid(n)))
        if t == "arrow_function":
            return self.function(n, "ArrowFunctionExpression")
        if t in _FUNCTION_TYPES:
            return self.function(n, "FunctionExpression")
        if t == "class":
            return self.class_(n, "ClassExpression")
        if t == "import":
            return N("Import", n)
        if t == "ERROR":
            self.note_error(n)
            exprs = [self.expr(c) for c in self.kids(n)]
            exprs = [e for e in exprs if e.type != "Unknown"]
            return N("SequenceExpression", n, expressions=exprs) if exprs else N("Unknown", n)
        return N("Unknown", n)

    def object_member(self, c) -> N:
        t = c.type
        if t == "pair":
            key, computed = self.prop_key(c.child_by_field_name("key"))
            return N("Property", c, key=key, value=self.expr(c.child_by_field_name("value")), computed=computed, shorthand=False)
        if t == "shorthand_property_identifier":
            ident = self.ident(c)
            return N("Property", c, key=ident, value=self.ident(c), computed=False, shorthand=True)
        if t == "method_definition":
            key, computed = self.prop_key(c.child_by_field_name("name"))
            fn = N("FunctionExpression", c, id=None, params=self.params(c.child_by_field_name("parameters")),
                   body=self.block(c.child_by_field_name("body")))  # fmt: skip
            return N("Property", c, key=key, value=fn, computed=computed, method=True)
        if t == "spread_element":
            return N("SpreadElement", c, argument=self.expr(self.first_kid(c)))
        return N("SpreadElement", c, argument=self.expr(c))

    # -- patterns --

    def pattern(self, n) -> N:  # noqa: C901
        if n is None:
            return N("Unknown")
        t = n.type
        f = n.child_by_field_name
        if t in ("identifier", "shorthand_property_identifier_pattern", "undefined"):
            return N("Identifier", n, name=_text(n))
        if t == "object_pattern":
            props = []
            for c in self.kids(n):
                ct = c.type
                if ct == "pair_pattern":
                    key, computed = self.prop_key(c.child_by_field_name("key"))
                    props.append(N("Property", c, key=key, value=self.pattern(c.child_by_field_name("value")), computed=computed))
                elif ct == "shorthand_property_identifier_pattern":
                    props.append(N("Property", c, key=self.ident(c), value=self.ident(c), computed=False, shorthand=True))
                elif ct == "object_assignment_pattern":
                    left = c.child_by_field_name("left")
                    target = self.pattern(left)
                    key = self.ident(left) if left is not None and left.type == "shorthand_property_identifier_pattern" else target
                    value = N("AssignmentPattern", c, left=target, right=self.expr(c.child_by_field_name("right")))
                    props.append(N("Property", c, key=key, value=value, computed=False, shorthand=True))
                elif ct == "rest_pattern":
                    props.append(N("RestElement", c, argument=self.pattern(self.first_kid(c))))
            return N("ObjectPattern", n, properties=props)
        if t == "array_pattern":
            return N("ArrayPattern", n, elements=[self.pattern(c) for c in self.kids(n)])
        if t == "assignment_pattern":
            return N("AssignmentPattern", n, left=self.pattern(f("left")), right=self.expr(f("right")))
        if t == "rest_pattern":
            return N("RestElement", n, argument=self.pattern(self.first_kid(n)))
        if t == "parenthesized_expression":
            return self.pattern(self.first_kid(n))
        return self.expr(n)  # member/subscript expressions and anything else


def convert(root) -> tuple[N, int, int]:
    """Return (ESTree Program, number of error regions, bytes inside error regions)."""
    conv = Converter()
    program = conv.program(root)
    return program, conv.error_regions, conv.error_bytes
