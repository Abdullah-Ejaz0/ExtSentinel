"""Static taint analysis over an ESTree syntax tree.

The question this answers is not "does the code mention document.cookie?" but
"does a value read from document.cookie actually reach fetch()?". Every
behavioural finding produced from this module is backed by a concrete trace
(source location -> ... -> sink location).

Design (deliberately simple, so it is predictable and explainable):

* Abstract values (`Val`) carry a set of taint labels, each with the trace of
  where it was introduced, plus object "kinds" (keyboard event, XHR, script
  element, ...), a folded constant string if known, and the global API path
  (e.g. "chrome.cookies.getAll") the value refers to.
* Flow-insensitive, monotone: variables only accumulate taint (weak updates),
  objects are field-insensitive. The file is re-walked until nothing changes
  (bounded), which guarantees termination.
* Function summaries are context-insensitive: parameters accumulate the union
  of all argument values; call results are the union of return values.
* Callbacks registered with browser APIs get their parameters seeded with the
  right labels (e.g. keydown handler -> event whose `.key` is KEYSTROKES).
* Comparisons and boolean operators produce *untainted* results. This is what
  separates a shortcut handler (`if (e.key === "k")`) from a keylogger
  (`buffer += e.key`). Implicit flows through branches are not tracked; this
  is a documented limitation.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from . import catalog as C


class BudgetExceeded(Exception):
    pass


@dataclass(frozen=True)
class Step:
    file: str
    line: int
    col: int
    pos: int
    note: str


Trace = tuple[Step, ...]
MAX_TRACE = 6


class Val:
    __slots__ = ("taint", "kinds", "const", "prefix", "path", "props", "items", "funcs")

    def __init__(
        self,
        taint: dict[str, Trace] | None = None,
        kinds: frozenset[str] = frozenset(),
        const: str | None = None,
        prefix: str | None = None,
        path: str | None = None,
        props: dict[str, "Val"] | None = None,
        items: list["Val"] | None = None,
        funcs: frozenset[int] = frozenset(),
    ) -> None:
        self.taint = taint if taint is not None else {}
        self.kinds = kinds
        self.const = const
        self.prefix = prefix
        self.path = path
        self.props = props
        self.items = items
        self.funcs = funcs

    def labels(self) -> set[str]:
        return set(self.taint)


EMPTY = Val()


def union(*vals: Val | None) -> Val:
    """Taint/kind/function union. Constant and path information is dropped."""
    taint: dict[str, Trace] = {}
    kinds: set[str] = set()
    funcs: set[int] = set()
    for v in vals:
        if v is None:
            continue
        for lab, tr in v.taint.items():
            taint.setdefault(lab, tr)
        kinds |= v.kinds
        funcs |= v.funcs
    return Val(taint, frozenset(kinds), funcs=frozenset(funcs))


def taint_of(*vals: Val | None) -> Val:
    taint: dict[str, Trace] = {}
    for v in vals:
        if v is not None:
            for lab, tr in v.taint.items():
                taint.setdefault(lab, tr)
    return Val(taint)


def add_label(v: Val, label: str, step: Step) -> Val:
    if label in v.taint:
        return v
    taint = dict(v.taint)
    taint[label] = (step,)
    return Val(taint, v.kinds, v.const, v.prefix, v.path, v.props, v.items, v.funcs)


def extend_trace(v: Val, step: Step) -> Val:
    return Val({lab: (tr + (step,))[:MAX_TRACE] for lab, tr in v.taint.items()})


def merge(old: Val | None, new: Val) -> Val:
    """Weak update used for variables and function parameters."""
    if old is None:
        return new
    taint = dict(old.taint)
    for lab, tr in new.taint.items():
        taint.setdefault(lab, tr)
    return Val(
        taint,
        old.kinds | new.kinds,
        old.const if old.const == new.const else None,
        old.prefix if old.prefix == new.prefix else None,
        old.path or new.path,
        old.props or new.props,
        old.items or new.items,
        old.funcs | new.funcs,
    )


def grew(old: Val | None, new: Val) -> bool:
    if old is None:
        return bool(new.taint or new.kinds or new.funcs or new.path or new.const is not None)
    return (
        len(new.taint) > len(old.taint)
        or len(new.kinds) > len(old.kinds)
        or len(new.funcs) > len(old.funcs)
        or (new.path is not None and old.path is None)
    )


# --- Results -------------------------------------------------------------------


@dataclass
class Flow:
    sink: str  # network | message | page_leak
    step: Step
    labels: dict[str, Trace]
    destination: str | None  # URL or URL prefix when statically known
    navigation: bool = False  # opens/navigates a tab rather than sending a background request
    dest_extension: bool = False  # destination is a page inside the extension itself


@dataclass
class CodeExec:
    kind: str  # eval | function | timer_string | script_src | script_text | import_scripts | ...
    step: Step
    const: str | None
    prefix: str | None
    labels: dict[str, Trace]
    is_extension_url: bool = False


@dataclass
class Listener:
    event: str  # keyboard | input | submit | paste | page_message
    step: Step


@dataclass
class FileAnalysis:
    path: str
    parsed: bool
    parse_error: str | None = None
    flows: list[Flow] = field(default_factory=list)
    code_execs: list[CodeExec] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    capabilities: dict[str, list[Step]] = field(default_factory=dict)  # API path -> sites
    sensitive_reads: dict[str, list[Step]] = field(default_factory=dict)  # label -> sites
    message_sends: list[tuple[Step, Val]] = field(default_factory=list)
    injected_files: set[str] = field(default_factory=set)  # executeScript files / registered content scripts
    imported_files: set[str] = field(default_factory=set)  # importScripts / ES imports (same context)
    injected_ranges: list[tuple[int, int]] = field(default_factory=list)  # functions passed to executeScript({func})
    network_destinations: list[tuple[str | None, Step]] = field(default_factory=list)
    partial: bool = False


# --- Scopes and functions ------------------------------------------------------


class Scope:
    __slots__ = ("vars", "parent")

    def __init__(self, parent: "Scope | None" = None) -> None:
        self.vars: dict[str, Val] = {}
        self.parent = parent

    def lookup(self, name: str) -> Val | None:
        s: Scope | None = self
        while s is not None:
            v = s.vars.get(name)
            if v is not None:
                return v
            s = s.parent
        return None

    def owner(self, name: str) -> "Scope | None":
        s: Scope | None = self
        while s is not None:
            if name in s.vars:
                return s
            s = s.parent
        return None


class FuncInfo:
    __slots__ = ("node", "scope", "params", "ret", "fid", "this_key")

    def __init__(self, node, closure: Scope, this_key: str) -> None:
        self.node = node
        self.fid = id(node)
        self.scope = Scope(closure)
        self.params: list[Val] = [EMPTY] * len(node.params or [])
        self.ret: Val = EMPTY
        self.this_key = this_key  # pseudo-variable holding (field-insensitive) `this`


# Receivers that are platform APIs; calls on them never dispatch to user methods by name.
_MAX_DISPATCH = 8
_API_ROOTS = {"chrome", "document", "navigator", "console", "JSON", "Math", "Object", "Array", "Promise",
              "Reflect", "String", "Number", "Date", "localStorage", "sessionStorage", "location", "history", "$"}


_URL_PASSTHROUGH = {"href", "toString", "toJSON", "origin", "searchParams"}
_STORAGE_RE = re.compile(r"^chrome\.storage\.(?:local|sync|session|managed)\.(get|set)$")
_CAPABILITY_PREFIXES = ("chrome.", "navigator.clipboard", "navigator.geolocation", "document.execCommand")
_URL_RE = re.compile(r"^(?:https?|wss?):\/\/[^\s\"'<>]+$", re.I)
_PASSWORD_RE = re.compile(r"password", re.I)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def _is_remote_url(s: str | None) -> bool:
    if not s:
        return False
    s = s.strip().lower()
    return s.startswith(("http://", "https://", "//", "ws://", "wss://"))


def url_host(url: str | None) -> str | None:
    if not url:
        return None
    u = url.strip()
    if u.startswith("//"):
        u = "https:" + u
    try:
        host = urlparse(u).hostname
    except ValueError:
        return None
    return host


# --- Analyzer ------------------------------------------------------------------


class FileAnalyzer:
    def __init__(
        self,
        path: str,
        ast,
        incoming_messages: Val | None = None,
        max_rounds: int = 5,
        node_budget: int = 3_000_000,
    ) -> None:
        self.path = path
        self.ast = ast
        self.incoming = incoming_messages or EMPTY
        self.max_rounds = max_rounds
        self.node_budget = node_budget
        self.visits = 0

        self.global_scope = Scope()
        self.scope = self.global_scope
        self.func_stack: list[FuncInfo] = []
        self.funcs: dict[int, FuncInfo] = {}
        self.methods: dict[str, set[int]] = {}  # method name -> user functions (name-based dispatch)
        self.class_this: str | None = None  # set while defining methods of a class
        self.analyzed: set[int] = set()
        self.in_progress: set[int] = set()
        self.reanalysis: dict[int, int] = {}
        self.changed = False
        self.last_xhr_dest: Val | None = None

        self.result = FileAnalysis(path=path, parsed=True)
        self._flow_index: dict[tuple[int, str], Flow] = {}
        self._exec_index: dict[tuple[int, str], CodeExec] = {}
        self._seen_sites: set[tuple[str, int]] = set()

    # -- driver --

    def run(self) -> FileAnalysis:
        try:
            for _ in range(self.max_rounds):
                self.changed = False
                self.analyzed = set()
                self.reanalysis = {}
                self.scope = self.global_scope
                self.block(self.ast.body)
                if not self.changed:
                    break
        except BudgetExceeded:
            self.result.partial = True
        except RecursionError:
            self.result.partial = True
        return self.result

    # -- helpers --

    def step(self, node, note: str) -> Step:
        loc = getattr(node, "loc", None)
        rng = getattr(node, "range", None) or (0, 0)
        if loc is None:
            return Step(self.path, 0, 0, rng[0], note)
        return Step(self.path, loc.start.line, loc.start.column, rng[0], note)

    def _site_once(self, kind: str, node) -> bool:
        key = (kind, (getattr(node, "range", None) or (0,))[0])
        if key in self._seen_sites:
            return False
        self._seen_sites.add(key)
        return True

    def capability(self, path: str, node) -> None:
        if self._site_once("cap:" + path, node):
            sites = self.result.capabilities.setdefault(path, [])
            if len(sites) < 5:
                sites.append(self.step(node, f"uses {path}"))

    def sensitive_read(self, label: str, step: Step) -> None:
        sites = self.result.sensitive_reads.setdefault(label, [])
        if len(sites) < 5 and step not in sites:
            sites.append(step)

    def source(self, v: Val, label: str, node, note: str) -> Val:
        st = self.step(node, f"source: {note}")
        self.sensitive_read(label, st)
        return add_label(v, label, st)

    def sink(self, kind: str, node, val: Val, note: str, dest: Val | None = None, navigation: bool = False) -> None:
        destination = None
        if dest is not None:
            destination = dest.const if dest.const is not None else dest.prefix
        if kind == "network" and self._site_once("net", node):
            self.result.network_destinations.append((destination, self.step(node, note)))
        if not val.taint:
            return
        key = ((getattr(node, "range", None) or (0,))[0], kind)
        flow = self._flow_index.get(key)
        if flow is None:
            flow = Flow(kind, self.step(node, f"sink: {note}"), {}, destination, navigation,
                        dest is not None and "ext_url" in dest.kinds)
            self._flow_index[key] = flow
            self.result.flows.append(flow)
        for lab, tr in val.taint.items():
            flow.labels.setdefault(lab, tr)
        if kind == "message":
            self.result.message_sends.append((flow.step, val))

    def code_exec(self, kind: str, node, val: Val, note: str) -> None:
        key = ((getattr(node, "range", None) or (0,))[0], kind)
        ce = self._exec_index.get(key)
        if ce is None:
            ce = CodeExec(kind, self.step(node, note), val.const, val.prefix, {}, "ext_url" in val.kinds)
            self._exec_index[key] = ce
            self.result.code_execs.append(ce)
        elif ce.const != val.const:
            ce.const = None
        for lab, tr in val.taint.items():
            ce.labels.setdefault(lab, tr)

    def tick(self) -> None:
        self.visits += 1
        if self.visits > self.node_budget:
            raise BudgetExceeded

    # -- variables --

    def assign_name(self, name: str, val: Val, declare: bool = False) -> None:
        target = self.scope if declare else (self.scope.owner(name) or self.global_scope)
        old = target.vars.get(name)
        new = merge(old, val)
        if grew(old, new):
            self.changed = True
        target.vars[name] = new

    def weak_update_root(self, node, val: Val) -> None:
        """`obj.a.b = x` / `arr.push(x)`: taint flows into the root variable (field-insensitive)."""
        if not val.taint:
            return
        while node is not None and node.type == "MemberExpression":
            node = node.object
        if node is not None and node.type == "Identifier":
            self.assign_name(node.name, taint_of(val))
        elif node is not None and node.type == "ThisExpression":
            self.merge_this(self.this_key(), val)

    def merge_this(self, key: str, val: Val) -> None:
        if not val.taint:
            return
        old = self.global_scope.vars.get(key)
        new = merge(old, taint_of(val))
        if grew(old, new):
            self.changed = True
        self.global_scope.vars[key] = new

    def bind_pattern(self, pat, val: Val, declare: bool = True) -> None:
        if pat is None:
            return
        t = pat.type
        if t == "Identifier":
            self.assign_name(pat.name, val, declare)
        elif t == "ObjectPattern":
            for prop in pat.properties:
                if prop.type == "RestElement":
                    self.bind_pattern(prop.argument, taint_of(val), declare)
                    continue
                key = self.static_key(prop)
                self.bind_pattern(prop.value, self.member(val, key, prop), declare)
        elif t == "ArrayPattern":
            for el in pat.elements:
                if el is not None:
                    self.bind_pattern(el, self.member(val, None, el), declare)
        elif t == "AssignmentPattern":
            self.bind_pattern(pat.left, merge(val, self.expr(pat.right)), declare)
        elif t == "RestElement":
            self.bind_pattern(pat.argument, val, declare)
        elif t == "MemberExpression":
            self.expr(pat.object)
            self.weak_update_root(pat, val)

    def static_key(self, prop) -> str | None:
        key = prop.key
        if getattr(prop, "computed", False):
            return self.expr(key).const
        if key.type == "Identifier":
            return key.name
        if key.type == "Literal":
            return str(key.value)
        return None

    # -- functions --

    def func_val(self, node) -> Val:
        fid = id(node)
        info = self.funcs.get(fid)
        if info is None:
            if self.class_this is not None:
                this_key = self.class_this
            elif node.type == "ArrowFunctionExpression":
                this_key = self.this_key()  # lexical this
            else:
                this_key = f"<this:{fid}>"
            info = FuncInfo(node, self.scope, this_key)
            self.funcs[fid] = info
        if fid not in self.analyzed and fid not in self.in_progress:
            self.analyzed.add(fid)
            self.analyze_function(info)
        return Val(funcs=frozenset([fid]))

    def analyze_function(self, info: FuncInfo) -> None:
        self.in_progress.add(info.fid)
        saved_scope = self.scope
        self.scope = info.scope
        self.func_stack.append(info)
        try:
            for i, p in enumerate(info.node.params or []):
                self.bind_pattern(p, info.params[i] if i < len(info.params) else EMPTY, declare=True)
            body = info.node.body
            if body.type == "BlockStatement":
                self.block(body.body)
            else:
                self.add_return(self.expr(body))
        finally:
            self.func_stack.pop()
            self.scope = saved_scope
            self.in_progress.discard(info.fid)

    def this_key(self) -> str:
        return self.func_stack[-1].this_key if self.func_stack else "<this:global>"

    def methods_named(self, name: str | None, recv: Val | None) -> frozenset[int]:
        """Name-based resolution of `obj.name` to user functions, used only when the receiver is unknown.

        Short names (minifier output such as `e`, `t`) and names shared by many functions are
        ambiguous; linking them would connect unrelated code, so they are not resolved.
        """
        if name is None or len(name) < 3:
            return frozenset()
        if recv is not None and recv.path and recv.path.split(".")[0] in _API_ROOTS:
            return frozenset()
        candidates = self.methods.get(name)
        if not candidates or len(candidates) > _MAX_DISPATCH:
            return frozenset()
        return frozenset(candidates)

    def register_method(self, name: str | None, val: Val) -> None:
        if name and val.funcs:
            known = self.methods.setdefault(name, set())
            if not val.funcs <= known:
                known |= val.funcs
                self.changed = True

    def store_taint(self, v: Val) -> None:
        if not v.taint:
            return
        old = self.global_scope.vars.get("<storage>")
        new = merge(old, v)
        if grew(old, new):
            self.changed = True
        self.global_scope.vars["<storage>"] = new

    def add_return(self, v: Val) -> None:
        if self.func_stack:
            info = self.func_stack[-1]
            new = merge(info.ret, v)
            if grew(info.ret, new):
                self.changed = True
            info.ret = new

    def call_funcs(self, fval: Val, args: list[Val]) -> Val:
        """Invoke user functions: accumulate parameter values, return summary result."""
        result = EMPTY
        for fid in fval.funcs:
            info = self.funcs.get(fid)
            if info is None:
                continue
            changed_here = False
            for i, a in enumerate(args[: len(info.params)]):
                new = merge(info.params[i], a)
                if grew(info.params[i], new):
                    info.params[i] = new
                    changed_here = True
            if changed_here:
                self.changed = True
                # Converge faster: re-run the body now if it already ran this round.
                if fid in self.analyzed and fid not in self.in_progress and self.reanalysis.get(fid, 0) < 2:
                    self.reanalysis[fid] = self.reanalysis.get(fid, 0) + 1
                    self.analyze_function(info)
            result = union(result, info.ret)
        return result

    def seed(self, fval: Val, params: list[Val]) -> Val:
        """Treat `fval` as a callback the browser will invoke with `params`."""
        if fval.path in ("eval", "Function"):
            return EMPTY
        return self.call_funcs(fval, params)

    # -- statements --

    def block(self, stmts) -> None:
        for s in stmts:
            if s.type == "FunctionDeclaration" and s.id is not None:
                self.assign_name(s.id.name, self.func_val(s), declare=True)
        for s in stmts:
            self.stmt(s)

    def stmt(self, n) -> None:
        if n is None:
            return
        self.tick()
        t = n.type
        if t in ("ExpressionStatement", "Directive"):
            self.expr(n.expression)
        elif t == "VariableDeclaration":
            for d in n.declarations:
                self.bind_pattern(d.id, self.expr(d.init) if d.init is not None else EMPTY, declare=True)
        elif t == "FunctionDeclaration":
            fv = self.func_val(n)
            if n.id is not None:
                self.assign_name(n.id.name, fv, declare=True)
        elif t == "ReturnStatement":
            if n.argument is not None:
                self.add_return(self.expr(n.argument))
        elif t == "IfStatement":
            self.expr(n.test)
            self.stmt(n.consequent)
            self.stmt(n.alternate)
        elif t == "BlockStatement":
            self.block(n.body)
        elif t == "ForStatement":
            if n.init is not None:
                self.stmt(n.init) if n.init.type == "VariableDeclaration" else self.expr(n.init)
            if n.test is not None:
                self.expr(n.test)
            if n.update is not None:
                self.expr(n.update)
            self.stmt(n.body)
        elif t in ("ForInStatement", "ForOfStatement"):
            right = taint_of(self.expr(n.right))
            left = n.left
            if left.type == "VariableDeclaration":
                for d in left.declarations:
                    self.bind_pattern(d.id, right, declare=True)
            else:
                self.bind_pattern(left, right, declare=False)
            self.stmt(n.body)
        elif t in ("WhileStatement", "DoWhileStatement"):
            self.expr(n.test)
            self.stmt(n.body)
        elif t == "TryStatement":
            self.stmt(n.block)
            if n.handler is not None:
                if n.handler.param is not None:
                    self.bind_pattern(n.handler.param, EMPTY, declare=True)
                self.stmt(n.handler.body)
            self.stmt(n.finalizer)
        elif t == "SwitchStatement":
            self.expr(n.discriminant)
            for case in n.cases:
                if case.test is not None:
                    self.expr(case.test)
                for s in case.consequent:
                    self.stmt(s)
        elif t == "ThrowStatement":
            self.expr(n.argument)
        elif t == "LabeledStatement":
            self.stmt(n.body)
        elif t == "WithStatement":
            self.expr(n.object)
            self.stmt(n.body)
        elif t == "ClassDeclaration":
            self.class_(n)
        elif t == "ImportDeclaration":
            self.module_ref(n.source)
        elif t == "ExportNamedDeclaration":
            if n.declaration is not None:
                self.stmt(n.declaration)
            if getattr(n, "source", None) is not None:
                self.module_ref(n.source)
        elif t == "ExportDefaultDeclaration":
            d = n.declaration
            if d.type.endswith("Declaration"):
                self.stmt(d)
            else:
                self.expr(d)
        elif t == "ExportAllDeclaration":
            self.module_ref(n.source)
        # Break/Continue/Empty/Debugger: nothing to do.

    def module_ref(self, source) -> None:
        if source is not None and isinstance(getattr(source, "value", None), str):
            spec = source.value
            if spec.startswith((".", "/")):
                self.result.imported_files.add(spec)

    def class_(self, n) -> Val:
        if n.superClass is not None:
            self.expr(n.superClass)
        saved = self.class_this
        self.class_this = f"<this:class:{id(n)}>"
        try:
            for m in n.body.body:
                if m.type == "StaticBlock":
                    self.block(m.body)
                elif m.type == "PropertyDefinition":
                    # Field initialisers run with `this` bound to the instance.
                    value = self.expr(m.value) if m.value is not None else EMPTY
                    self.register_method(self.static_key(m), value)
                    self.merge_this(self.class_this, value)
                elif getattr(m, "value", None) is not None and m.value.type in ("FunctionExpression", "ArrowFunctionExpression"):
                    self.register_method(self.static_key(m), self.func_val(m.value))
        finally:
            self.class_this = saved
        if n.type == "ClassDeclaration" and n.id is not None:
            self.assign_name(n.id.name, EMPTY, declare=True)
        return EMPTY

    # -- expressions --

    def expr(self, n) -> Val:
        if n is None:
            return EMPTY
        self.tick()
        t = n.type
        if t == "Literal":
            return self.literal(n)
        if t == "Identifier":
            return self.identifier(n)
        if t == "MemberExpression":
            obj = self.expr(n.object)
            return self.member(obj, self.prop_name(n), n)
        if t in ("CallExpression", "NewExpression"):
            return self.call(n, is_new=(t == "NewExpression"))
        if t == "AssignmentExpression":
            return self.assignment(n)
        if t == "BinaryExpression":
            left, right = self.expr(n.left), self.expr(n.right)
            if n.operator == "+":
                const = left.const + right.const if left.const is not None and right.const is not None else None
                prefix = left.const if left.const is not None else left.prefix
                v = taint_of(left, right)
                v.const, v.prefix = const, prefix
                if "ext_url" in left.kinds:
                    v.kinds = frozenset({"ext_url"})  # chrome.runtime.getURL(...) + '?query'
                return v
            if n.operator in ("==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in"):
                return EMPTY  # comparisons do not carry data
            return taint_of(left, right)
        if t == "LogicalExpression":
            return union(self.expr(n.left), self.expr(n.right))
        if t == "ConditionalExpression":
            self.expr(n.test)
            return union(self.expr(n.consequent), self.expr(n.alternate))
        if t == "UnaryExpression":
            v = self.expr(n.argument)
            return EMPTY if n.operator in ("typeof", "!", "void", "delete") else taint_of(v)
        if t == "UpdateExpression":
            return taint_of(self.expr(n.argument))
        if t == "TemplateLiteral":
            vals = [self.expr(e) for e in n.expressions]
            v = taint_of(*vals)
            cooked = [q.value.cooked if q.value.cooked is not None else q.value.raw for q in n.quasis]
            if all(x.const is not None for x in vals):
                v.const = "".join(c + (vals[i].const if i < len(vals) else "") for i, c in enumerate(cooked))
            v.prefix = cooked[0] if cooked else None
            return v
        if t == "TaggedTemplateExpression":
            self.expr(n.tag)
            return self.expr(n.quasi)
        if t == "ObjectExpression":
            props: dict[str, Val] = {}
            vals = []
            for p in n.properties:
                if p.type == "SpreadElement":
                    vals.append(self.expr(p.argument))
                    continue
                pv = self.expr(p.value) if p.value is not None else EMPTY
                key = self.static_key(p)
                if key is not None:
                    props[key] = pv
                    self.register_method(key, pv)
                vals.append(pv)
            v = union(*vals)
            v.props = props
            return v
        if t == "ArrayExpression":
            items = [self.expr(e) if e is not None else EMPTY for e in n.elements]
            v = taint_of(*items)
            v.items = items
            return v
        if t in ("FunctionExpression", "ArrowFunctionExpression"):
            return self.func_val(n)
        if t == "ClassExpression":
            return self.class_(n)
        if t == "SequenceExpression":
            v = EMPTY
            for e in n.expressions:
                v = self.expr(e)
            return v
        if t in ("AwaitExpression", "SpreadElement", "YieldExpression", "RestElement"):
            return self.expr(n.argument)
        if t == "ThisExpression":
            return self.global_scope.vars.get(self.this_key(), EMPTY)
        if t == "Import":
            return Val(path="import")
        return EMPTY

    def literal(self, n) -> Val:
        value = n.value
        if isinstance(value, str):
            return Val(const=value)
        if isinstance(value, bool) or value is None:
            return EMPTY
        if isinstance(value, (int, float)):
            return Val(const=str(int(value)) if float(value).is_integer() else str(value))
        return EMPTY

    def identifier(self, n) -> Val:
        name = n.name
        if name == "undefined":
            return EMPTY
        v = self.scope.lookup(name)
        if v is not None:
            return v
        path = C.normalize_path(name)
        v = Val(path=path)
        src = C.SOURCE_PATHS.get(path)
        if src is not None:
            v = self.source(v, src[0], n, src[1])
        if path in C.DOM_PATHS:
            v.kinds = frozenset({"dom_el"})
        return v

    def prop_name(self, n) -> str | None:
        if not n.computed:
            return n.property.name if n.property.type == "Identifier" else None
        return self.expr(n.property).const

    def member(self, obj: Val, prop: str | None, node) -> Val:
        path = C.normalize_path(f"{obj.path}.{prop}") if obj.path and prop is not None else None
        if obj.props is not None and prop in obj.props:
            v = merge(taint_of(obj), obj.props[prop])
            v = Val(v.taint, v.kinds, v.const, v.prefix, path or v.path, v.props, v.items, v.funcs)
        else:
            v = Val(dict(obj.taint), path=path)
        if obj.items is not None and prop is not None and prop.isdigit() and int(prop) < len(obj.items):
            item = obj.items[int(prop)]
            v.const = item.const
        kinds: set[str] = set()
        k = obj.kinds

        if path is not None:
            src = C.SOURCE_PATHS.get(path)
            if src is not None:
                v = self.source(v, src[0], node, src[1])
            if path in C.DOM_PATHS:
                kinds.add("dom_el")
            if path.startswith(_CAPABILITY_PREFIXES):
                self.capability(path, node)

        if prop is not None and k:
            if "kbd_event" in k:
                if prop in C.KEY_PROPS:
                    v = self.source(v, "KEYSTROKES", node, f"reads the pressed key (event.{prop})")
                elif prop in ("target", "srcElement", "currentTarget"):
                    kinds |= {"dom_el", "event_target"}
            if k & {"input_event", "submit_event"}:
                if prop in ("target", "srcElement", "currentTarget"):
                    kinds |= {"dom_el", "event_target"}
                elif prop == "data":
                    v = self.source(v, "FORM_INPUT", node, "reads typed text (event.data)")
            if "paste_event" in k and prop == "clipboardData":
                v = self.source(v, "CLIPBOARD", node, "reads pasted clipboard data")
            if "page_message" in k and prop == "data":
                v = self.source(v, "UNTRUSTED_PAGE", node, "receives a message posted by the web page")
            if "dom_el" in k:
                if prop == "value":
                    if "password_el" in k:
                        v = self.source(v, "PASSWORD", node, "reads the value of a password field")
                    else:
                        v = self.source(v, "FORM_INPUT", node, "reads the value of an input field")
                elif prop in C.TEXT_PROPS and "event_target" not in k:
                    v = self.source(v, "PAGE_CONTENT", node, f"reads page content (.{prop})")
                elif prop in ("elements", "form", "parentNode", "parentElement", "children", "firstChild", "lastChild", "nextSibling"):
                    kinds.add("dom_el")
                    kinds |= k & {"password_el"}
            if "xhr" in k and prop in ("response", "responseXML"):
                v = self.source(v, "REMOTE_DATA", node, "reads an XMLHttpRequest response")
            if "port_in" in k and prop == "onMessage":
                kinds.add("port_in_onmessage")
            if "port_out" in k and prop == "onMessage":
                kinds.add("port_out_onmessage")
        if prop == "responseText":
            v = self.source(v, "REMOTE_DATA", node, "reads an XMLHttpRequest response")
        if "ext_url" in k and prop in _URL_PASSTHROUGH:
            kinds.add("ext_url")
        if kinds:
            v.kinds = v.kinds | frozenset(kinds)
        return v

    def assignment(self, n) -> Val:
        right = self.expr(n.right)
        left = n.left
        if n.operator != "=":
            right = union(self.expr(left), right) if left.type in ("Identifier", "MemberExpression") else right
        if left.type == "Identifier":
            self.assign_name(left.name, right)
        elif left.type == "MemberExpression":
            obj = self.expr(left.object)
            prop = self.prop_name(left)
            self.member_write(obj, prop, right, n)
            self.weak_update_root(left.object, right)
        else:
            self.bind_pattern(left, right, declare=False)
        return right

    def member_write(self, obj: Val, prop: str | None, val: Val, node) -> None:
        if prop is None:
            return
        k = obj.kinds
        self.register_method(prop, val)
        if prop in ("onkeydown", "onkeypress", "onkeyup"):
            self.listener("keyboard", node)
            self.seed(val, [Val(kinds=frozenset({"kbd_event"}))])
        elif prop in ("oninput", "onchange"):
            self.listener("input", node)
            self.seed(val, [Val(kinds=frozenset({"input_event"}))])
        elif prop == "onsubmit":
            self.listener("submit", node)
            self.seed(val, [Val(kinds=frozenset({"submit_event"}))])
        elif prop == "onpaste":
            self.listener("paste", node)
            self.seed(val, [Val(kinds=frozenset({"paste_event"}))])
        elif prop == "onmessage":
            if "websocket" in k:
                self.seed(val, [self.source(Val(), "REMOTE_DATA", node, "receives WebSocket data")])
            elif obj.path in ("window", "self") or obj.path is None and not k:
                self.listener("page_message", node)
                self.seed(val, [Val(kinds=frozenset({"page_message"}))])
        elif prop == "src":
            if "script_el" in k:
                self.code_exec("script_src", node, val, "sets the src of a <script> element")
            elif "img_el" in k or (not k and val.taint):
                self.sink("network", node, val, "sets an image/frame src (sends a request)", val)
        elif prop in ("text", "textContent", "innerHTML", "innerText") and "script_el" in k:
            self.code_exec("script_text", node, val, "writes code into a <script> element")
        elif (prop == "href" and obj.path in ("location", "document.location")) or (
            prop == "location" and obj.path in ("window", "document", "self")
        ):
            self.sink("network", node, val, "navigates the page to a URL", val, navigation=True)
        if val.funcs and prop.startswith("on"):
            self.seed(val, [EMPTY])

    def listener(self, event: str, node) -> None:
        if self._site_once("listener:" + event, node):
            self.result.listeners.append(Listener(event, self.step(node, f"registers a {event} listener")))

    # -- calls --

    def call(self, n, is_new: bool) -> Val:
        callee = n.callee
        recv: Val | None = None
        prop: str | None = None
        if callee.type == "MemberExpression":
            recv = self.expr(callee.object)
            prop = self.prop_name(callee)
            fval = self.member(recv, prop, callee)
        elif callee.type == "Import":
            fval = Val(path="import")
        else:
            fval = self.expr(callee)
        args = [self.arg_val(a) for a in n.arguments]
        path = fval.path

        if path is not None and path.startswith(_CAPABILITY_PREFIXES):
            self.capability(path, n)

        handled = self.api_call(n, path, prop, recv, args, is_new, callee)
        if handled is not None:
            return handled

        if fval.funcs:
            return self.call_funcs(fval, args)

        dispatched = EMPTY
        targets = self.methods_named(prop, recv)
        if targets:
            dispatched = self.call_funcs(Val(funcs=targets), args)

        # Unknown function: conservatively propagate data from receiver and arguments,
        # and treat function arguments as callbacks receiving the receiver's data
        # (covers arr.forEach(fn), arr.map(fn), ...).
        result = taint_of(recv, *args)
        cb_ret = EMPTY
        for a in args:
            if a.funcs:
                cb_ret = union(cb_ret, self.seed(a, [taint_of(recv), taint_of(recv)]))
        if prop == "join" and recv is not None and recv.items is not None:
            sep = args[0].const if args else ","
            if sep is not None and all(i.const is not None for i in recv.items):
                result.const = sep.join(i.const for i in recv.items)  # type: ignore[misc]
        elif prop == "reverse" and recv is not None and recv.items is not None:
            result.items = list(reversed(recv.items))
        elif prop == "split" and recv is not None and recv.const is not None and args and args[0].const is not None:
            parts = list(recv.const) if args[0].const == "" else recv.const.split(args[0].const)
            result.items = [Val(const=p) for p in parts[:10_000]]
        elif prop in ("concat",) and recv is not None and recv.const is not None and all(a.const is not None for a in args):
            result.const = recv.const + "".join(a.const for a in args)  # type: ignore[misc]
        elif path == "String.fromCharCode" and args and all(a.const is not None and a.const.isdigit() for a in args):
            try:
                result.const = "".join(chr(int(a.const)) for a in args)  # type: ignore[arg-type]
            except (ValueError, OverflowError):
                pass
        elif path in ("atob",) and args and args[0].const:
            result.const = _b64decode(args[0].const)
        elif path in ("decodeURIComponent", "unescape", "decodeURI") and args and args[0].const is not None:
            from urllib.parse import unquote

            result.const = unquote(args[0].const)
        if cb_ret.taint:
            result = taint_of(result, cb_ret) if result.const is None else result
        if dispatched.taint or dispatched.kinds:
            result = taint_of(result, dispatched)
            result.kinds = dispatched.kinds - {"dom_el", "password_el"}
        if (path == "URL" and "ext_url" in a0_kinds(args)) or (recv is not None and "ext_url" in recv.kinds and prop in _URL_PASSTHROUGH):
            result.kinds = result.kinds | frozenset({"ext_url"})
        return result

    def arg_val(self, node) -> Val:
        """Evaluate a call argument; `obj.method` passed as a callback resolves to the method by name."""
        if node.type != "MemberExpression":
            return self.expr(node)
        obj = self.expr(node.object)
        prop = self.prop_name(node)
        v = self.member(obj, prop, node)
        if not v.funcs:
            targets = self.methods_named(prop, obj)
            if targets:
                v = Val(v.taint, v.kinds, v.const, v.prefix, v.path, v.props, v.items, targets)
        return v

    def api_call(self, n, path, prop, recv, args, is_new, callee) -> Val | None:  # noqa: C901
        a0 = args[0] if args else EMPTY
        a1 = args[1] if len(args) > 1 else EMPTY

        # ---- code execution sinks ----
        if path == "eval" and not is_new:
            self.code_exec("eval", n, a0, "passes a string to eval()")
            return taint_of(a0)
        if path == "Function":
            body = args[-1] if args else EMPTY
            v = taint_of(*args)
            v.const = body.const
            v.prefix = body.prefix
            self.code_exec("function", n, v, "builds a function from a string (Function constructor)")
            return Val(taint=dict(v.taint))
        if path in ("setTimeout", "setInterval", "setImmediate"):
            if a0.funcs:
                self.seed(a0, [])
            elif a0.const is not None or a0.prefix is not None:
                # Only when the argument is demonstrably a string (literal, concatenation, template);
                # an opaque variable is far more often a callback.
                self.code_exec("timer_string", n, a0, f"passes a code string to {path}()")
            return EMPTY
        if path == "importScripts":
            for a in args:
                if a.const is not None and not _is_remote_url(a.const):
                    self.result.imported_files.add(a.const)
                self.code_exec("import_scripts", n, a, "loads a script with importScripts()")
            return EMPTY
        if path == "import":
            if a0.const is not None and not _is_remote_url(a0.const):
                self.result.imported_files.add(a0.const)
            self.code_exec("dynamic_import", n, a0, "loads a module with import()")
            return taint_of(a0)
        if path in ("document.write", "document.writeln"):
            self.code_exec("document_write", n, taint_of(*args) if len(args) > 1 else a0, "writes HTML with document.write()")
            return EMPTY
        if path in ("$.globalEval",):
            self.code_exec("eval", n, a0, "runs code with jQuery.globalEval()")
            return EMPTY
        if path in ("$.getScript",):
            self.code_exec("script_src", n, a0, "loads and runs a script with jQuery.getScript()")
            return self.source(Val(), "REMOTE_DATA", n, "downloads a script")
        if path == "chrome.tabs.executeScript":
            details = next((a for a in args if a.props is not None), EMPTY)
            if details.props:
                if "code" in details.props:
                    self.code_exec("execute_script_code", n, details.props["code"], "injects a code string into a tab")
                f = details.props.get("file")
                if f is not None and f.const:
                    self.result.injected_files.add(f.const)
            return EMPTY
        if path == "chrome.scripting.executeScript":
            details = a0
            if details.props:
                files = details.props.get("files")
                for item in (files.items or []) if files is not None else []:
                    if item.const:
                        self.result.injected_files.add(item.const)
                func = details.props.get("func") or details.props.get("function")
                if func is not None:
                    for fid in func.funcs:
                        info = self.funcs.get(fid)
                        if info is not None and getattr(info.node, "range", None):
                            self.result.injected_ranges.append(tuple(info.node.range))
            return EMPTY
        if path in ("chrome.scripting.registerContentScripts", "chrome.scripting.updateContentScripts"):
            for script in a0.items or []:
                js = (script.props or {}).get("js")
                for item in (js.items or []) if js is not None else []:
                    if item.const:
                        self.result.injected_files.add(item.const)
            return EMPTY
        if path in ("chrome.userScripts.register", "chrome.userScripts.update"):
            self.code_exec("user_script", n, taint_of(*args), "registers user scripts")
            return EMPTY
        if path == "chrome.debugger.sendCommand" and a1.const == "Runtime.evaluate":
            expr = (args[2].props or {}).get("expression", EMPTY) if len(args) > 2 else EMPTY
            self.code_exec("debugger_eval", n, expr, "runs code in a page through the debugger")
            return EMPTY
        if path in ("chrome.runtime.getURL", "chrome.extension.getURL"):
            v = taint_of(*args)
            v.kinds = frozenset({"ext_url"})
            return v

        # ---- DOM element creation / lookup ----
        if prop == "createElement" and a0.const is not None:
            tag = a0.const.lower()
            kinds = {"dom_el"}
            if tag == "script":
                kinds.add("script_el")
            elif tag in ("img", "iframe", "frame", "embed", "object", "audio", "video", "source"):
                kinds.add("img_el")
            return Val(kinds=frozenset(kinds))
        if prop in C.DOM_QUERY_METHODS or path in ("$",) and a0.const is not None and not a0.const.startswith("<"):
            kinds = {"dom_el"}
            if a0.const and _PASSWORD_RE.search(a0.const):
                kinds.add("password_el")
                self.sensitive_read("PASSWORD", self.step(n, f"source: selects password fields ({a0.const!r})"))
            v = taint_of(recv) if recv is not None else Val()
            v.kinds = frozenset(kinds | ((recv.kinds if recv else frozenset()) & {"password_el"}))
            return v
        if prop == "setAttribute" and recv is not None and a0.const is not None:
            self.member_write(recv, a0.const.lower(), a1, n)
            return EMPTY

        # ---- event listeners ----
        if prop == "addEventListener" and len(args) >= 2:
            etype = (a0.const or "").lower()
            handler = a1
            rk = recv.kinds if recv is not None else frozenset()
            if "websocket" in rk and etype == "message":
                self.seed(handler, [self.source(Val(), "REMOTE_DATA", n, "receives WebSocket data")])
            elif etype in C.KEY_EVENTS:
                self.listener("keyboard", n)
                self.seed(handler, [Val(kinds=frozenset({"kbd_event"}))])
            elif etype in C.INPUT_EVENTS:
                self.listener("input", n)
                self.seed(handler, [Val(kinds=frozenset({"input_event"}))])
            elif etype == "submit":
                self.listener("submit", n)
                self.seed(handler, [Val(kinds=frozenset({"submit_event"}))])
            elif etype == "paste":
                self.listener("paste", n)
                self.seed(handler, [Val(kinds=frozenset({"paste_event"}))])
            elif etype == "message" and (recv is None or recv.path in ("window", "self", None)) and "xhr" not in rk:
                self.listener("page_message", n)
                self.seed(handler, [Val(kinds=frozenset({"page_message"}))])
            else:
                self.seed(handler, [EMPTY])
            return EMPTY
        if prop in ("on", "bind", "live", "delegate") and args and a0.const and recv is not None:
            if set(a0.const.lower().split()) & C.KEY_EVENTS:
                self.listener("keyboard", n)
                for a in args[1:]:
                    self.seed(a, [Val(kinds=frozenset({"kbd_event"}))])
                return EMPTY
        if prop in C.JQUERY_KEY_METHODS and args and args[-1].funcs and recv is not None and "dom_el" not in recv.kinds:
            self.listener("keyboard", n)
            self.seed(args[-1], [Val(kinds=frozenset({"kbd_event"}))])
            return EMPTY

        # ---- chrome.* events ----
        if path is not None and path.endswith(".addListener"):
            event = path[: -len(".addListener")]
            handler = a0
            if event in C.MESSAGE_LISTENERS:
                self.seed(handler, [self.incoming, EMPTY, EMPTY])
                return EMPTY
            if event == "chrome.runtime.onConnect":
                self.seed(handler, [Val(kinds=frozenset({"port_in"}))])
                return EMPTY
            if event in C.EVENT_SOURCES:
                label, note = C.EVENT_SOURCES[event]
                if event.startswith("chrome.webRequest.") and label == "BROWSING":
                    specs = {i.const for i in (args[2].items or [])} if len(args) > 2 else set()
                    if specs & C.REQUEST_DATA_SPECS:
                        label, note = "REQUEST_DATA", note + f" with {', '.join(sorted(specs & C.REQUEST_DATA_SPECS))}"
                tainted = self.source(Val(), label, n, note)
                self.seed(handler, [tainted, tainted, tainted])
                return EMPTY
            self.seed(handler, [EMPTY, EMPTY, EMPTY])
            return EMPTY
        if prop == "addListener" and recv is not None and "port_in_onmessage" in recv.kinds:
            self.seed(a0, [self.incoming])
            return EMPTY

        # ---- promises / responses ----
        if prop in ("then", "catch", "finally") and recv is not None:
            if prop == "then" and args:
                for a in args[:1]:
                    if a.path in ("eval", "Function"):
                        self.code_exec("eval", n, recv, "passes a promise result straight to eval()")
                ret = self.seed(a0, [recv])
                for a in args[1:]:
                    self.seed(a, [EMPTY])
                return union(taint_of(recv), ret)
            for a in args:
                self.seed(a, [EMPTY])
            return taint_of(recv)
        if prop in C.RESPONSE_METHODS and recv is not None and recv.taint and not args:
            return taint_of(recv)

        # ---- storage: a bridge that keeps taint across set -> get ----
        m = _STORAGE_RE.match(path or "")
        if m or path in ("localStorage.setItem", "sessionStorage.setItem", "localStorage.getItem", "sessionStorage.getItem"):
            if (m and m.group(1) == "set") or (path or "").endswith("setItem"):
                self.store_taint(taint_of(*[a for a in args if not a.funcs]))
                for a in args:
                    if a.funcs:
                        self.seed(a, [EMPTY])
                return EMPTY
            stored = self.global_scope.vars.get("<storage>", EMPTY)
            for a in args:
                if a.funcs:
                    self.seed(a, [stored])
            if path in C.CALL_SOURCES:
                label, note = C.CALL_SOURCES[path]
                return self.source(taint_of(stored), label, n, note)
            return taint_of(stored)

        # ---- sources (API calls) ----
        if path in C.CALL_SOURCES:
            label, note = C.CALL_SOURCES[path]
            tainted = self.source(Val(), label, n, note)
            for a in args:
                if a.funcs:
                    self.seed(a, [tainted])
            return tainted
        if path == "document.execCommand" and (a0.const or "").lower() == "paste":
            return self.source(Val(), "CLIPBOARD", n, "reads the clipboard with execCommand('paste')")
        if path == "chrome.runtime.connect" or path == "chrome.tabs.connect":
            return Val(kinds=frozenset({"port_out"}))
        if path == "chrome.runtime.sendNativeMessage" or path == "chrome.runtime.connectNative":
            self.sink("network", n, taint_of(*args), f"sends data to a native program ({path})", None)
            return Val(kinds=frozenset({"port_out"}))

        # ---- network sinks ----
        if path in C.NETWORK_CALLS:
            idx, note = C.NETWORK_CALLS[path]
            dest = args[idx] if idx is not None and idx < len(args) else EMPTY
            if dest.props is not None and "url" in dest.props:
                dest = dest.props["url"]
            self.sink("network", n, taint_of(*[a for a in args if not a.funcs]), note, dest, navigation=path == "open")
            remote = self.source(Val(), "REMOTE_DATA", n, f"response of {path}()")
            for a in args:
                if a.funcs:
                    self.seed(a, [remote])
            return remote
        if path in C.NETWORK_URL_PROP_CALLS:
            details = next((a for a in args if a.props is not None), EMPTY)
            dest = (details.props or {}).get("url", EMPTY)
            self.sink("network", n, taint_of(dest), C.NETWORK_URL_PROP_CALLS[path], dest,
                      navigation=path != "chrome.downloads.download")
            for a in args:
                if a.funcs:
                    self.seed(a, [EMPTY])
            return EMPTY
        if recv is not None and "xhr" in recv.kinds:
            if prop == "open":
                self.last_xhr_dest = a1
                self.sink("network", n, taint_of(a1), "opens an XMLHttpRequest", a1)
                return EMPTY
            if prop == "send":
                self.sink("network", n, taint_of(a0), "sends data with XMLHttpRequest", self.last_xhr_dest)
                return EMPTY
            if prop == "setRequestHeader":
                self.sink("network", n, taint_of(a1), "puts data in an XMLHttpRequest header", self.last_xhr_dest)
                return EMPTY
        if recv is not None and "websocket" in recv.kinds and prop == "send":
            self.sink("network", n, taint_of(a0), "sends data over a WebSocket")
            return EMPTY
        if is_new and path in ("XMLHttpRequest", "ActiveXObject"):
            return Val(kinds=frozenset({"xhr"}))
        if is_new and path in ("WebSocket", "EventSource"):
            self.sink("network", n, taint_of(a0), f"opens a {path} connection", a0)
            v = Val(kinds=frozenset({"websocket"}))
            return v
        if is_new and path == "Image":
            return Val(kinds=frozenset({"dom_el", "img_el"}))
        if is_new and path == "FormData" and args and a0.kinds & {"dom_el"}:
            return self.source(Val(), "FORM_INPUT", n, "collects all fields of a form (FormData)")

        # ---- messaging ----
        if path in C.MESSAGE_SENDS:
            payload = taint_of(*[a for a in args if not a.funcs])
            self.sink("message", n, payload, "passes data to the extension's background script")
            for a in args:
                if a.funcs:
                    self.seed(a, [EMPTY])
            return EMPTY
        if prop == "postMessage" and recv is not None:
            if recv.kinds & {"port_out", "port_in"}:
                self.sink("message", n, taint_of(a0), "passes data over an extension message port")
                return EMPTY
            if recv.path in ("window", "parent", "top", "self") or path == "postMessage":
                self.sink("page_leak", n, taint_of(a0), "posts data to the web page (window.postMessage)")
                return EMPTY

        # ---- container mutation: arr.push(x), params.set(k, x), Object.assign(o, x) ----
        if prop in C.MUTATING_METHODS and isinstance(callee, object) and callee.type == "MemberExpression":
            payload = taint_of(*args)
            if path == "Object.assign" and n.arguments:
                self.weak_update_root(n.arguments[0], payload)
            else:
                self.weak_update_root(callee.object, payload)
            return None
        return None


def a0_kinds(args: list[Val]) -> frozenset[str]:
    return args[0].kinds if args else frozenset()


def _b64decode(s: str) -> str | None:
    s = s.strip()
    if len(s) < 4 or not _B64_RE.match(s):
        return None
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=False).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def analyze_ast(path: str, ast, incoming: Val | None = None, max_rounds: int = 5) -> FileAnalysis:
    return FileAnalyzer(path, ast, incoming, max_rounds=max_rounds).run()
