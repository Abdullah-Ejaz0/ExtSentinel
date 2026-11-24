"""Data contracts shared with the extension UI and the scoring module.

`Finding` is the unit every analysis layer produces. The scorer (owned by the
threat-intel/scoring module) only needs `rule_id`, `category` and `severity`;
the UI shows `title`, `description` and `evidence`.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def lowered(self, steps: int = 1) -> "Severity":
        return _SEVERITY_ORDER[max(0, self.rank - steps)]


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Category(str, Enum):
    PERMISSION = "permission"
    HOST_ACCESS = "host_access"
    CONTENT_SCRIPT = "content_script"
    CSP = "csp"
    MANIFEST = "manifest"
    CODE_EXECUTION = "code_execution"
    DATA_ACCESS = "data_access"
    SURVEILLANCE = "surveillance"
    EXFILTRATION = "exfiltration"
    NETWORK = "network"
    OBFUSCATION = "obfuscation"


class ScriptContext(str, Enum):
    CONTENT_SCRIPT = "content_script"  # runs inside web pages
    BACKGROUND = "background"  # service worker / background page
    EXTENSION_PAGE = "extension_page"  # popup, options, side panel, ...
    WEB_ACCESSIBLE = "web_accessible"  # can be loaded by web pages
    UNKNOWN = "unknown"  # not referenced statically (may be injected at runtime)


class Confidence(str, Enum):
    """How strong the evidence behind a finding is.

    CONFIRMED - a concrete data flow (source -> sink) was traced in the code,
                or the fact is declared outright (e.g. a manifest permission).
    LIKELY    - the pieces are present and connected only heuristically.
    POSSIBLE  - a capability exists but no behaviour using it was observed.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class Evidence(BaseModel):
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    note: str | None = Field(default=None, description="Role of this location, e.g. 'source: reads document.cookie'")


class Finding(BaseModel):
    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence = Confidence.CONFIRMED
    title: str = Field(description="Short plain-language reason shown to the user")
    description: str = Field(description="Longer explanation of why this matters")
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Locations supporting the finding. For data flows this is the ordered source -> sink trace.",
    )
    occurrences: int = 1
    tags: list[str] = Field(default_factory=list, description="Machine-readable details, e.g. data labels, destination host")


class FileReport(BaseModel):
    path: str
    size: int
    contexts: list[ScriptContext]
    parsed: bool = Field(description="True if a full syntax tree was built; False means regex fallback")
    parse_error: str | None = None
    library: str | None = Field(default=None, description="Known third-party library detected from its banner")
    minified: bool = False
    obfuscation_signals: list[str] = Field(default_factory=list)


class AnalysisCoverage(BaseModel):
    """How much of the code the engine could actually reason about.

    Findings are only as strong as the coverage behind them; a clean result
    from a package whose scripts could not be parsed is not evidence of safety.
    """

    parser: str = Field(description="tree-sitter, or esprima when tree-sitter could not be loaded")
    js_files: int
    parsed_files: int
    files_with_syntax_errors: list[str] = Field(
        default_factory=list, description="Parsed with tree-sitter error recovery; broken regions were skipped"
    )
    fallback_files: list[str] = Field(description="Scripts analysed with the regex scanner only")
    obfuscated_files: list[str]
    library_files: list[str]


class ExtensionReport(BaseModel):
    """Static-analysis output. Risk scoring is applied on top of this by the scoring module."""

    extension_id: str
    name: str
    version: str
    manifest_version: int | None
    description: str | None = None
    source: str = Field(description="webstore | upload | local")
    package_sha256: str
    analyzed_at: datetime
    analyzer_version: str
    mode: str = Field(description="dataflow (default) or keyword (baseline for evaluation)")

    findings: list[Finding] = Field(description="Most severe first")
    coverage: AnalysisCoverage

    permissions: list[str]
    host_permissions: list[str]
    optional_permissions: list[str]
    files: list[FileReport]
    warnings: list[str] = Field(default_factory=list)
