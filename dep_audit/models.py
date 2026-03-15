"""Data models for dep-audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @property
    def icon(self) -> str:
        icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "none": "⚪"}
        return icons.get(self.value, "⚪")

    @property
    def priority(self) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
        return order.get(self.value, 99)


class LicenseRisk(Enum):
    """License risk categories."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def icon(self) -> str:
        icons = {"high": "🔴", "medium": "🟡", "low": "🟢", "unknown": "⚪"}
        return icons.get(self.value, "⚪")


class EcosystemType(Enum):
    """Package ecosystem types."""
    PYTHON = "python"
    NODEJS = "nodejs"
    RUST = "rust"
    GO = "go"
    RUBY = "ruby"
    JAVA = "java"
    DOTNET = "dotnet"
    PHP = "php"
    UNKNOWN = "unknown"


# ── License Classification ──────────────────────────────────────

PERMISSIVE_LICENSES = {
    "MIT", "MIT License",
    "Apache-2.0", "Apache License 2.0", "Apache Software License",
    "BSD-2-Clause", "BSD-3-Clause", "BSD License",
    "ISC", "ISC License",
    "Unlicense", "The Unlicense",
    "CC0-1.0", "CC0",
    "0BSD",
    "Zlib", "zlib License",
    "PSF-2.0", "Python Software Foundation License",
    "BSL-1.0", "Boost Software License",
}

COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "GNU General Public License v2",
    "GNU General Public License v3",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "GNU Affero General Public License v3",
}

WEAK_COPYLEFT_LICENSES = {
    "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    "GNU Lesser General Public License v2",
    "GNU Lesser General Public License v3",
    "MPL-2.0", "Mozilla Public License 2.0",
    "EPL-1.0", "EPL-2.0", "Eclipse Public License",
    "CDDL-1.0",
}


def classify_license(license_name: str) -> LicenseRisk:
    """Classify a license string into a risk category."""
    if not license_name or license_name.upper() in ("UNKNOWN", "NOASSERTION", ""):
        return LicenseRisk.UNKNOWN

    normalized = license_name.strip()

    # Check exact match first
    if normalized in PERMISSIVE_LICENSES:
        return LicenseRisk.LOW
    if normalized in COPYLEFT_LICENSES:
        return LicenseRisk.HIGH
    if normalized in WEAK_COPYLEFT_LICENSES:
        return LicenseRisk.MEDIUM

    # Fuzzy match
    upper = normalized.upper()
    if any(p.upper() in upper for p in ("MIT", "APACHE", "BSD", "ISC", "UNLICENSE", "CC0", "PSF")):
        return LicenseRisk.LOW
    # Check weak copyleft BEFORE copyleft (LGPL must not match GPL)
    if any(p.upper() in upper for p in ("LGPL", "MPL", "MOZILLA", "ECLIPSE", "EPL")):
        return LicenseRisk.MEDIUM
    if any(p.upper() in upper for p in ("AGPL", "GPL", "GNU GENERAL", "GNU GPL")):
        return LicenseRisk.HIGH

    return LicenseRisk.UNKNOWN


# ── Data Classes ────────────────────────────────────────────────


@dataclass
class Dependency:
    """A parsed dependency."""
    name: str
    version_spec: str = ""
    installed_version: str = ""
    latest_version: str = ""
    license: str = ""
    license_risk: LicenseRisk = LicenseRisk.UNKNOWN
    ecosystem: EcosystemType = EcosystemType.UNKNOWN
    is_direct: bool = True
    is_dev: bool = False
    summary: str = ""
    homepage: str = ""
    python_requires: str = ""
    requires_dist: list[str] = field(default_factory=list)

    @property
    def is_outdated(self) -> bool:
        if not self.installed_version or not self.latest_version:
            return False
        return self.installed_version != self.latest_version

    @property
    def update_type(self) -> str:
        """Determine if update is major, minor, or patch."""
        if not self.is_outdated:
            return ""
        try:
            inst = self.installed_version.split(".")
            latest = self.latest_version.split(".")
            if len(inst) >= 1 and len(latest) >= 1 and inst[0] != latest[0]:
                return "major"
            if len(inst) >= 2 and len(latest) >= 2 and inst[1] != latest[1]:
                return "minor"
            return "patch"
        except (IndexError, ValueError):
            return "unknown"


@dataclass
class Vulnerability:
    """A known vulnerability for a dependency."""
    id: str  # CVE or advisory ID
    package: str
    affected_versions: str = ""
    fixed_version: str = ""
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    url: str = ""
    source: str = ""  # osv, pypi, npm, etc.

    @property
    def display(self) -> str:
        return f"{self.severity.icon} [{self.severity.value.upper()}] {self.id}: {self.title}"


@dataclass
class LicenseIssue:
    """A license compliance issue."""
    package: str
    version: str = ""
    license: str = ""
    risk: LicenseRisk = LicenseRisk.UNKNOWN
    message: str = ""
    suggestion: str = ""


@dataclass
class DepNode:
    """A node in the dependency tree."""
    name: str
    version: str = ""
    children: list["DepNode"] = field(default_factory=list)
    depth: int = 0

    @property
    def child_count(self) -> int:
        total = len(self.children)
        for c in self.children:
            total += c.child_count
        return total


@dataclass
class AuditResult:
    """Complete audit result for a project."""
    project_path: str = ""
    ecosystem: EcosystemType = EcosystemType.UNKNOWN
    total_dependencies: int = 0
    direct_dependencies: int = 0
    dev_dependencies: int = 0
    dependencies: list[Dependency] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    license_issues: list[LicenseIssue] = field(default_factory=list)
    outdated: list[Dependency] = field(default_factory=list)
    tree: Optional[DepNode] = None

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def critical_vulns(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_vulns(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def outdated_count(self) -> int:
        return len(self.outdated)

    @property
    def license_issue_count(self) -> int:
        return len(self.license_issues)

    @property
    def has_critical(self) -> bool:
        return self.critical_vulns > 0

    @property
    def security_score(self) -> float:
        if self.total_dependencies == 0:
            return 100.0
        penalty = (
            self.critical_vulns * 25
            + self.high_vulns * 15
            + sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM) * 5
            + sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW) * 2
        )
        score = max(0, 100 - penalty)
        return round(score, 1)

    @property
    def health_score(self) -> float:
        sec = self.security_score
        # Penalize outdated deps (each outdated = -1, max -20)
        outdated_penalty = min(20, self.outdated_count * 2)
        # Penalize license issues (each = -3, max -15)
        license_penalty = min(15, self.license_issue_count * 3)
        score = max(0, sec - outdated_penalty - license_penalty)
        return round(score, 1)

    @property
    def grade(self) -> str:
        s = self.health_score
        if s >= 95:
            return "A+"
        elif s >= 90:
            return "A"
        elif s >= 80:
            return "B"
        elif s >= 70:
            return "C"
        elif s >= 60:
            return "D"
        else:
            return "F"
