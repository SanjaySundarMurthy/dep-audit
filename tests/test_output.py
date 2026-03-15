"""Tests for dep_audit.output (rendering functions)."""

from __future__ import annotations

import io

from rich.console import Console

from dep_audit.models import (
    AuditResult,
    DepNode,
    Dependency,
    EcosystemType,
    LicenseIssue,
    LicenseRisk,
    Severity,
    Vulnerability,
)
from dep_audit.output import (
    render_audit_result,
    render_dependency_list,
    render_license_issues,
    render_license_summary,
    render_outdated,
    render_tree,
    render_vulnerabilities,
)


def capture_output(func, *args, **kwargs) -> str:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    import dep_audit.output as mod
    original = mod.console
    mod.console = console
    try:
        func(*args, **kwargs)
    finally:
        mod.console = original
    return buf.getvalue()


class TestRenderAuditResult:
    def test_perfect(self):
        r = AuditResult(total_dependencies=5, ecosystem=EcosystemType.PYTHON)
        output = capture_output(render_audit_result, r)
        assert "A+" in output
        assert "100" in output

    def test_with_vulns(self):
        vulns = [Vulnerability("CVE-1", "pkg", severity=Severity.HIGH, title="Bad")]
        r = AuditResult(total_dependencies=5, ecosystem=EcosystemType.PYTHON, vulnerabilities=vulns)
        output = capture_output(render_audit_result, r)
        assert "CVE-1" in output

    def test_clean_bill(self):
        r = AuditResult(total_dependencies=5, ecosystem=EcosystemType.PYTHON)
        output = capture_output(render_audit_result, r)
        assert "clear" in output.lower() or "A+" in output


class TestRenderVulnerabilities:
    def test_basic(self):
        vulns = [
            Vulnerability("CVE-1", "pkg", severity=Severity.CRITICAL, title="RCE", fixed_version="2.0"),
            Vulnerability("CVE-2", "pkg2", severity=Severity.LOW, title="Info leak"),
        ]
        output = capture_output(render_vulnerabilities, vulns)
        assert "CVE-1" in output
        assert "CVE-2" in output
        assert "2.0" in output


class TestRenderOutdated:
    def test_basic(self):
        outdated = [
            Dependency(name="pkg", installed_version="1.0.0", latest_version="2.0.0"),
        ]
        output = capture_output(render_outdated, outdated)
        assert "pkg" in output
        assert "1.0.0" in output
        assert "2.0.0" in output


class TestRenderLicenseIssues:
    def test_basic(self):
        issues = [
            LicenseIssue(package="gpl-lib", license="GPL-3.0", risk=LicenseRisk.HIGH, message="Copyleft"),
        ]
        output = capture_output(render_license_issues, issues)
        assert "gpl-lib" in output
        assert "GPL-3.0" in output


class TestRenderLicenseSummary:
    def test_basic(self):
        summary = {
            "total": 10,
            "unique_licenses": 3,
            "risk_breakdown": {"low": 7, "medium": 2, "high": 1, "unknown": 0},
            "licenses": {"MIT": 5, "Apache-2.0": 3, "GPL-3.0": 2},
        }
        output = capture_output(render_license_summary, summary)
        assert "10" in output
        assert "MIT" in output


class TestRenderDependencyList:
    def test_basic(self):
        deps = [
            Dependency(name="click", installed_version="8.1.7", license="MIT",
                       license_risk=LicenseRisk.LOW, ecosystem=EcosystemType.PYTHON),
        ]
        output = capture_output(render_dependency_list, deps)
        assert "click" in output
        assert "8.1.7" in output


class TestRenderTree:
    def test_basic(self):
        root = DepNode(name="project")
        root.children = [DepNode(name="click", version="8.1.7", depth=1)]
        output = capture_output(render_tree, root)
        assert "project" in output
        assert "click" in output
