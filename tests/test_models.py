"""Tests for dep_audit.models."""

from __future__ import annotations

import pytest

from dep_audit.models import (
    AuditResult,
    DepNode,
    Dependency,
    EcosystemType,
    LicenseIssue,
    LicenseRisk,
    Severity,
    Vulnerability,
    classify_license,
)


# ── Severity ────────────────────────────────────────────────────

class TestSeverity:
    def test_icons(self):
        assert Severity.CRITICAL.icon == "🔴"
        assert Severity.HIGH.icon == "🟠"
        assert Severity.MEDIUM.icon == "🟡"
        assert Severity.LOW.icon == "🔵"
        assert Severity.NONE.icon == "⚪"

    def test_priority_order(self):
        assert Severity.CRITICAL.priority < Severity.HIGH.priority
        assert Severity.HIGH.priority < Severity.MEDIUM.priority
        assert Severity.MEDIUM.priority < Severity.LOW.priority
        assert Severity.LOW.priority < Severity.NONE.priority


# ── LicenseRisk ─────────────────────────────────────────────────

class TestLicenseRisk:
    def test_icons(self):
        assert LicenseRisk.HIGH.icon == "🔴"
        assert LicenseRisk.MEDIUM.icon == "🟡"
        assert LicenseRisk.LOW.icon == "🟢"
        assert LicenseRisk.UNKNOWN.icon == "⚪"


# ── EcosystemType ───────────────────────────────────────────────

class TestEcosystemType:
    def test_values(self):
        assert EcosystemType.PYTHON.value == "python"
        assert EcosystemType.NODEJS.value == "nodejs"
        assert EcosystemType.RUST.value == "rust"
        assert EcosystemType.GO.value == "go"


# ── classify_license ────────────────────────────────────────────

class TestClassifyLicense:
    @pytest.mark.parametrize("license_str", [
        "MIT", "MIT License", "Apache-2.0", "Apache License 2.0",
        "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense", "CC0-1.0",
    ])
    def test_permissive(self, license_str):
        assert classify_license(license_str) == LicenseRisk.LOW

    @pytest.mark.parametrize("license_str", [
        "GPL-2.0", "GPL-3.0", "AGPL-3.0",
        "GNU General Public License v3",
    ])
    def test_copyleft(self, license_str):
        assert classify_license(license_str) == LicenseRisk.HIGH

    @pytest.mark.parametrize("license_str", [
        "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "Mozilla Public License 2.0",
        "EPL-2.0",
    ])
    def test_weak_copyleft(self, license_str):
        assert classify_license(license_str) == LicenseRisk.MEDIUM

    def test_unknown(self):
        assert classify_license("") == LicenseRisk.UNKNOWN
        assert classify_license("UNKNOWN") == LicenseRisk.UNKNOWN
        assert classify_license("Custom License v99") == LicenseRisk.UNKNOWN

    def test_fuzzy_match(self):
        assert classify_license("MIT License (modified)") == LicenseRisk.LOW
        assert classify_license("Apache Software License") == LicenseRisk.LOW
        assert classify_license("GNU GPL v3") == LicenseRisk.HIGH


# ── Dependency ──────────────────────────────────────────────────

class TestDependency:
    def test_basic(self):
        dep = Dependency(name="click", version_spec=">=8.0", installed_version="8.1.7")
        assert dep.name == "click"
        assert dep.is_outdated is False

    def test_outdated(self):
        dep = Dependency(name="pkg", installed_version="1.0.0", latest_version="2.0.0")
        assert dep.is_outdated is True

    def test_not_outdated_same(self):
        dep = Dependency(name="pkg", installed_version="1.0.0", latest_version="1.0.0")
        assert dep.is_outdated is False

    def test_not_outdated_no_latest(self):
        dep = Dependency(name="pkg", installed_version="1.0.0")
        assert dep.is_outdated is False

    def test_update_type_major(self):
        dep = Dependency(name="pkg", installed_version="1.0.0", latest_version="2.0.0")
        assert dep.update_type == "major"

    def test_update_type_minor(self):
        dep = Dependency(name="pkg", installed_version="1.0.0", latest_version="1.1.0")
        assert dep.update_type == "minor"

    def test_update_type_patch(self):
        dep = Dependency(name="pkg", installed_version="1.0.0", latest_version="1.0.1")
        assert dep.update_type == "patch"

    def test_update_type_not_outdated(self):
        dep = Dependency(name="pkg", installed_version="1.0.0", latest_version="1.0.0")
        assert dep.update_type == ""


# ── Vulnerability ───────────────────────────────────────────────

class TestVulnerability:
    def test_display(self):
        v = Vulnerability(
            id="CVE-2024-0001",
            package="requests",
            severity=Severity.HIGH,
            title="HTTP header injection",
        )
        assert "CVE-2024-0001" in v.display
        assert "HIGH" in v.display

    def test_basic(self):
        v = Vulnerability(id="GHSA-xxx", package="flask", severity=Severity.CRITICAL)
        assert v.severity == Severity.CRITICAL


# ── LicenseIssue ────────────────────────────────────────────────

class TestLicenseIssue:
    def test_basic(self):
        issue = LicenseIssue(
            package="evil-lib",
            license="GPL-3.0",
            risk=LicenseRisk.HIGH,
            message="Copyleft license not allowed",
        )
        assert issue.package == "evil-lib"
        assert issue.risk == LicenseRisk.HIGH


# ── DepNode ─────────────────────────────────────────────────────

class TestDepNode:
    def test_basic(self):
        node = DepNode(name="root")
        assert node.child_count == 0

    def test_with_children(self):
        root = DepNode(name="root")
        child1 = DepNode(name="a", version="1.0")
        child2 = DepNode(name="b", version="2.0")
        root.children = [child1, child2]
        assert root.child_count == 2

    def test_nested_count(self):
        root = DepNode(name="root")
        child = DepNode(name="a")
        grandchild = DepNode(name="b")
        child.children = [grandchild]
        root.children = [child]
        assert root.child_count == 2


# ── AuditResult ─────────────────────────────────────────────────

class TestAuditResult:
    def test_perfect_score(self):
        r = AuditResult(total_dependencies=10)
        assert r.health_score == 100.0
        assert r.grade == "A+"

    def test_with_vulns(self):
        vulns = [
            Vulnerability("CVE-1", "pkg", severity=Severity.CRITICAL),
            Vulnerability("CVE-2", "pkg2", severity=Severity.HIGH),
        ]
        r = AuditResult(total_dependencies=5, vulnerabilities=vulns)
        assert r.vuln_count == 2
        assert r.critical_vulns == 1
        assert r.has_critical is True
        assert r.security_score < 100

    def test_grade_thresholds(self):
        r = AuditResult(total_dependencies=5)
        assert r.grade == "A+"

    def test_outdated_count(self):
        outdated = [
            Dependency(name="a", installed_version="1.0", latest_version="2.0"),
            Dependency(name="b", installed_version="1.0", latest_version="1.1"),
        ]
        r = AuditResult(total_dependencies=5, outdated=outdated)
        assert r.outdated_count == 2

    def test_zero_deps(self):
        r = AuditResult(total_dependencies=0)
        assert r.health_score == 100.0
        assert r.grade == "A+"
