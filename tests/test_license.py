"""Tests for dep_audit.license."""

from __future__ import annotations


from dep_audit.models import Dependency, LicenseRisk
from dep_audit.license import (
    check_license_compliance,
    get_license_summary,
    _suggest_action,
    POLICIES,
)


class TestCheckLicenseCompliance:
    def test_all_permissive(self):
        deps = [
            Dependency(name="a", license="MIT", installed_version="1.0"),
            Dependency(name="b", license="Apache-2.0", installed_version="1.0"),
            Dependency(name="c", license="BSD-3-Clause", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="strict")
        assert len(issues) == 0

    def test_copyleft_in_strict(self):
        deps = [
            Dependency(name="gpl-lib", license="GPL-3.0", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="strict")
        assert len(issues) == 1
        assert issues[0].risk == LicenseRisk.HIGH

    def test_weak_copyleft_in_strict(self):
        deps = [
            Dependency(name="lgpl-lib", license="LGPL-3.0", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="strict")
        assert len(issues) == 1
        assert issues[0].risk == LicenseRisk.MEDIUM

    def test_weak_copyleft_in_moderate(self):
        deps = [
            Dependency(name="lgpl-lib", license="LGPL-3.0", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="moderate")
        assert len(issues) == 0

    def test_copyleft_in_moderate(self):
        deps = [
            Dependency(name="gpl-lib", license="GPL-3.0", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="moderate")
        assert len(issues) == 1

    def test_unknown_license(self):
        deps = [
            Dependency(name="mystery", license="", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="moderate")
        assert len(issues) == 1
        assert issues[0].risk == LicenseRisk.UNKNOWN

    def test_custom_license_unknown(self):
        deps = [
            Dependency(name="custom", license="Custom License v99", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="moderate")
        assert len(issues) >= 1

    def test_denied_list(self):
        deps = [
            Dependency(name="evil", license="MIT", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, denied_licenses=["MIT"])
        assert len(issues) == 1
        assert "denied" in issues[0].message.lower()

    def test_permissive_policy_allows_all(self):
        deps = [
            Dependency(name="gpl", license="GPL-3.0", installed_version="1.0"),
            Dependency(name="mit", license="MIT", installed_version="1.0"),
        ]
        issues = check_license_compliance(deps, policy="permissive")
        assert len(issues) == 0

    def test_mixed_deps(self, sample_deps):
        issues = check_license_compliance(sample_deps, policy="strict")
        # GPL-3.0 should be flagged
        gpl_issues = [i for i in issues if i.package == "evil-lib"]
        assert len(gpl_issues) >= 1


class TestGetLicenseSummary:
    def test_basic(self, sample_deps):
        summary = get_license_summary(sample_deps)
        assert summary["total"] == len(sample_deps)
        assert summary["unique_licenses"] >= 1
        assert "risk_breakdown" in summary

    def test_empty(self):
        summary = get_license_summary([])
        assert summary["total"] == 0

    def test_risk_breakdown(self):
        deps = [
            Dependency(name="a", license="MIT"),
            Dependency(name="b", license="GPL-3.0"),
        ]
        summary = get_license_summary(deps)
        assert summary["risk_breakdown"]["low"] >= 1
        assert summary["risk_breakdown"]["high"] >= 1


class TestSuggestAction:
    def test_high_risk(self):
        dep = Dependency(name="gpl-lib")
        suggestion = _suggest_action(LicenseRisk.HIGH, dep)
        assert "Replace" in suggestion

    def test_medium_risk(self):
        dep = Dependency(name="lgpl-lib")
        suggestion = _suggest_action(LicenseRisk.MEDIUM, dep)
        assert "Review" in suggestion


class TestPolicies:
    def test_strict_exists(self):
        assert "strict" in POLICIES
        assert LicenseRisk.LOW in POLICIES["strict"]["allowed"]

    def test_moderate_exists(self):
        assert "moderate" in POLICIES
        assert LicenseRisk.MEDIUM in POLICIES["moderate"]["allowed"]

    def test_permissive_exists(self):
        assert "permissive" in POLICIES
        assert LicenseRisk.HIGH in POLICIES["permissive"]["allowed"]
