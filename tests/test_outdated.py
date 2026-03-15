"""Tests for dep_audit.outdated."""

from __future__ import annotations


from dep_audit.models import Dependency
from dep_audit.outdated import compare_versions, get_update_summary


class TestCompareVersions:
    def test_major(self):
        assert compare_versions("1.0.0", "2.0.0") == "major"

    def test_minor(self):
        assert compare_versions("1.0.0", "1.1.0") == "minor"

    def test_patch(self):
        assert compare_versions("1.0.0", "1.0.1") == "patch"

    def test_same(self):
        assert compare_versions("1.0.0", "1.0.0") == ""

    def test_major_with_minor_diff(self):
        assert compare_versions("1.2.3", "2.0.0") == "major"

    def test_two_part_version(self):
        assert compare_versions("1.0", "2.0") == "major"

    def test_single_part(self):
        assert compare_versions("1", "2") == "major"


class TestGetUpdateSummary:
    def test_basic(self):
        outdated = [
            Dependency(name="a", installed_version="1.0.0", latest_version="2.0.0"),
            Dependency(name="b", installed_version="1.0.0", latest_version="1.1.0"),
            Dependency(name="c", installed_version="1.0.0", latest_version="1.0.1"),
        ]
        summary = get_update_summary(outdated)
        assert summary["total"] == 3
        assert summary["major"] == 1
        assert summary["minor"] == 1
        assert summary["patch"] == 1

    def test_empty(self):
        summary = get_update_summary([])
        assert summary["total"] == 0
