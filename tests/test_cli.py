"""Tests for dep_audit.cli (Click commands)."""

from __future__ import annotations


import pytest
from click.testing import CliRunner

from dep_audit.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestVersion:
    def test_version_flag(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output


class TestAuditCommand:
    def test_audit_python(self, runner, python_project):
        result = runner.invoke(cli, ["audit", "--no-vuln", "--no-outdated", "--no-license", str(python_project)])
        assert result.exit_code == 0

    def test_audit_node(self, runner, node_project):
        result = runner.invoke(cli, ["audit", "--no-vuln", "--no-outdated", "--no-license", str(node_project)])
        assert result.exit_code == 0

    def test_audit_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["audit", str(tmp_path)])
        assert "No supported" in result.output or "No dependencies" in result.output

    def test_audit_json(self, runner, python_project):
        result = runner.invoke(cli, ["audit", "--no-vuln", "--no-outdated", "--no-license", "--json-output", str(python_project)])
        assert result.exit_code == 0

    def test_audit_strict_policy(self, runner, python_project):
        result = runner.invoke(cli, ["audit", "--no-vuln", "--no-outdated", "--policy", "strict", str(python_project)])
        # May find license issues
        assert result.exit_code in (0, 1)


class TestScanCommand:
    def test_scan_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["scan", str(tmp_path)])
        assert "No dependencies" in result.output


class TestLicensesCommand:
    def test_licenses_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["licenses", str(tmp_path)])
        assert "No dependencies" in result.output

    def test_licenses_summary(self, runner, python_project):
        result = runner.invoke(cli, ["licenses", "--summary", str(python_project)])
        # Should show some output about license distribution
        assert result.exit_code == 0


class TestOutdatedCommand:
    def test_outdated_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["outdated", str(tmp_path)])
        assert "No dependencies" in result.output


class TestTreeCommand:
    def test_tree_python(self, runner, python_project):
        result = runner.invoke(cli, ["tree", str(python_project)])
        assert result.exit_code == 0

    def test_tree_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["tree", str(tmp_path)])
        assert "No dependencies" in result.output


class TestListCommand:
    def test_list_python(self, runner, python_project):
        result = runner.invoke(cli, ["list", str(python_project)])
        assert result.exit_code == 0

    def test_list_json(self, runner, python_project):
        result = runner.invoke(cli, ["list", "--json-output", str(python_project)])
        assert result.exit_code == 0

    def test_list_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["list", str(tmp_path)])
        assert "No dependencies" in result.output

    def test_list_with_dev(self, runner, python_project):
        result = runner.invoke(cli, ["list", "--dev", str(python_project)])
        assert result.exit_code == 0


class TestInfoCommand:
    def test_info_python(self, runner, python_project):
        result = runner.invoke(cli, ["info", str(python_project)])
        assert result.exit_code == 0
        assert "Python" in result.output

    def test_info_node(self, runner, node_project):
        result = runner.invoke(cli, ["info", str(node_project)])
        assert result.exit_code == 0
        assert "Nodejs" in result.output

    def test_info_empty(self, runner, tmp_path):
        result = runner.invoke(cli, ["info", str(tmp_path)])
        assert "Unknown" in result.output
