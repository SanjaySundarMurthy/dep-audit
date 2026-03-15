"""Tests for dep_audit.parsers."""

from __future__ import annotations

import json


from dep_audit.models import EcosystemType
from dep_audit.parsers import (
    detect_ecosystem,
    parse_all_manifests,
    parse_cargo_toml,
    parse_gemfile,
    parse_go_mod,
    parse_manifest,
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
    _parse_python_requirement,
)


# ── detect_ecosystem ────────────────────────────────────────────

class TestDetectEcosystem:
    def test_python(self, python_project):
        eco, files = detect_ecosystem(str(python_project))
        assert eco == EcosystemType.PYTHON
        assert len(files) >= 1

    def test_nodejs(self, node_project):
        eco, files = detect_ecosystem(str(node_project))
        assert eco == EcosystemType.NODEJS
        assert len(files) >= 1

    def test_go(self, go_project):
        eco, files = detect_ecosystem(str(go_project))
        assert eco == EcosystemType.GO

    def test_rust(self, rust_project):
        eco, files = detect_ecosystem(str(rust_project))
        assert eco == EcosystemType.RUST

    def test_unknown(self, tmp_path):
        eco, files = detect_ecosystem(str(tmp_path))
        assert eco == EcosystemType.UNKNOWN
        assert len(files) == 0


# ── parse_requirements_txt ──────────────────────────────────────

class TestParseRequirementsTxt:
    def test_basic(self, python_project):
        deps = parse_requirements_txt(str(python_project / "requirements.txt"))
        names = [d.name for d in deps]
        assert "click" in names
        assert "rich" in names
        assert "requests" in names
        assert "flask" in names

    def test_pinned_version(self, python_project):
        deps = parse_requirements_txt(str(python_project / "requirements.txt"))
        req = next(d for d in deps if d.name == "requests")
        assert req.installed_version == "2.31.0"

    def test_comments_skipped(self, tmp_path):
        fp = tmp_path / "requirements.txt"
        fp.write_text("# comment\nflask==3.0.0\n")
        deps = parse_requirements_txt(str(fp))
        assert len(deps) == 1

    def test_empty_lines_skipped(self, tmp_path):
        fp = tmp_path / "requirements.txt"
        fp.write_text("flask==3.0\n\n\nclick>=8.0\n")
        deps = parse_requirements_txt(str(fp))
        assert len(deps) == 2

    def test_options_skipped(self, tmp_path):
        fp = tmp_path / "requirements.txt"
        fp.write_text("-i https://pypi.org/simple\nflask==3.0\n--no-binary :all:\n")
        deps = parse_requirements_txt(str(fp))
        assert len(deps) == 1

    def test_extras(self, tmp_path):
        fp = tmp_path / "requirements.txt"
        fp.write_text("requests[security]>=2.28\n")
        deps = parse_requirements_txt(str(fp))
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_environment_markers(self, tmp_path):
        fp = tmp_path / "requirements.txt"
        fp.write_text('pywin32>=300; sys_platform == "win32"\n')
        deps = parse_requirements_txt(str(fp))
        assert len(deps) == 1
        assert deps[0].name == "pywin32"

    def test_nonexistent(self, tmp_path):
        deps = parse_requirements_txt(str(tmp_path / "nope.txt"))
        assert deps == []

    def test_dev_flag(self, tmp_path):
        fp = tmp_path / "requirements-dev.txt"
        fp.write_text("pytest>=8.0\n")
        deps = parse_requirements_txt(str(fp))
        assert deps[0].is_dev is True

    def test_inline_comments(self, tmp_path):
        fp = tmp_path / "requirements.txt"
        fp.write_text("flask==3.0.0  # web framework\n")
        deps = parse_requirements_txt(str(fp))
        assert len(deps) == 1
        assert deps[0].name == "flask"


# ── _parse_python_requirement ───────────────────────────────────

class TestParsePythonRequirement:
    def test_pinned(self):
        dep = _parse_python_requirement("flask==3.0.0")
        assert dep.name == "flask"
        assert dep.installed_version == "3.0.0"

    def test_range(self):
        dep = _parse_python_requirement("click>=8.0,<9.0")
        assert dep.name == "click"
        assert dep.version_spec == ">=8.0,<9.0"

    def test_no_version(self):
        dep = _parse_python_requirement("flask")
        assert dep.name == "flask"
        assert dep.version_spec == ""

    def test_with_extras(self):
        dep = _parse_python_requirement("requests[security]>=2.28")
        assert dep.name == "requests"

    def test_empty(self):
        dep = _parse_python_requirement("")
        assert dep is None

    def test_export_prefix(self):
        dep = _parse_python_requirement("export flask==3.0")
        # This isn't typical for requirements but should handle gracefully
        assert dep is not None


# ── parse_pyproject_toml ────────────────────────────────────────

class TestParsePyprojectToml:
    def test_basic(self, python_project):
        deps = parse_pyproject_toml(str(python_project / "pyproject.toml"))
        names = [d.name for d in deps]
        assert "click" in names
        assert "rich" in names
        assert "requests" in names

    def test_dev_deps(self, python_project):
        deps = parse_pyproject_toml(str(python_project / "pyproject.toml"))
        dev_deps = [d for d in deps if d.is_dev]
        dev_names = [d.name for d in dev_deps]
        assert "pytest" in dev_names
        assert "ruff" in dev_names

    def test_nonexistent(self, tmp_path):
        deps = parse_pyproject_toml(str(tmp_path / "pyproject.toml"))
        assert deps == []

    def test_no_deps_section(self, tmp_path):
        fp = tmp_path / "pyproject.toml"
        fp.write_text('[build-system]\nrequires = ["hatchling"]\n')
        deps = parse_pyproject_toml(str(fp))
        assert deps == []


# ── parse_package_json ──────────────────────────────────────────

class TestParsePackageJson:
    def test_basic(self, node_project):
        deps = parse_package_json(str(node_project / "package.json"))
        names = [d.name for d in deps]
        assert "express" in names
        assert "lodash" in names

    def test_dev_deps(self, node_project):
        deps = parse_package_json(str(node_project / "package.json"))
        dev = [d for d in deps if d.is_dev]
        assert any(d.name == "jest" for d in dev)

    def test_version_stripping(self, node_project):
        deps = parse_package_json(str(node_project / "package.json"))
        express = next(d for d in deps if d.name == "express")
        assert express.installed_version == "4.18.2"

    def test_empty_deps(self, tmp_path):
        fp = tmp_path / "package.json"
        fp.write_text(json.dumps({"name": "test", "version": "1.0"}))
        deps = parse_package_json(str(fp))
        assert deps == []

    def test_nonexistent(self, tmp_path):
        deps = parse_package_json(str(tmp_path / "package.json"))
        assert deps == []


# ── parse_go_mod ────────────────────────────────────────────────

class TestParseGoMod:
    def test_basic(self, go_project):
        deps = parse_go_mod(str(go_project / "go.mod"))
        names = [d.name for d in deps]
        assert "github.com/gin-gonic/gin" in names

    def test_indirect(self, go_project):
        deps = parse_go_mod(str(go_project / "go.mod"))
        indirect = [d for d in deps if not d.is_direct]
        assert any("text" in d.name for d in indirect)

    def test_version_parsing(self, go_project):
        deps = parse_go_mod(str(go_project / "go.mod"))
        gin = next(d for d in deps if "gin" in d.name)
        assert gin.installed_version == "1.9.1"

    def test_nonexistent(self, tmp_path):
        deps = parse_go_mod(str(tmp_path / "go.mod"))
        assert deps == []


# ── parse_cargo_toml ────────────────────────────────────────────

class TestParseCargoToml:
    def test_basic(self, rust_project):
        deps = parse_cargo_toml(str(rust_project / "Cargo.toml"))
        names = [d.name for d in deps]
        assert "serde" in names
        assert "tokio" in names

    def test_dev_deps(self, rust_project):
        deps = parse_cargo_toml(str(rust_project / "Cargo.toml"))
        dev = [d for d in deps if d.is_dev]
        assert any(d.name == "assert_cmd" for d in dev)

    def test_inline_table(self, rust_project):
        deps = parse_cargo_toml(str(rust_project / "Cargo.toml"))
        tokio = next(d for d in deps if d.name == "tokio")
        assert tokio.installed_version  # Should have parsed version from inline table

    def test_nonexistent(self, tmp_path):
        deps = parse_cargo_toml(str(tmp_path / "Cargo.toml"))
        assert deps == []


# ── parse_gemfile ───────────────────────────────────────────────

class TestParseGemfile:
    def test_basic(self, tmp_path):
        fp = tmp_path / "Gemfile"
        fp.write_text("gem 'rails', '~> 7.0'\ngem 'puma', '~> 6.0'\n")
        deps = parse_gemfile(str(fp))
        assert len(deps) == 2
        assert deps[0].name == "rails"

    def test_no_version(self, tmp_path):
        fp = tmp_path / "Gemfile"
        fp.write_text("gem 'rspec'\n")
        deps = parse_gemfile(str(fp))
        assert len(deps) == 1
        assert deps[0].version_spec == ""

    def test_comments_skipped(self, tmp_path):
        fp = tmp_path / "Gemfile"
        fp.write_text("# comment\ngem 'rails'\n")
        deps = parse_gemfile(str(fp))
        assert len(deps) == 1

    def test_nonexistent(self, tmp_path):
        deps = parse_gemfile(str(tmp_path / "Gemfile"))
        assert deps == []


# ── parse_manifest (unified) ───────────────────────────────────

class TestParseManifest:
    def test_requirements(self, python_project):
        deps = parse_manifest(str(python_project / "requirements.txt"))
        assert len(deps) >= 1

    def test_package_json(self, node_project):
        deps = parse_manifest(str(node_project / "package.json"))
        assert len(deps) >= 1

    def test_go_mod(self, go_project):
        deps = parse_manifest(str(go_project / "go.mod"))
        assert len(deps) >= 1


# ── parse_all_manifests ────────────────────────────────────────

class TestParseAllManifests:
    def test_python(self, python_project):
        deps = parse_all_manifests(str(python_project))
        assert len(deps) >= 3  # click, rich, requests from both files

    def test_dedup(self, python_project):
        deps = parse_all_manifests(str(python_project))
        names = [d.name for d in deps]
        # Should not have duplicate click entries
        assert names.count("click") == 1

    def test_empty_project(self, tmp_path):
        deps = parse_all_manifests(str(tmp_path))
        assert deps == []
