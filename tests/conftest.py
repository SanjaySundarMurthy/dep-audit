"""Shared fixtures for dep-audit tests."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from dep_audit.models import Dependency, EcosystemType


@pytest.fixture
def tmp_project(tmp_path):
    """Helper to write project files and return directory."""

    def _write(filename: str, content: str) -> Path:
        fp = tmp_path / filename
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(textwrap.dedent(content).strip() + "\n")
        return fp

    _write.path = tmp_path
    return _write


@pytest.fixture
def python_project(tmp_project):
    """A Python project with requirements.txt and pyproject.toml."""
    tmp_project("requirements.txt", """
        click>=8.0
        rich>=13.0
        requests==2.31.0
        flask==3.0.0
    """)
    tmp_project("pyproject.toml", """
        [build-system]
        requires = ["hatchling"]
        build-backend = "hatchling.build"

        [project]
        name = "myapp"
        version = "1.0.0"
        dependencies = [
            "click>=8.0",
            "rich>=13.0",
            "requests>=2.28",
        ]

        [project.optional-dependencies]
        dev = [
            "pytest>=8.0",
            "ruff>=0.4",
        ]
    """)
    return tmp_project.path


@pytest.fixture
def node_project(tmp_project):
    """A Node.js project with package.json."""
    tmp_project("package.json", json.dumps({
        "name": "myapp",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "^4.17.21",
        },
        "devDependencies": {
            "jest": "^29.7.0",
            "eslint": "^8.56.0",
        },
    }, indent=2))
    return tmp_project.path


@pytest.fixture
def go_project(tmp_project):
    """A Go project with go.mod."""
    tmp_project("go.mod", """
        module github.com/example/myapp

        go 1.21

        require (
            github.com/gin-gonic/gin v1.9.1
            github.com/stretchr/testify v1.8.4
            golang.org/x/text v0.14.0 // indirect
        )
    """)
    return tmp_project.path


@pytest.fixture
def rust_project(tmp_project):
    """A Rust project with Cargo.toml."""
    tmp_project("Cargo.toml", """
        [package]
        name = "myapp"
        version = "0.1.0"

        [dependencies]
        serde = "1.0"
        tokio = { version = "1.35", features = ["full"] }

        [dev-dependencies]
        assert_cmd = "2.0"
    """)
    return tmp_project.path


@pytest.fixture
def sample_deps():
    """A list of sample dependencies for testing."""
    return [
        Dependency(name="click", version_spec=">=8.0", installed_version="8.1.7",
                   license="BSD-3-Clause", ecosystem=EcosystemType.PYTHON, is_direct=True),
        Dependency(name="rich", version_spec=">=13.0", installed_version="13.7.0",
                   license="MIT", ecosystem=EcosystemType.PYTHON, is_direct=True),
        Dependency(name="requests", version_spec="==2.31.0", installed_version="2.31.0",
                   latest_version="2.32.0", license="Apache-2.0", ecosystem=EcosystemType.PYTHON),
        Dependency(name="flask", version_spec="==3.0.0", installed_version="3.0.0",
                   latest_version="3.0.0", license="BSD-3-Clause", ecosystem=EcosystemType.PYTHON),
        Dependency(name="pytest", version_spec=">=8.0", installed_version="8.0.0",
                   license="MIT", ecosystem=EcosystemType.PYTHON, is_dev=True),
        Dependency(name="evil-lib", version_spec="==1.0", installed_version="1.0.0",
                   license="GPL-3.0", ecosystem=EcosystemType.PYTHON),
    ]
