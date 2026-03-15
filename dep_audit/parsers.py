"""Parsers for dependency manifest files."""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from dep_audit.models import Dependency, EcosystemType


# ── Detection ───────────────────────────────────────────────────

MANIFEST_FILES = {
    "requirements.txt": EcosystemType.PYTHON,
    "requirements-dev.txt": EcosystemType.PYTHON,
    "requirements_dev.txt": EcosystemType.PYTHON,
    "requirements-test.txt": EcosystemType.PYTHON,
    "dev-requirements.txt": EcosystemType.PYTHON,
    "setup.py": EcosystemType.PYTHON,
    "setup.cfg": EcosystemType.PYTHON,
    "pyproject.toml": EcosystemType.PYTHON,
    "Pipfile": EcosystemType.PYTHON,
    "Pipfile.lock": EcosystemType.PYTHON,
    "poetry.lock": EcosystemType.PYTHON,
    "package.json": EcosystemType.NODEJS,
    "package-lock.json": EcosystemType.NODEJS,
    "yarn.lock": EcosystemType.NODEJS,
    "Cargo.toml": EcosystemType.RUST,
    "Cargo.lock": EcosystemType.RUST,
    "go.mod": EcosystemType.GO,
    "go.sum": EcosystemType.GO,
    "Gemfile": EcosystemType.RUBY,
    "Gemfile.lock": EcosystemType.RUBY,
    "pom.xml": EcosystemType.JAVA,
    "build.gradle": EcosystemType.JAVA,
    "composer.json": EcosystemType.PHP,
    "composer.lock": EcosystemType.PHP,
}


def detect_ecosystem(project_path: str) -> tuple[EcosystemType, list[str]]:
    """Detect the project ecosystem and find manifest files."""
    found = []
    ecosystem = EcosystemType.UNKNOWN

    for name, eco in MANIFEST_FILES.items():
        full_path = os.path.join(project_path, name)
        if os.path.exists(full_path):
            found.append(full_path)
            if ecosystem == EcosystemType.UNKNOWN:
                ecosystem = eco

    return ecosystem, found


# ── Python Parsers ──────────────────────────────────────────────


def parse_requirements_txt(file_path: str) -> list[Dependency]:
    """Parse a requirements.txt file."""
    deps = []
    if not os.path.exists(file_path):
        return deps

    is_dev = any(x in os.path.basename(file_path).lower() for x in ("dev", "test"))

    try:
        with open(file_path, encoding="utf-8") as f:
            for line_num, raw_line in enumerate(f, 1):
                line = raw_line.strip()

                # Skip empty, comments, options
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Skip editable installs and URLs
                if line.startswith("git+") or line.startswith("http"):
                    continue

                dep = _parse_python_requirement(line)
                if dep:
                    dep.ecosystem = EcosystemType.PYTHON
                    dep.is_dev = is_dev
                    deps.append(dep)
    except (OSError, UnicodeDecodeError):
        pass

    return deps


def _parse_python_requirement(line: str) -> Optional[Dependency]:
    """Parse a single Python requirement line like 'package>=1.0,<2.0'."""
    # Remove inline comments and extras
    line = re.sub(r"\s*#.*$", "", line).strip()
    if not line:
        return None

    # Remove environment markers
    line = re.split(r"\s*;\s*", line)[0]

    # Remove extras like [security]
    line = re.sub(r"\[.*?\]", "", line)

    # Split name and version spec
    match = re.match(r"^([A-Za-z0-9][\w.-]*)\s*(.*)", line)
    if not match:
        return None

    name = match.group(1).strip()
    version_spec = match.group(2).strip()

    # Extract pinned version if available
    installed = ""
    if version_spec.startswith("=="):
        installed = version_spec[2:].strip()

    return Dependency(name=name, version_spec=version_spec, installed_version=installed)


def parse_pyproject_toml(file_path: str) -> list[Dependency]:
    """Parse dependencies from pyproject.toml."""
    deps = []
    if not os.path.exists(file_path):
        return deps

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return deps

    # Parse [project] dependencies
    dep_lines = _extract_toml_list(content, "dependencies")
    for line in dep_lines:
        dep = _parse_python_requirement(line.strip().strip('"').strip("'"))
        if dep:
            dep.ecosystem = EcosystemType.PYTHON
            dep.is_direct = True
            deps.append(dep)

    # Parse optional-dependencies (dev)
    dev_sections = ["dev", "test", "testing", "development"]
    for section in dev_sections:
        dev_lines = _extract_toml_optional_deps(content, section)
        for line in dev_lines:
            dep = _parse_python_requirement(line.strip().strip('"').strip("'"))
            if dep:
                dep.ecosystem = EcosystemType.PYTHON
                dep.is_dev = True
                dep.is_direct = True
                deps.append(dep)

    return deps


def _extract_toml_list(content: str, key: str) -> list[str]:
    """Extract a TOML list value (simple parser)."""
    pattern = rf"^{re.escape(key)}\s*=\s*\[([^\]]*)\]"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if not match:
        return []

    block = match.group(1)
    items = []
    for item in re.findall(r'"([^"]*)"', block):
        items.append(item)
    for item in re.findall(r"'([^']*)'", block):
        if item not in items:
            items.append(item)
    return items


def _extract_toml_optional_deps(content: str, section: str) -> list[str]:
    """Extract optional dependency list from pyproject.toml."""
    pattern = rf"^\[project\.optional-dependencies\].*?^{re.escape(section)}\s*=\s*\[([^\]]*)\]"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if not match:
        # Try inline section
        pattern2 = rf'{re.escape(section)}\s*=\s*\[([^\]]*)\]'
        match = re.search(pattern2, content, re.DOTALL)
        if not match:
            return []

    block = match.group(1)
    items = []
    for item in re.findall(r'"([^"]*)"', block):
        items.append(item)
    for item in re.findall(r"'([^']*)'", block):
        if item not in items:
            items.append(item)
    return items


# ── Node.js Parsers ─────────────────────────────────────────────


def parse_package_json(file_path: str) -> list[Dependency]:
    """Parse dependencies from package.json."""
    deps = []
    if not os.path.exists(file_path):
        return deps

    try:
        with open(file_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return deps

    # Production dependencies
    for name, version in data.get("dependencies", {}).items():
        deps.append(Dependency(
            name=name,
            version_spec=version,
            installed_version=version.lstrip("^~>=<"),
            ecosystem=EcosystemType.NODEJS,
            is_direct=True,
        ))

    # Dev dependencies
    for name, version in data.get("devDependencies", {}).items():
        deps.append(Dependency(
            name=name,
            version_spec=version,
            installed_version=version.lstrip("^~>=<"),
            ecosystem=EcosystemType.NODEJS,
            is_direct=True,
            is_dev=True,
        ))

    return deps


# ── Go Parsers ──────────────────────────────────────────────────


def parse_go_mod(file_path: str) -> list[Dependency]:
    """Parse dependencies from go.mod."""
    deps = []
    if not os.path.exists(file_path):
        return deps

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return deps

    in_require = False
    for line in content.splitlines():
        stripped = line.strip()

        if stripped == "require (":
            in_require = True
            continue
        if stripped == ")" and in_require:
            in_require = False
            continue

        if in_require and stripped and not stripped.startswith("//"):
            parts = stripped.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].lstrip("v")
                is_indirect = "// indirect" in line
                deps.append(Dependency(
                    name=name,
                    version_spec=parts[1],
                    installed_version=version,
                    ecosystem=EcosystemType.GO,
                    is_direct=not is_indirect,
                ))

        # Single-line require
        if stripped.startswith("require ") and "(" not in stripped:
            parts = stripped[8:].strip().split()
            if len(parts) >= 2:
                deps.append(Dependency(
                    name=parts[0],
                    version_spec=parts[1],
                    installed_version=parts[1].lstrip("v"),
                    ecosystem=EcosystemType.GO,
                    is_direct=True,
                ))

    return deps


# ── Rust Parsers ────────────────────────────────────────────────


def parse_cargo_toml(file_path: str) -> list[Dependency]:
    """Parse dependencies from Cargo.toml."""
    deps = []
    if not os.path.exists(file_path):
        return deps

    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return deps

    # [dependencies]
    deps.extend(_parse_cargo_section(content, "dependencies", is_dev=False))
    # [dev-dependencies]
    deps.extend(_parse_cargo_section(content, "dev-dependencies", is_dev=True))

    return deps


def _parse_cargo_section(content: str, section: str, is_dev: bool) -> list[Dependency]:
    """Parse a [dependencies] or [dev-dependencies] section from Cargo.toml."""
    deps = []
    pattern = rf"^\[{re.escape(section)}\]\s*$(.*?)(?=^\[|\Z)"
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if not match:
        return deps

    block = match.group(1)
    for line in block.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # name = "version" or name = { version = "..." }
        m = re.match(r'^(\w[\w-]*)\s*=\s*"([^"]*)"', line)
        if m:
            deps.append(Dependency(
                name=m.group(1),
                version_spec=m.group(2),
                installed_version=m.group(2).lstrip("^~>=<"),
                ecosystem=EcosystemType.RUST,
                is_direct=True,
                is_dev=is_dev,
            ))
            continue

        m2 = re.match(r'^(\w[\w-]*)\s*=\s*\{.*?version\s*=\s*"([^"]*)"', line)
        if m2:
            deps.append(Dependency(
                name=m2.group(1),
                version_spec=m2.group(2),
                installed_version=m2.group(2).lstrip("^~>=<"),
                ecosystem=EcosystemType.RUST,
                is_direct=True,
                is_dev=is_dev,
            ))

    return deps


# ── Ruby Parsers ────────────────────────────────────────────────


def parse_gemfile(file_path: str) -> list[Dependency]:
    """Parse dependencies from Gemfile."""
    deps = []
    if not os.path.exists(file_path):
        return deps

    try:
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                m = re.match(r'''gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?''', line)
                if m:
                    name = m.group(1)
                    version = m.group(2) or ""
                    in_dev = ":development" in line or ":test" in line
                    deps.append(Dependency(
                        name=name,
                        version_spec=version,
                        installed_version=version.lstrip("~>=<"),
                        ecosystem=EcosystemType.RUBY,
                        is_direct=True,
                        is_dev=in_dev,
                    ))
    except (OSError, UnicodeDecodeError):
        pass

    return deps


# ── Unified Parser ──────────────────────────────────────────────


def parse_manifest(file_path: str) -> list[Dependency]:
    """Parse any supported manifest file."""
    basename = os.path.basename(file_path)

    parsers = {
        "requirements": parse_requirements_txt,
        "pyproject.toml": parse_pyproject_toml,
        "package.json": parse_package_json,
        "go.mod": parse_go_mod,
        "Cargo.toml": parse_cargo_toml,
        "Gemfile": parse_gemfile,
    }

    for key, parser in parsers.items():
        if key in basename:
            return parser(file_path)

    return []


def parse_all_manifests(project_path: str) -> list[Dependency]:
    """Parse all manifest files in a project directory."""
    _, manifests = detect_ecosystem(project_path)
    all_deps: dict[str, Dependency] = {}

    for manifest in manifests:
        basename = os.path.basename(manifest)
        # Skip lock files for parsing (they add duplicate info)
        if basename in ("package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock"):
            continue

        deps = parse_manifest(manifest)
        for dep in deps:
            key = f"{dep.name}:{dep.ecosystem.value}"
            if key not in all_deps:
                all_deps[key] = dep
            else:
                # Merge — prefer the one with more info
                existing = all_deps[key]
                if dep.installed_version and not existing.installed_version:
                    existing.installed_version = dep.installed_version
                if dep.is_dev:
                    existing.is_dev = True

    return list(all_deps.values())
