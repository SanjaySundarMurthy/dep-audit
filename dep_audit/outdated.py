"""Outdated dependency checking and PyPI/npm version lookups."""

from __future__ import annotations

from typing import Optional

from dep_audit.models import Dependency, EcosystemType


def check_outdated_pypi(dep: Dependency) -> Optional[str]:
    """Check PyPI for the latest version of a Python package."""
    try:
        import requests
        resp = requests.get(
            f"https://pypi.org/pypi/{dep.name}/json",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            info = data.get("info", {})
            latest = info.get("version", "")
            # Also enrich metadata
            if not dep.license:
                lic = info.get("license", "")
                if lic and len(lic) < 100:
                    dep.license = lic
            if not dep.summary:
                dep.summary = info.get("summary", "")
            if not dep.homepage:
                dep.homepage = info.get("home_page", "") or info.get("project_url", "")
            dep.python_requires = info.get("requires_python", "") or ""
            dep.requires_dist = info.get("requires_dist", []) or []
            return latest
    except Exception:
        pass
    return None


def check_outdated_npm(dep: Dependency) -> Optional[str]:
    """Check npm for the latest version of a Node.js package."""
    try:
        import requests
        resp = requests.get(
            f"https://registry.npmjs.org/{dep.name}/latest",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            latest = data.get("version", "")
            if not dep.license:
                dep.license = data.get("license", "")
            if not dep.summary:
                dep.summary = data.get("description", "")
            return latest
    except Exception:
        pass
    return None


def check_outdated(dep: Dependency) -> Dependency:
    """Check if a dependency is outdated and enrich with latest version."""
    latest = None

    if dep.ecosystem == EcosystemType.PYTHON:
        latest = check_outdated_pypi(dep)
    elif dep.ecosystem == EcosystemType.NODEJS:
        latest = check_outdated_npm(dep)

    if latest:
        dep.latest_version = latest

    return dep


def check_all_outdated(deps: list[Dependency]) -> list[Dependency]:
    """Check all dependencies for updates. Returns list of outdated deps."""
    outdated = []
    for dep in deps:
        if not dep.installed_version:
            continue
        check_outdated(dep)
        if dep.is_outdated:
            outdated.append(dep)
    return outdated


def compare_versions(current: str, latest: str) -> str:
    """Compare two version strings and return update type."""
    try:
        cur_parts = current.split(".")
        lat_parts = latest.split(".")

        if len(cur_parts) >= 1 and len(lat_parts) >= 1:
            if cur_parts[0] != lat_parts[0]:
                return "major"
        if len(cur_parts) >= 2 and len(lat_parts) >= 2:
            if cur_parts[1] != lat_parts[1]:
                return "minor"
        if cur_parts != lat_parts:
            return "patch"
    except (IndexError, ValueError):
        return "unknown"

    return ""


def get_update_summary(outdated: list[Dependency]) -> dict:
    """Summarize outdated dependencies by update type."""
    summary = {"major": 0, "minor": 0, "patch": 0, "unknown": 0, "total": len(outdated)}

    for dep in outdated:
        ut = dep.update_type or "unknown"
        summary[ut] = summary.get(ut, 0) + 1

    return summary
