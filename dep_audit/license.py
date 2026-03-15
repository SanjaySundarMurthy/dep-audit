"""License compliance checking."""

from __future__ import annotations

from typing import Optional

from dep_audit.models import (
    Dependency,
    EcosystemType,
    LicenseIssue,
    LicenseRisk,
    classify_license,
)


# Common license policies
STRICT_POLICY = {
    "allowed": {LicenseRisk.LOW},
    "name": "strict",
    "description": "Only permissive licenses (MIT, Apache, BSD, ISC) allowed",
}

MODERATE_POLICY = {
    "allowed": {LicenseRisk.LOW, LicenseRisk.MEDIUM},
    "name": "moderate",
    "description": "Permissive and weak copyleft (LGPL, MPL) allowed",
}

PERMISSIVE_POLICY = {
    "allowed": {LicenseRisk.LOW, LicenseRisk.MEDIUM, LicenseRisk.HIGH},
    "name": "permissive",
    "description": "All known licenses allowed, only unknown flagged",
}

POLICIES = {
    "strict": STRICT_POLICY,
    "moderate": MODERATE_POLICY,
    "permissive": PERMISSIVE_POLICY,
}


def check_license_compliance(
    deps: list[Dependency],
    policy: str = "moderate",
    denied_licenses: Optional[list[str]] = None,
) -> list[LicenseIssue]:
    """Check all dependencies against a license policy."""
    issues = []
    policy_config = POLICIES.get(policy, MODERATE_POLICY)
    allowed_risks = policy_config["allowed"]

    denied = set(denied_licenses) if denied_licenses else set()

    for dep in deps:
        if not dep.license:
            issues.append(LicenseIssue(
                package=dep.name,
                version=dep.installed_version,
                license="Unknown",
                risk=LicenseRisk.UNKNOWN,
                message=f"No license information found for {dep.name}",
                suggestion="Check the package repository for license details",
            ))
            continue

        risk = classify_license(dep.license)
        dep.license_risk = risk

        # Check against denied list
        if dep.license in denied or dep.license.upper() in {d.upper() for d in denied}:
            issues.append(LicenseIssue(
                package=dep.name,
                version=dep.installed_version,
                license=dep.license,
                risk=LicenseRisk.HIGH,
                message=f"License '{dep.license}' is explicitly denied",
                suggestion=f"Remove or replace {dep.name} with a differently licensed alternative",
            ))
            continue

        # Check against policy
        if risk not in allowed_risks and risk != LicenseRisk.UNKNOWN:
            issues.append(LicenseIssue(
                package=dep.name,
                version=dep.installed_version,
                license=dep.license,
                risk=risk,
                message=f"License '{dep.license}' ({risk.value} risk) not allowed under '{policy}' policy",
                suggestion=_suggest_action(risk, dep),
            ))
        elif risk == LicenseRisk.UNKNOWN:
            issues.append(LicenseIssue(
                package=dep.name,
                version=dep.installed_version,
                license=dep.license,
                risk=LicenseRisk.UNKNOWN,
                message=f"License '{dep.license}' could not be classified",
                suggestion="Manually review the license for compliance",
            ))

    return issues


def _suggest_action(risk: LicenseRisk, dep: Dependency) -> str:
    """Generate a suggestion based on risk level."""
    if risk == LicenseRisk.HIGH:
        return f"Replace {dep.name} — copyleft licenses (GPL/AGPL) require disclosure of your source code"
    elif risk == LicenseRisk.MEDIUM:
        return f"Review {dep.name} — weak copyleft may impose obligations on modifications"
    return f"Review license terms for {dep.name}"


def get_license_summary(deps: list[Dependency]) -> dict:
    """Generate a license summary for all dependencies."""
    licenses: dict[str, int] = {}
    risks: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "unknown": 0}

    for dep in deps:
        lic = dep.license or "Unknown"
        licenses[lic] = licenses.get(lic, 0) + 1

        risk = classify_license(dep.license)
        risks[risk.value] = risks.get(risk.value, 0) + 1

    return {
        "total": len(deps),
        "licenses": dict(sorted(licenses.items(), key=lambda x: -x[1])),
        "risk_breakdown": risks,
        "unique_licenses": len(licenses),
    }


def fetch_pypi_license(package_name: str) -> Optional[str]:
    """Fetch license information from PyPI."""
    try:
        import requests
        resp = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            info = data.get("info", {})
            license_str = info.get("license", "")
            if license_str and license_str.strip() and len(license_str.strip()) < 100:
                return license_str.strip()
            # Try classifiers
            classifiers = info.get("classifiers", [])
            for c in classifiers:
                if c.startswith("License"):
                    parts = c.split(" :: ")
                    if len(parts) >= 3:
                        return parts[-1]
    except Exception:
        pass
    return None


def fetch_npm_license(package_name: str) -> Optional[str]:
    """Fetch license information from npm."""
    try:
        import requests
        resp = requests.get(
            f"https://registry.npmjs.org/{package_name}/latest",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("license", None)
    except Exception:
        pass
    return None


def enrich_licenses(deps: list[Dependency]) -> list[Dependency]:
    """Enrich dependencies with license information from package registries."""
    for dep in deps:
        if dep.license:
            continue

        license_str = None
        if dep.ecosystem == EcosystemType.PYTHON:
            license_str = fetch_pypi_license(dep.name)
        elif dep.ecosystem == EcosystemType.NODEJS:
            license_str = fetch_npm_license(dep.name)

        if license_str:
            dep.license = license_str
            dep.license_risk = classify_license(license_str)

    return deps
