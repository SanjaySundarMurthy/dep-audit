"""CLI commands for dep-audit."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from dep_audit import __version__
from dep_audit.license import (
    check_license_compliance,
    enrich_licenses,
    get_license_summary,
)
from dep_audit.models import AuditResult, EcosystemType
from dep_audit.outdated import check_all_outdated
from dep_audit.output import (
    console,
    render_audit_result,
    render_dependency_list,
    render_license_issues,
    render_license_summary,
    render_outdated,
    render_tree,
    render_vulnerabilities,
)
from dep_audit.parsers import detect_ecosystem, parse_all_manifests
from dep_audit.tree import build_tree_from_deps
from dep_audit.vulnerability import query_osv_batch


@click.group()
@click.version_option(version=__version__, prog_name="dep-audit")
def cli():
    """Dependency auditing — vulnerability scanning, license compliance, outdated detection."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--no-vuln", is_flag=True, help="Skip vulnerability scanning.")
@click.option("--no-outdated", is_flag=True, help="Skip outdated checking.")
@click.option("--no-license", is_flag=True, help="Skip license checking.")
@click.option("--policy", type=click.Choice(["strict", "moderate", "permissive"]), default="moderate",
              help="License policy (default: moderate).")
@click.option("--json-output", "-j", is_flag=True, help="Output results as JSON.")
@click.option("--strict", is_flag=True, help="Exit 1 on any vulnerability or license issue.")
def audit(path: str, no_vuln: bool, no_outdated: bool, no_license: bool,
          policy: str, json_output: bool, strict: bool):
    """Full dependency audit — vulnerabilities, licenses, outdated packages.

    Scans the project at PATH for dependency issues.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    ecosystem, manifests = detect_ecosystem(str(target))
    if ecosystem == EcosystemType.UNKNOWN:
        console.print("  [yellow]No supported dependency files found.[/yellow]")
        sys.exit(0)

    # Parse dependencies
    deps = parse_all_manifests(str(target))
    if not deps:
        console.print("  [yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    result = AuditResult(
        project_path=str(target),
        ecosystem=ecosystem,
        total_dependencies=len(deps),
        direct_dependencies=sum(1 for d in deps if d.is_direct and not d.is_dev),
        dev_dependencies=sum(1 for d in deps if d.is_dev),
        dependencies=deps,
    )

    # Enrich with license info
    if not no_license:
        enrich_licenses(deps)

    # Vulnerability scan
    if not no_vuln:
        vulns = query_osv_batch(deps)
        result.vulnerabilities = vulns

    # Outdated check
    if not no_outdated:
        outdated = check_all_outdated(deps)
        result.outdated = outdated

    # License check
    if not no_license:
        license_issues = check_license_compliance(deps, policy=policy)
        result.license_issues = license_issues

    # Build tree
    project_name = target.name
    result.tree = build_tree_from_deps(deps, project_name)

    if json_output:
        _print_json(result)
    else:
        render_audit_result(result)

    if strict and (result.vuln_count > 0 or result.license_issue_count > 0):
        sys.exit(1)
    elif result.has_critical:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def scan(path: str):
    """Scan for vulnerabilities only.

    Checks all dependencies against the OSV vulnerability database.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    deps = parse_all_manifests(str(target))
    if not deps:
        console.print("  [yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    console.print(f"\n  Scanning {len(deps)} dependencies for vulnerabilities...\n")
    vulns = query_osv_batch(deps)

    if vulns:
        render_vulnerabilities(vulns)
        sys.exit(1)
    else:
        console.print("  [green bold]No vulnerabilities found![/green bold]\n")
        sys.exit(0)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--policy", type=click.Choice(["strict", "moderate", "permissive"]), default="moderate",
              help="License policy.")
@click.option("--summary", "-s", is_flag=True, help="Show license distribution summary.")
def licenses(path: str, policy: str, summary: bool):
    """Check license compliance for all dependencies.

    Classifies licenses as permissive, weak copyleft, or copyleft.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    deps = parse_all_manifests(str(target))
    if not deps:
        console.print("  [yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    enrich_licenses(deps)

    if summary:
        lic_summary = get_license_summary(deps)
        render_license_summary(lic_summary)
    else:
        issues = check_license_compliance(deps, policy=policy)
        if issues:
            render_license_issues(issues)
        else:
            console.print("\n  [green bold]All licenses are compliant![/green bold]\n")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def outdated(path: str):
    """Check for outdated dependencies.

    Compares installed versions with latest available releases.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    deps = parse_all_manifests(str(target))
    if not deps:
        console.print("  [yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    console.print(f"\n  Checking {len(deps)} dependencies for updates...\n")
    outdated_deps = check_all_outdated(deps)

    if outdated_deps:
        render_outdated(outdated_deps)
    else:
        console.print("  [green bold]All dependencies are up to date![/green bold]\n")


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def tree(path: str):
    """Display the dependency tree.

    Shows direct, dev, and transitive dependencies in a tree view.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    deps = parse_all_manifests(str(target))
    if not deps:
        console.print("  [yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    dep_tree = build_tree_from_deps(deps, target.name)
    render_tree(dep_tree)


@cli.command(name="list")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--dev", is_flag=True, help="Include dev dependencies.")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON.")
def list_deps(path: str, dev: bool, json_output: bool):
    """List all project dependencies.

    Shows package names, versions, licenses, and risk levels.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    deps = parse_all_manifests(str(target))
    if not deps:
        console.print("  [yellow]No dependencies found.[/yellow]")
        sys.exit(0)

    if not dev:
        deps = [d for d in deps if not d.is_dev]

    enrich_licenses(deps)

    if json_output:
        data = []
        for d in sorted(deps, key=lambda x: x.name):
            data.append({
                "name": d.name,
                "version": d.installed_version or d.version_spec,
                "license": d.license,
                "risk": d.license_risk.value,
                "type": "dev" if d.is_dev else ("direct" if d.is_direct else "transitive"),
            })
        console.print_json(json.dumps(data, indent=2))
    else:
        render_dependency_list(deps)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
def info(path: str):
    """Show project dependency summary.

    Displays ecosystem, file count, and dependency breakdown.
    """
    target = Path(path).resolve()
    if not target.is_dir():
        target = target.parent

    ecosystem, manifests = detect_ecosystem(str(target))

    console.print()
    console.print(f"  [bold]Project:[/bold] [cyan]{target.name}[/cyan]")
    console.print(f"  [bold]Path:[/bold] {target}")
    console.print(f"  [bold]Ecosystem:[/bold] {ecosystem.value.title()}")
    console.print(f"  [bold]Manifest files:[/bold] {len(manifests)}")

    for m in manifests:
        console.print(f"    [dim]• {os.path.basename(m)}[/dim]")

    deps = parse_all_manifests(str(target))
    direct = sum(1 for d in deps if d.is_direct and not d.is_dev)
    dev = sum(1 for d in deps if d.is_dev)

    console.print()
    console.print(f"  [bold]Dependencies:[/bold] {len(deps)} total")
    console.print(f"    Production: [cyan]{direct}[/cyan]")
    console.print(f"    Development: [dim]{dev}[/dim]")
    console.print()


def _print_json(result: AuditResult) -> None:
    """Output audit results as JSON."""
    data = {
        "project": result.project_path,
        "ecosystem": result.ecosystem.value,
        "grade": result.grade,
        "health_score": result.health_score,
        "security_score": result.security_score,
        "summary": {
            "total_dependencies": result.total_dependencies,
            "direct": result.direct_dependencies,
            "dev": result.dev_dependencies,
            "vulnerabilities": result.vuln_count,
            "outdated": result.outdated_count,
            "license_issues": result.license_issue_count,
        },
        "vulnerabilities": [
            {
                "id": v.id,
                "package": v.package,
                "severity": v.severity.value,
                "title": v.title,
                "fixed_version": v.fixed_version,
                "url": v.url,
            }
            for v in result.vulnerabilities
        ],
        "outdated": [
            {
                "package": d.name,
                "current": d.installed_version,
                "latest": d.latest_version,
                "update_type": d.update_type,
            }
            for d in result.outdated
        ],
        "license_issues": [
            {
                "package": i.package,
                "license": i.license,
                "risk": i.risk.value,
                "message": i.message,
            }
            for i in result.license_issues
        ],
    }
    console.print_json(json.dumps(data, indent=2))


def main():
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
