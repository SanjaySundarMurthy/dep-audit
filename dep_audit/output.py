"""Rich terminal output for dep-audit."""

from __future__ import annotations


from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree as RichTree

from dep_audit.models import (
    AuditResult,
    DepNode,
    Dependency,
    LicenseIssue,
    LicenseRisk,
    Severity,
    Vulnerability,
)

console = Console()


def render_audit_result(result: AuditResult) -> None:
    """Display full audit results."""
    console.print()

    # Health panel
    grade_colors = {"A+": "green", "A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
    color = grade_colors.get(result.grade, "white")

    panel = Panel(
        Text.from_markup(
            f"  Grade: [bold {color}]{result.grade}[/bold {color}]  |  "
            f"Score: [bold]{result.health_score}[/bold]/100\n"
            f"  Dependencies: [cyan]{result.total_dependencies}[/cyan]  |  "
            f"Vulnerabilities: [{'red' if result.vuln_count else 'green'}]{result.vuln_count}"
            f"[/{'red' if result.vuln_count else 'green'}]  |  "
            f"Outdated: [{'yellow' if result.outdated_count else 'green'}]{result.outdated_count}"
            f"[/{'yellow' if result.outdated_count else 'green'}]  |  "
            f"License Issues: {result.license_issue_count}"
        ),
        title=f"[bold]Dependency Audit — {result.ecosystem.value.title()}[/bold]",
        border_style=color,
        padding=(0, 2),
    )
    console.print(panel)
    console.print()

    # Vulnerabilities
    if result.vulnerabilities:
        render_vulnerabilities(result.vulnerabilities)

    # Outdated
    if result.outdated:
        render_outdated(result.outdated)

    # License issues
    if result.license_issues:
        render_license_issues(result.license_issues)

    # Clean bill
    if not result.vulnerabilities and not result.outdated and not result.license_issues:
        console.print("  [green bold]All clear — no issues found![/green bold]")
        console.print()


def render_vulnerabilities(vulns: list[Vulnerability]) -> None:
    """Display vulnerabilities."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("", width=3)
    table.add_column("Severity", width=10)
    table.add_column("ID", min_width=18)
    table.add_column("Package", min_width=20)
    table.add_column("Title", min_width=30)
    table.add_column("Fix", style="green")

    sev_colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
    }

    for v in sorted(vulns, key=lambda x: x.severity.priority):
        color = sev_colors.get(v.severity, "white")
        icon = "!" if v.severity in (Severity.CRITICAL, Severity.HIGH) else "~"
        table.add_row(
            f"[red]{icon}[/red]",
            f"[{color}]{v.severity.value.upper()}[/{color}]",
            f"[dim]{v.id}[/dim]",
            f"[cyan]{v.package}[/cyan]",
            v.title[:50],
            v.fixed_version or "[dim]—[/dim]",
        )

    console.print("  [bold red]Vulnerabilities[/bold red]")
    console.print(table)
    console.print()


def render_outdated(outdated: list[Dependency]) -> None:
    """Display outdated dependencies."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Package", min_width=25, style="cyan")
    table.add_column("Current", min_width=12)
    table.add_column("Latest", min_width=12, style="green")
    table.add_column("Update", width=8)
    table.add_column("Type", width=6, style="dim")

    type_colors = {"major": "red", "minor": "yellow", "patch": "green"}

    for dep in sorted(outdated, key=lambda d: d.name):
        ut = dep.update_type
        ut_color = type_colors.get(ut, "white")
        table.add_row(
            dep.name,
            dep.installed_version,
            dep.latest_version,
            f"[{ut_color}]{ut}[/{ut_color}]",
            "dev" if dep.is_dev else "",
        )

    console.print("  [bold yellow]Outdated Dependencies[/bold yellow]")
    console.print(table)
    console.print()


def render_license_issues(issues: list[LicenseIssue]) -> None:
    """Display license compliance issues."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("", width=3)
    table.add_column("Risk", width=10)
    table.add_column("Package", min_width=20, style="cyan")
    table.add_column("License", min_width=15)
    table.add_column("Issue", min_width=30)

    risk_colors = {
        LicenseRisk.HIGH: "red",
        LicenseRisk.MEDIUM: "yellow",
        LicenseRisk.LOW: "green",
        LicenseRisk.UNKNOWN: "dim",
    }

    for issue in issues:
        color = risk_colors.get(issue.risk, "white")
        icon = issue.risk.icon
        table.add_row(
            icon,
            f"[{color}]{issue.risk.value.upper()}[/{color}]",
            issue.package,
            issue.license,
            issue.message[:60],
        )

    console.print("  [bold]License Issues[/bold]")
    console.print(table)
    console.print()


def render_license_summary(summary: dict) -> None:
    """Display license distribution summary."""
    console.print()
    console.print("  [bold]License Distribution[/bold]")
    console.print()

    risks = summary.get("risk_breakdown", {})
    total = summary.get("total", 0)

    console.print(f"    Total packages: [cyan]{total}[/cyan]")
    console.print(f"    Unique licenses: [cyan]{summary.get('unique_licenses', 0)}[/cyan]")
    console.print()

    if risks.get("low", 0):
        console.print(f"    [green]Permissive (low risk):[/green] {risks['low']}")
    if risks.get("medium", 0):
        console.print(f"    [yellow]Weak copyleft (medium risk):[/yellow] {risks['medium']}")
    if risks.get("high", 0):
        console.print(f"    [red]Copyleft (high risk):[/red] {risks['high']}")
    if risks.get("unknown", 0):
        console.print(f"    [dim]Unknown:[/dim] {risks['unknown']}")
    console.print()

    # Top licenses
    licenses = summary.get("licenses", {})
    if licenses:
        console.print("    [bold]Top Licenses:[/bold]")
        for lic, count in list(licenses.items())[:10]:
            bar = "█" * min(count * 2, 40)
            console.print(f"      {lic:<30} [cyan]{bar}[/cyan] {count}")
        console.print()


def render_dependency_list(deps: list[Dependency]) -> None:
    """Display a list of dependencies."""
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    table.add_column("Package", min_width=25, style="cyan")
    table.add_column("Version", min_width=12)
    table.add_column("License", min_width=15)
    table.add_column("Risk", width=10)
    table.add_column("Type", width=8, style="dim")

    for dep in sorted(deps, key=lambda d: d.name):
        risk_color = {
            LicenseRisk.LOW: "green",
            LicenseRisk.MEDIUM: "yellow",
            LicenseRisk.HIGH: "red",
            LicenseRisk.UNKNOWN: "dim",
        }.get(dep.license_risk, "white")

        dep_type = "dev" if dep.is_dev else ("direct" if dep.is_direct else "transitive")

        table.add_row(
            dep.name,
            dep.installed_version or dep.version_spec,
            dep.license or "[dim]Unknown[/dim]",
            f"[{risk_color}]{dep.license_risk.value}[/{risk_color}]",
            dep_type,
        )

    console.print()
    console.print(table)
    console.print()


def render_tree(node: DepNode) -> None:
    """Display the dependency tree using Rich."""
    console.print()
    tree = RichTree(f"[bold cyan]{node.name}[/bold cyan]")
    _add_tree_children(tree, node)
    console.print(tree)
    console.print()


def _add_tree_children(rich_node: RichTree, dep_node: DepNode) -> None:
    """Recursively add children to Rich tree."""
    for child in dep_node.children:
        if child.name.startswith("["):
            # Group label
            label = f"[bold yellow]{child.name}[/bold yellow]"
        else:
            version = f" [dim]@ {child.version}[/dim]" if child.version else ""
            label = f"[cyan]{child.name}[/cyan]{version}"

        child_node = rich_node.add(label)
        _add_tree_children(child_node, child)
