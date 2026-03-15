"""Dependency tree builder."""

from __future__ import annotations

from typing import Optional

from dep_audit.models import DepNode, Dependency


def build_tree_from_deps(deps: list[Dependency], project_name: str = "project") -> DepNode:
    """Build a dependency tree from a flat list of dependencies."""
    root = DepNode(name=project_name, version="")

    direct = [d for d in deps if d.is_direct and not d.is_dev]
    dev = [d for d in deps if d.is_dev]
    indirect = [d for d in deps if not d.is_direct and not d.is_dev]

    for dep in direct:
        node = DepNode(name=dep.name, version=dep.installed_version, depth=1)
        root.children.append(node)

    if dev:
        dev_node = DepNode(name="[dev]", version="", depth=1)
        for dep in dev:
            child = DepNode(name=dep.name, version=dep.installed_version, depth=2)
            dev_node.children.append(child)
        root.children.append(dev_node)

    if indirect:
        indirect_node = DepNode(name="[transitive]", version="", depth=1)
        for dep in indirect:
            child = DepNode(name=dep.name, version=dep.installed_version, depth=2)
            indirect_node.children.append(child)
        root.children.append(indirect_node)

    return root


def build_python_tree(project_path: str) -> Optional[DepNode]:
    """Build dependency tree by inspecting pip packages."""
    try:
        import subprocess
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project_path,
        )
        if result.returncode != 0:
            return None

        import json
        packages = json.loads(result.stdout)

        root = DepNode(name="project", version="")
        for pkg in packages:
            node = DepNode(
                name=pkg.get("name", ""),
                version=pkg.get("version", ""),
                depth=1,
            )
            root.children.append(node)

        return root
    except Exception:
        return None


def tree_to_text(node: DepNode, prefix: str = "", is_last: bool = True) -> str:
    """Render a dependency tree as a text string."""
    lines = []

    if node.depth == 0:
        # Root node
        label = f"{node.name}"
        if node.version:
            label += f" ({node.version})"
        lines.append(label)
    else:
        connector = "└── " if is_last else "├── "
        label = f"{node.name}"
        if node.version:
            label += f" @ {node.version}"
        lines.append(f"{prefix}{connector}{label}")

    child_prefix = prefix + ("    " if is_last else "│   ") if node.depth > 0 else ""

    for i, child in enumerate(node.children):
        is_child_last = i == len(node.children) - 1
        lines.append(tree_to_text(child, child_prefix, is_child_last))

    return "\n".join(lines)


def count_tree_nodes(node: DepNode) -> int:
    """Count total nodes in the tree (excluding root)."""
    total = 0
    for child in node.children:
        if child.name not in ("[dev]", "[transitive]"):
            total += 1
        total += count_tree_nodes(child)
    return total
