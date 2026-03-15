"""Tests for dep_audit.tree."""

from __future__ import annotations


from dep_audit.models import DepNode, Dependency
from dep_audit.tree import build_tree_from_deps, count_tree_nodes, tree_to_text


class TestBuildTreeFromDeps:
    def test_basic(self, sample_deps):
        tree = build_tree_from_deps(sample_deps, "myproject")
        assert tree.name == "myproject"
        assert len(tree.children) >= 1

    def test_direct_deps(self):
        deps = [
            Dependency(name="a", installed_version="1.0", is_direct=True),
            Dependency(name="b", installed_version="2.0", is_direct=True),
        ]
        tree = build_tree_from_deps(deps, "proj")
        assert len(tree.children) == 2

    def test_dev_group(self):
        deps = [
            Dependency(name="a", installed_version="1.0", is_direct=True),
            Dependency(name="b", installed_version="1.0", is_dev=True),
        ]
        tree = build_tree_from_deps(deps, "proj")
        # Should have direct dep + [dev] group
        dev_nodes = [c for c in tree.children if c.name == "[dev]"]
        assert len(dev_nodes) == 1
        assert len(dev_nodes[0].children) == 1

    def test_transitive_group(self):
        deps = [
            Dependency(name="a", installed_version="1.0", is_direct=True),
            Dependency(name="b", installed_version="1.0", is_direct=False, is_dev=False),
        ]
        tree = build_tree_from_deps(deps, "proj")
        trans_nodes = [c for c in tree.children if c.name == "[transitive]"]
        assert len(trans_nodes) == 1

    def test_empty_deps(self):
        tree = build_tree_from_deps([], "proj")
        assert tree.name == "proj"
        assert len(tree.children) == 0


class TestTreeToText:
    def test_simple(self):
        root = DepNode(name="project", version="")
        child = DepNode(name="click", version="8.1.7", depth=1)
        root.children = [child]
        text = tree_to_text(root)
        assert "project" in text
        assert "click" in text
        assert "8.1.7" in text

    def test_multiple_children(self):
        root = DepNode(name="project", version="")
        root.children = [
            DepNode(name="a", version="1.0", depth=1),
            DepNode(name="b", version="2.0", depth=1),
        ]
        text = tree_to_text(root)
        assert "├──" in text or "└──" in text
        assert "a" in text
        assert "b" in text

    def test_nested(self):
        root = DepNode(name="project", version="")
        child = DepNode(name="a", version="1.0", depth=1)
        grandchild = DepNode(name="b", version="2.0", depth=2)
        child.children = [grandchild]
        root.children = [child]
        text = tree_to_text(root)
        assert "a" in text
        assert "b" in text

    def test_empty_tree(self):
        root = DepNode(name="project", version="")
        text = tree_to_text(root)
        assert "project" in text


class TestCountTreeNodes:
    def test_empty(self):
        root = DepNode(name="root")
        assert count_tree_nodes(root) == 0

    def test_flat(self):
        root = DepNode(name="root")
        root.children = [DepNode(name="a"), DepNode(name="b")]
        assert count_tree_nodes(root) == 2

    def test_nested(self):
        root = DepNode(name="root")
        child = DepNode(name="a")
        child.children = [DepNode(name="b"), DepNode(name="c")]
        root.children = [child]
        assert count_tree_nodes(root) == 3

    def test_skips_groups(self):
        root = DepNode(name="root")
        dev = DepNode(name="[dev]")
        dev.children = [DepNode(name="a")]
        root.children = [dev]
        # [dev] is skipped but "a" is counted
        assert count_tree_nodes(root) == 1
