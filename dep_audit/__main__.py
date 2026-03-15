"""Allow running dep-audit as python -m dep_audit."""

from dep_audit.cli import cli

if __name__ == "__main__":
    cli()
