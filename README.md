# dep-audit-cli

**Comprehensive dependency auditing CLI for vulnerability scanning, license compliance, outdated detection, and dependency tree visualization.**

[![PyPI version](https://badge.fury.io/py/dep-audit-cli.svg)](https://pypi.org/project/dep-audit-cli/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Features

- **Vulnerability Scanning** — Query OSV.dev API for known CVEs across 6+ ecosystems
- **License Compliance** — Check dependencies against configurable license policies (strict/moderate/permissive)
- **Outdated Detection** — Find packages with newer versions on PyPI/npm registries
- **Dependency Tree** — Visualize project dependency hierarchy with Rich tree rendering
- **Multi-Ecosystem** — Python, Node.js, Go, Rust, Ruby support out of the box
- **Security Scoring** — 0–100 health score with letter grades (A+ through F)
- **Multiple Output Formats** — Rich terminal tables or structured JSON
- **CI/CD Ready** — Exit codes for pipeline integration, `--strict` mode for zero-tolerance

---

## Installation

```bash
pip install dep-audit-cli
```

---

## Quick Start

```bash
# Full audit (vulns + outdated + licenses)
dep-audit audit .

# Vulnerability scan only
dep-audit scan .

# Check license compliance
dep-audit licenses . --policy strict

# Find outdated packages
dep-audit outdated .

# Show dependency tree
dep-audit tree .

# List all dependencies
dep-audit list .

# Project summary
dep-audit info .
```

---

## Commands

### `dep-audit audit`

Run a comprehensive dependency audit combining vulnerability scanning, outdated detection, and license compliance.

```bash
dep-audit audit [PATH] [OPTIONS]

Options:
  --no-vuln        Skip vulnerability scanning
  --no-outdated    Skip outdated check
  --no-license     Skip license compliance check
  --policy TEXT    License policy: strict, moderate, permissive (default: moderate)
  --json-output    Output as JSON
  --strict         Exit with code 1 on any finding
```

**Example:**

```bash
$ dep-audit audit ./my-project --policy strict

╭─── Dependency Audit Report ──────────────────────────────────╮
│                                                               │
│  Project:  ./my-project                                       │
│  Ecosystem: Python                                            │
│  Grade:    A (92/100)                                         │
│                                                               │
│  Dependencies:  24 total (18 direct, 6 dev)                   │
│  Vulnerabilities: 1 (0 critical, 1 high)                      │
│  Outdated:      3 packages                                    │
│  License Issues: 0                                            │
│                                                               │
╰───────────────────────────────────────────────────────────────╯
```

### `dep-audit scan`

Scan dependencies for known vulnerabilities using the OSV.dev database.

```bash
dep-audit scan [PATH] [OPTIONS]

Options:
  --json-output    Output as JSON
  --strict         Exit with code 1 on any vulnerability
```

**Example:**

```bash
$ dep-audit scan .

 Vulnerability Scan Results
┌──────────────┬─────────┬──────────┬────────────────────────────────────┐
│ Package      │ Version │ Severity │ Advisory                           │
├──────────────┼─────────┼──────────┼────────────────────────────────────┤
│ requests     │ 2.25.0  │ 🔴 HIGH  │ GHSA-j8r2-6x86-q33q               │
│ urllib3      │ 1.26.5  │ 🟡 MED   │ PYSEC-2023-212                    │
└──────────────┴─────────┴──────────┴────────────────────────────────────┘
```

### `dep-audit licenses`

Check dependency licenses against compliance policies.

```bash
dep-audit licenses [PATH] [OPTIONS]

Options:
  --policy TEXT     License policy: strict, moderate, permissive
  --summary         Show license distribution summary
  --json-output     Output as JSON
```

**Policies:**

| Policy | Allowed | Flagged |
|--------|---------|---------|
| **strict** | MIT, BSD, Apache-2.0 | LGPL, MPL, GPL, AGPL |
| **moderate** | MIT, BSD, Apache-2.0, LGPL, MPL | GPL, AGPL |
| **permissive** | MIT, BSD, Apache, LGPL, MPL, GPL | AGPL |

### `dep-audit outdated`

Find dependencies with newer versions available.

```bash
dep-audit outdated [PATH] [OPTIONS]

Options:
  --json-output    Output as JSON
```

**Example:**

```bash
$ dep-audit outdated .

 Outdated Dependencies
┌──────────────┬──────────┬──────────┬────────┐
│ Package      │ Current  │ Latest   │ Update │
├──────────────┼──────────┼──────────┼────────┤
│ click        │ 8.0.0    │ 8.1.7    │ minor  │
│ rich         │ 12.0.0   │ 13.7.1   │ major  │
│ requests     │ 2.28.0   │ 2.31.0   │ minor  │
└──────────────┴──────────┴──────────┴────────┘
```

### `dep-audit tree`

Visualize the dependency tree hierarchy.

```bash
dep-audit tree [PATH]
```

**Example:**

```bash
$ dep-audit tree .

📦 my-project
├── 📦 Direct Dependencies
│   ├── click >= 8.0
│   ├── rich >= 13.0
│   └── requests >= 2.28
└── 📦 Dev Dependencies [dev]
    ├── pytest >= 7.0
    └── ruff >= 0.1.0
```

### `dep-audit list`

List all project dependencies with metadata.

```bash
dep-audit list [PATH] [OPTIONS]

Options:
  --dev            Include dev dependencies
  --json-output    Output as JSON
```

### `dep-audit info`

Display project summary information.

```bash
dep-audit info [PATH]
```

---

## Supported Ecosystems

| Ecosystem | Manifest Files |
|-----------|---------------|
| **Python** | `requirements.txt`, `requirements-dev.txt`, `requirements_dev.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile` |
| **Node.js** | `package.json` |
| **Go** | `go.mod` |
| **Rust** | `Cargo.toml` |
| **Ruby** | `Gemfile` |

---

## JSON Output

All commands support `--json-output` for CI/CD integration:

```bash
dep-audit audit . --json-output > audit-report.json
```

```json
{
  "project_path": ".",
  "ecosystem": "Python",
  "total_dependencies": 24,
  "vulnerabilities": [...],
  "outdated": [...],
  "license_issues": [...],
  "health_score": 92,
  "grade": "A"
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Dependency Audit
  run: |
    pip install dep-audit-cli
    dep-audit audit . --strict
```

### GitLab CI

```yaml
dependency-audit:
  script:
    - pip install dep-audit-cli
    - dep-audit audit . --strict --json-output > audit.json
  artifacts:
    reports:
      dependency_scanning: audit.json
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: dep-audit
        name: Dependency Audit
        entry: dep-audit audit . --strict --no-outdated
        language: system
        pass_filenames: false
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No issues found (or non-strict mode) |
| `1` | Issues found (strict mode) or fatal error |

---

## Health Scoring

The health score (0–100) is calculated from:

- **Security Score**: Based on vulnerability count and severity
  - Critical: -25 points each
  - High: -15 points each
  - Medium: -8 points each
  - Low: -3 points each

- **Health Score**: Combines security score with:
  - License issues: -5 points each
  - Outdated packages: -2 points each

| Grade | Score Range |
|-------|------------|
| A+ | 95–100 |
| A | 90–94 |
| B+ | 85–89 |
| B | 80–84 |
| C+ | 75–79 |
| C | 70–74 |
| D | 60–69 |
| F | 0–59 |

---

## Development

```bash
git clone https://github.com/SanjaySundarMurthy/dep-audit.git
cd dep-audit
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
