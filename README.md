# ⚡ InjectorSQL

**Professional DAST SQL Injection Vulnerability Scanner**

[![CI](https://github.com/yourname/InjectorSQL/actions/workflows/ci.yml/badge.svg)](https://github.com/yourname/InjectorSQL/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

```
  ___       _           _             ____   ___  _
 |_ _|_ __ (_) ___  ___| |_ ___  _ _/ ___| / _ \| |
  | || '_ \| |/ _ \/ __| __/ _ \| '_\___ \| | | | |
  | || | | | |  __/ (__| || (_) | |  ___) | |_| | |___
 |___|_| |_| |\___|\___|\__\___/|_| |____/ \__\_\_____|
          |__/
              DAST SQL Injection Scanner  v1.0.0
   ⚠  For authorized testing only — DVWA / Juice Shop ⚠
```

> **⚠ Legal Disclaimer:** InjectorSQL is intended **exclusively** for authorized
> security testing of systems you own or have **explicit written permission** to test.
> Unauthorized use against live systems is illegal and unethical.
> Always use against local lab environments such as [DVWA](https://github.com/digininja/DVWA)
> or [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Lab Setup (Docker)](#lab-setup-docker)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [WAF Bypass Mode](#waf-bypass-mode)
- [Report Formats](#report-formats)
- [Detection Logic](#detection-logic)
- [Payload Library](#payload-library)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)
- [Remediation Guidance](#remediation-guidance)
- [Contributing](#contributing)

---

## Features

| Phase | Component | Capability |
|-------|-----------|------------|
| 1 | **Spider / Crawler** | BFS crawl, form extraction, URL parameter discovery |
| 2 | **Payload Library** | Error-based, Boolean-based, Time-based payloads across MySQL, MSSQL, Oracle, PostgreSQL, SQLite |
| 3 | **Injection Engine** | Concurrent requests via `ThreadPoolExecutor`, baseline diffing, throttle control |
| 4 | **Analyst / Detector** | DB error pattern matching, content differential, response latency analysis |
| 5 | **Reporter** | Text, JSON, and HTML reports with evidence, severity ratings, and remediation |
| ★ | **WAF Bypass** | Case variation, inline comment injection, hex encoding, whitespace substitution |

---

## Architecture

```
InjectorSQL
├── Phase 1  crawler.py      — Spider, EntryPoint
├── Phase 2  payloads.py     — PayloadLibrary, Payload, WafBypass
├── Phase 3  engine.py       — InjectionEngine (concurrent requestor)
├── Phase 4  detector.py     — Analyst, Finding, DB error patterns
├── Phase 5  reporter.py     — Text / JSON / HTML report generation
└──          utils.py        — Logging, validation, diff helpers
```

```
                   ┌─────────────────────────────────────────┐
                   │              InjectorSQL                 │
                   └─────────────────────────────────────────┘
                                      │
              ┌───────────────────────▼──────────────────────┐
              │         Phase 1: Spider (crawler.py)          │
              │  BFS crawl → extract forms + URL params       │
              └───────────────────────┬──────────────────────┘
                                      │  Entry Points
              ┌───────────────────────▼──────────────────────┐
              │     Phase 2: Payload Library (payloads.py)    │
              │  Error | Boolean | Time + WAF bypass variants │
              └───────────────────────┬──────────────────────┘
                                      │  Payloads × Entry Points
              ┌───────────────────────▼──────────────────────┐
              │      Phase 3: Injection Engine (engine.py)    │
              │  Baseline → Inject → ThreadPoolExecutor       │
              └───────────────────────┬──────────────────────┘
                                      │  (body, status, time)
              ┌───────────────────────▼──────────────────────┐
              │       Phase 4: Analyst (detector.py)          │
              │  Error strings | Content diff | Latency       │
              └───────────────────────┬──────────────────────┘
                                      │  Findings
              ┌───────────────────────▼──────────────────────┐
              │       Phase 5: Reporter (reporter.py)         │
              │  Text | JSON | HTML  +  Remediation           │
              └──────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/yourname/InjectorSQL.git
cd InjectorSQL

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

# Install
pip install -e .
# or
pip install -r requirements.txt
```

### 2. Spin Up a Lab Target

```bash
docker compose up -d
# DVWA       →  http://localhost:8080
# Juice Shop →  http://localhost:3000
# WebGoat    →  http://localhost:8888
```

### 3. Run Your First Scan

```bash
# 1. Log into DVWA at http://localhost:8080 (admin/password)
#    Set Security Level to "Low"
#    Copy your PHPSESSID from browser DevTools → Application → Cookies

injector-sql \
  -u "http://localhost:8080" \
  --cookie "PHPSESSID=YOUR_SESSION_ID; security=low" \
  --depth 3 \
  --threads 10 \
  --output html \
  --report-file reports/dvwa_scan.html
```

---

## Lab Setup (Docker)

The included `docker-compose.yml` launches three intentionally vulnerable applications:

```bash
# Start all lab targets
docker compose up -d

# Stop when done
docker compose down
```

| App | URL | Default Credentials |
|-----|-----|---------------------|
| DVWA | http://localhost:8080 | admin / password |
| OWASP Juice Shop | http://localhost:3000 | admin@juice-sh.op / admin123 |
| WebGoat | http://localhost:8888/WebGoat | — (register on first visit) |

> **Tip:** DVWA has an explicit "Security Level" setting. Start with **Low** to
> confirm the scanner works, then test **Medium** with `--waf-bypass` to see
> the bypass techniques in action.

---

## Usage

### Basic Scan

```bash
injector-sql -u http://localhost:8080 --cookie "PHPSESSID=abc123; security=low"
```

### Error-Based Only (Fast)

```bash
injector-sql -u http://localhost:8080 \
  --cookie "PHPSESSID=abc123; security=low" \
  --error-based --verbose
```

### Full Scan with WAF Bypass

```bash
injector-sql -u http://localhost:8080 \
  --cookie "PHPSESSID=abc123; security=medium" \
  --waf-bypass \
  --threads 15 \
  --output html \
  --report-file reports/waf_scan.html
```

### Time-Based Blind (Critical Detection)

```bash
injector-sql -u http://localhost:8080 \
  --cookie "PHPSESSID=abc123; security=low" \
  --time-based \
  --delay-threshold 4.5 \
  --threads 3       # Fewer threads — time-based needs clean latency readings
```

### CI / CD Pipeline (Exit Code 1 on Findings)

```bash
injector-sql -u http://staging.internal \
  --forms-only --quiet \
  --output json --report-file reports/ci.json

# $? == 1 if vulnerabilities found → block the pipeline
```

---

## CLI Reference

```
usage: injector-sql [-h] -u URL [--depth N] [--forms-only] [--params-only]
                    [--exclude PATTERN ...] [--cookie COOKIES]
                    [--header HEADER] [--auth USER:PASS]
                    [--error-based] [--boolean-based] [--time-based]
                    [--waf-bypass] [--delay-threshold SECONDS]
                    [--custom-payloads FILE] [--threads N]
                    [--timeout SEC] [--delay SEC] [--user-agent UA]
                    [--proxy URL] [--verify-ssl]
                    [--output {text,json,html}] [--report-file FILE]
                    [--verbose] [--quiet]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-u`, `--url` | *(required)* | Target base URL |
| `--depth` | `2` | BFS crawl depth |
| `--forms-only` | off | Test HTML forms only |
| `--params-only` | off | Test URL query parameters only |
| `--exclude PATTERN` | — | Skip URLs matching glob pattern |
| `--cookie` | — | Cookie string `"name=val; name2=val2"` |
| `--header` | — | Extra header (repeatable) |
| `--auth` | — | Basic auth `user:pass` |
| `--error-based` | *(all on if none specified)* | Error-based payloads |
| `--boolean-based` | | Boolean-based payloads |
| `--time-based` | | Time-based payloads |
| `--waf-bypass` | off | Append WAF evasion variants |
| `--delay-threshold` | `5.0` | Seconds to flag time-based hit |
| `--custom-payloads` | — | Newline-delimited payload file |
| `--threads` | `5` | Concurrent threads |
| `--timeout` | `10.0` | Per-request timeout (s) |
| `--delay` | `0` | Throttle between requests (s) |
| `--proxy` | — | HTTP/S proxy (e.g. Burp Suite) |
| `--output` | `text` | Report format: `text`, `json`, `html` |
| `--report-file` | *(auto-named)* | Save report to path |
| `-v`, `--verbose` | off | Debug-level logging |
| `-q`, `--quiet` | off | Suppress banner; findings only |

---

## WAF Bypass Mode

Activate with `--waf-bypass`. InjectorSQL automatically generates evasion
variants of every payload using five techniques:

| Technique | Example |
|-----------|---------|
| **Case Variation** | `SELECT` → `SeLeCt` |
| **Comment Injection** | `SELECT/**/FROM/**/users` |
| **Hex Encoding** | `'admin'` → `0x61646d696e` |
| **Whitespace Substitution** | `SELECT id` → `SELECT/**/id` |
| **Tab Substitution** | `SELECT\tid\tFROM\tusers` |

These variants bypass simple signature-based WAF rules that look for exact
keyword matches. A WAF is **not** a substitute for parameterized queries.

---

## Report Formats

### Text (default)

Printed to stdout and saved to `reports/`. Shows a severity summary table,
per-finding evidence blocks, and inline remediation advice.

### JSON (`--output json`)

Machine-readable. Ideal for SIEM ingestion, CI/CD artifact storage, or
feeding into custom dashboards.

```json
{
  "tool": "InjectorSQL",
  "scan": { "target": "...", "duration_sec": 42.1 },
  "summary": { "total_findings": 3, "by_severity": { "Critical": 1, "High": 2 } },
  "findings": [ { "url": "...", "parameter": "id", "payload": "' AND SLEEP(5)--", ... } ]
}
```

### HTML (`--output html`)

Self-contained dark-mode report with severity badges, expandable remediation
sections, and a findings table. Open directly in any browser.

---

## Detection Logic

InjectorSQL uses three non-overlapping detection strategies to minimize false positives:

### 1. Error-Based (Pattern Matching)

Scans the response body for ~40 database error signatures across MySQL, MSSQL,
Oracle, PostgreSQL, SQLite, and generic ODBC/JDBC patterns.

```python
# Example signatures
"You have an error in your SQL syntax"   # MySQL
"ORA-01756"                              # Oracle
"Incorrect syntax near"                  # MSSQL
"invalid input syntax for"              # PostgreSQL
```

### 2. Boolean-Based (Content Differential)

Compares the baseline response with the injected response using Python's
`difflib.SequenceMatcher`. A similarity ratio below **0.85** with identical
HTTP status codes flags a boolean-based hit.

```
baseline  →  "Welcome John. You have 5 items."  (sim = 1.0)
' OR 1=1  →  "Welcome John. You have 5 items."  (sim ≈ 1.0 — no hit)
' OR 1=1  →  "Welcome Admin. All 1024 items."   (sim ≈ 0.4 — HIT)
```

### 3. Time-Based (Latency Measurement)

Measures wall-clock time for requests containing sleep/delay payloads.
Any response exceeding `--delay-threshold` (default 5s) is flagged Critical.

---

## Payload Library

| Category | Count | Targets |
|----------|-------|---------|
| Error-Based | 16 | MySQL, MSSQL, Oracle, PostgreSQL, Generic |
| Boolean-Based | 21 | Generic, MySQL |
| Time-Based | 15 | MySQL, MSSQL, PostgreSQL, Oracle, SQLite |
| **Total (base)** | **52** | |
| WAF Bypass variants | ~200+ | All above |

Custom payloads can be added via `--custom-payloads payloads.txt`:

```
# One payload per line; lines starting with # are comments
' UNION SELECT user(),database()--
'; EXEC xp_cmdshell('whoami')--
```

---

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run the full test suite
pytest

# With coverage report
pytest --cov=injector_sql --cov-report=html

# Run a specific test class
pytest tests/test_injector_sql.py::TestAnalyst -v
```

The test suite uses the `responses` library to mock all HTTP calls — no live
network or Docker containers required for unit tests.

---

## Project Structure

```
InjectorSQL/
├── injector_sql/
│   ├── __init__.py         ← Public API exports
│   ├── main.py             ← CLI entry point & argument parser
│   ├── crawler.py          ← Phase 1: Spider, EntryPoint
│   ├── payloads.py         ← Phase 2: PayloadLibrary, Payload, WafBypass
│   ├── engine.py           ← Phase 3: InjectionEngine (concurrent)
│   ├── detector.py         ← Phase 4: Analyst, Finding, DB error patterns
│   ├── reporter.py         ← Phase 5: Text / JSON / HTML reports
│   └── utils.py            ← Logging, validation, diff helpers
├── tests/
│   └── test_injector_sql.py ← 30+ unit tests (no live network required)
├── examples/
│   ├── custom_payloads.txt  ← Sample custom payload file
│   └── scan_recipes.sh      ← Ready-to-run scan examples
├── reports/                 ← Generated reports land here
├── .github/
│   └── workflows/ci.yml     ← GitHub Actions CI pipeline
├── docker-compose.yml       ← DVWA + Juice Shop + WebGoat lab
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── pytest.ini
├── LICENSE
└── README.md
```

---

## Remediation Guidance

InjectorSQL doesn't just find bugs — it explains how to fix them.
Every report includes targeted remediation per detection type:

### Error-Based → Suppress DB Errors + Prepared Statements

```python
# ❌ Vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ Fixed — parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Boolean-Based / UNION → Parameterized Queries at ALL call sites

```python
# ✅ SQLAlchemy ORM (safest)
user = db.session.query(User).filter(User.id == user_id).first()
```

### Time-Based (Critical) → Immediate audit + DB statement timeout

```sql
-- PostgreSQL: limit slow queries
SET statement_timeout = '3s';

-- MSSQL: disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
```

### Universal Checklist

- [ ] Parameterize every database query — no exceptions
- [ ] Use an ORM where possible
- [ ] Validate and type-check all user inputs
- [ ] Run DB accounts with least privilege (no DDL)
- [ ] Show generic error pages in production
- [ ] Rate-limit login and search endpoints
- [ ] Run InjectorSQL (or similar) in your CI/CD pipeline

---

## Contributing

Pull requests are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-payload-category`)
3. Add tests for new functionality
4. Ensure `pytest` and `flake8` pass
5. Open a PR describing the change

For new payload ideas, open an issue with the payload, target DB, and the
DVWA/Juice Shop reproduction steps.

---

## License

MIT © InjectorSQL Contributors — see [LICENSE](LICENSE).

---

*Built for education and authorized security testing.
The authors assume no liability for misuse.*
