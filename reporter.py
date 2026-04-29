"""
InjectorSQL — Phase 5: Reporting & Remediation
Generates Text, JSON, and HTML reports with evidence and remediation guidance.
"""

from __future__ import annotations

import json
import os
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any

from .detector import Finding
from .utils import logger, sort_findings, SEVERITY_ORDER


# ── Remediation Advice ────────────────────────────────────────────────────────

REMEDIATION = {
    "error_based": {
        "short": "Suppress database error messages in production.",
        "detail": textwrap.dedent("""\
            Error-Based SQL Injection occurs when the application exposes raw database
            error messages to the user. These messages reveal schema information and
            confirm that user input is being interpreted as SQL.

            ✔ Use Prepared Statements / Parameterized Queries in ALL database calls:
                # Python (psycopg2 / sqlite3)
                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

                // Java (JDBC)
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT * FROM users WHERE id = ?");
                ps.setInt(1, userId);

            ✔ Configure the application/framework to show generic error pages in
              production. Never leak stack traces or SQL error strings.
            ✔ Apply Input Validation: whitelist expected formats (e.g., integer IDs).
            ✔ Enforce the Principle of Least Privilege — the DB user should not have
              DROP, CREATE, or FILE privileges.
        """),
    },
    "boolean_based": {
        "short": "Use parameterized queries; never interpolate user input into SQL.",
        "detail": textwrap.dedent("""\
            Boolean-Based Blind SQL Injection works by asking the database true/false
            questions and inferring data from changes in page content. The attacker can
            extract entire databases one bit at a time without triggering error messages.

            ✔ Prepared Statements are the ONLY reliable fix:
                # Python (SQLAlchemy ORM — safest)
                user = db.session.query(User).filter(User.id == user_id).first()

                # Raw SQL — always use placeholders:
                cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))

            ✔ Input Validation: if a parameter should be an integer, cast and validate it
              before constructing any query.
            ✔ Web Application Firewall (WAF) rules can slow attackers but are NOT a fix —
              they can be bypassed (as this tool demonstrates with --waf-bypass).
            ✔ Implement rate-limiting and anomaly detection on login and search endpoints.
        """),
    },
    "time_based": {
        "short": "Critical: parameterize ALL queries immediately — blind injection confirmed.",
        "detail": textwrap.dedent("""\
            Time-Based Blind SQL Injection is the most dangerous form of blind SQLi.
            By injecting sleep/delay commands (SLEEP, WAITFOR DELAY, pg_sleep) the
            attacker confirms injection and can exfiltrate data even when the page
            content is identical regardless of query outcome.

            ✔ IMMEDIATE ACTION: audit and parameterize every database call.
              No string concatenation of user input into SQL — ever.

            ✔ Stored Procedures alone are NOT safe if they use dynamic SQL internally.
              Ensure stored procedures also use parameterized queries.

            ✔ Disable dangerous built-in procedures on DB servers:
                -- MSSQL
                EXEC sp_configure 'show advanced options', 1;
                EXEC sp_configure 'xp_cmdshell', 0;

            ✔ Set a short statement_timeout / query timeout on the DB connection to
              limit the effectiveness of time-based payloads:
                -- PostgreSQL
                SET statement_timeout = '3s';

            ✔ Monitor for slow queries in DB logs — time-based attacks leave traces.
        """),
    },
}

GENERAL_REMEDIATION = textwrap.dedent("""\
    ══════════════════════════════════════════════════════════
     GENERAL SQL INJECTION REMEDIATION GUIDANCE
    ══════════════════════════════════════════════════════════

    1. PARAMETERIZED QUERIES (Primary Defence)
       Never build SQL by concatenating or formatting user-supplied data.
       Use the parameter placeholder of your database driver in EVERY query.

    2. ORM FRAMEWORKS
       Use a battle-tested ORM (SQLAlchemy, Hibernate, ActiveRecord, Entity
       Framework). Avoid raw queries even inside ORMs when possible.

    3. INPUT VALIDATION & ALLOW-LISTING
       Validate the *type*, *format*, and *range* of every input.
       Reject or sanitise before the data ever reaches business logic.

    4. LEAST PRIVILEGE
       The application's DB account should only have SELECT on tables it reads,
       and INSERT/UPDATE/DELETE only on tables it writes. No DDL rights.

    5. ERROR HANDLING
       Log errors server-side; show only generic messages to users.
       Never expose table names, column names, or stack traces.

    6. WAF + RATE LIMITING
       A WAF provides defence-in-depth but is not a substitute for parameterisation.
       Rate-limit login and search endpoints to slow blind enumeration.

    7. SECURITY TESTING
       Run DAST tools (like this one) against staging before every release.
       Supplement with SAST and manual code review of all DB-interacting code.
""")


# ── Reporter ──────────────────────────────────────────────────────────────────

class Reporter:

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.fmt = cfg.get("output", "text")
        self.report_file = cfg.get("report_file")

    def generate(
        self,
        findings: list[Finding],
        entry_points: list,
        scan_meta: dict,
    ):
        findings = sort_findings([f.to_dict() for f in findings])

        if self.fmt == "json":
            output = self._json_report(findings, entry_points, scan_meta)
        elif self.fmt == "html":
            output = self._html_report(findings, entry_points, scan_meta)
        else:
            output = self._text_report(findings, entry_points, scan_meta)

        self._write(output, self.fmt)

    # ── Text Report ───────────────────────────────────────────────────────────

    def _text_report(self, findings: list[dict], entry_points: list, meta: dict) -> str:
        lines = []
        W = 70

        def rule(char="═"):
            return char * W

        def header(title):
            lines.append(rule())
            lines.append(f"  {title}")
            lines.append(rule())

        lines.append("")
        header("INJECTOR SQL — SCAN REPORT")
        lines.append(f"  Target    : {meta['target']}")
        lines.append(f"  Timestamp : {meta['timestamp']}")
        lines.append(f"  Duration  : {meta['duration_sec']}s")
        lines.append(f"  Entry pts : {meta['total_entry_points']}")
        lines.append(f"  Findings  : {len(findings)}")
        lines.append("")

        # Summary counts by severity
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        lines.append("  SEVERITY SUMMARY")
        lines.append("  " + "─" * 30)
        for sev in ["Critical", "High", "Medium", "Low"]:
            icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(sev, "")
            lines.append(f"  {icon}  {sev:<10} {counts.get(sev, 0)}")
        lines.append("")

        if not findings:
            lines.append("  ✅  No vulnerabilities detected.")
            lines.append("")
        else:
            header(f"VULNERABILITY DETAILS  ({len(findings)} finding(s))")
            for i, f in enumerate(findings, 1):
                lines.append("")
                lines.append(f"  [{i}] {'━' * (W - 6)}")
                lines.append(f"  Severity       : {f['severity']}")
                lines.append(f"  Detection Type : {f['detection_type'].replace('_', ' ').title()}")
                lines.append(f"  DB Engine      : {f['db_type']}")
                lines.append(f"  URL            : {f['url']}")
                lines.append(f"  Method         : {f['method']}")
                lines.append(f"  Parameter      : {f['parameter']}")
                lines.append(f"  Payload        : {f['payload']}")
                lines.append(f"  WAF Bypass     : {'Yes' if f['waf_bypass_used'] else 'No'}")
                lines.append(f"  Response Time  : {f['response_time_sec']}s")
                lines.append(f"  Similarity     : {f['similarity_ratio']:.1%}")
                lines.append(f"  Evidence       : {f['evidence'][:200]}")
                lines.append(f"  Source Page    : {f['source_page']}")

                # Inline remediation
                cat = f["payload_category"]
                if cat in REMEDIATION:
                    lines.append("")
                    lines.append(f"  ⚑  REMEDIATION ({cat.replace('_', '-').upper()})")
                    lines.append(f"  {REMEDIATION[cat]['short']}")
            lines.append("")

        # General remediation
        lines.append("")
        lines.append(GENERAL_REMEDIATION)

        return "\n".join(lines)

    # ── JSON Report ───────────────────────────────────────────────────────────

    def _json_report(self, findings: list[dict], entry_points: list, meta: dict) -> str:
        report = {
            "tool": "InjectorSQL",
            "version": "1.0.0",
            "scan": meta,
            "summary": {
                "total_findings": len(findings),
                "by_severity": self._count_by_severity(findings),
                "by_detection_type": self._count_by_key(findings, "detection_type"),
            },
            "findings": findings,
            "entry_points": [e.to_dict() for e in entry_points],
            "remediation": {
                cat: REMEDIATION[cat]["detail"]
                for cat in REMEDIATION
                if any(f["payload_category"] == cat for f in findings)
            },
        }
        return json.dumps(report, indent=2)

    # ── HTML Report ───────────────────────────────────────────────────────────

    def _html_report(self, findings: list[dict], entry_points: list, meta: dict) -> str:
        severity_colors = {
            "Critical": "#dc2626",
            "High":     "#ea580c",
            "Medium":   "#d97706",
            "Low":      "#16a34a",
            "Info":     "#2563eb",
        }
        counts = self._count_by_severity(findings)

        def badge(sev):
            color = severity_colors.get(sev, "#6b7280")
            return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{sev}</span>'

        rows = ""
        for i, f in enumerate(findings, 1):
            cat = f["payload_category"]
            remediation_text = REMEDIATION.get(cat, {}).get("detail", "").replace("\n", "<br>")
            rows += f"""
            <tr>
              <td>{i}</td>
              <td>{badge(f['severity'])}</td>
              <td>{f['detection_type'].replace('_',' ').title()}</td>
              <td><code>{f['url']}</code></td>
              <td>{f['method']}</td>
              <td><strong>{f['parameter']}</strong></td>
              <td><code style="word-break:break-all">{f['payload']}</code></td>
              <td>{f['db_type']}</td>
              <td>{'✅' if f['waf_bypass_used'] else '—'}</td>
              <td>{f['response_time_sec']}s</td>
              <td>{f['evidence'][:200]}</td>
            </tr>
            <tr class="rem-row">
              <td colspan="11">
                <details>
                  <summary>📋 Remediation for {cat.replace('_','-').title()}</summary>
                  <pre style="background:#f8fafc;padding:12px;border-radius:6px;font-size:0.85em">{REMEDIATION.get(cat,{}).get('detail','—')}</pre>
                </details>
              </td>
            </tr>"""

        summary_cards = ""
        for sev in ["Critical", "High", "Medium", "Low"]:
            color = severity_colors.get(sev, "#6b7280")
            cnt = counts.get(sev, 0)
            summary_cards += f"""
            <div style="background:{color};color:#fff;border-radius:8px;padding:16px 24px;text-align:center;min-width:100px">
              <div style="font-size:2em;font-weight:bold">{cnt}</div>
              <div style="font-size:0.9em">{sev}</div>
            </div>"""

        no_findings_msg = "" if findings else '<p style="color:#16a34a;font-size:1.2em">✅ No vulnerabilities detected.</p>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>InjectorSQL — Scan Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}
    h1{{font-size:1.8em;margin-bottom:4px;color:#f8fafc}}
    .subtitle{{color:#94a3b8;margin-bottom:24px;font-size:0.95em}}
    .meta{{background:#1e293b;border-radius:8px;padding:16px;margin-bottom:24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
    .meta-item{{color:#94a3b8;font-size:0.9em}}.meta-item strong{{color:#f1f5f9;display:block}}
    .summary-cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
    table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;font-size:0.85em}}
    th{{background:#334155;padding:10px 8px;text-align:left;color:#94a3b8;font-weight:600;font-size:0.8em;text-transform:uppercase;letter-spacing:.05em}}
    td{{padding:10px 8px;border-bottom:1px solid #334155;vertical-align:top}}
    tr:hover td{{background:#253045}}
    .rem-row td{{background:#0f172a;padding:8px 12px}}
    details summary{{cursor:pointer;color:#60a5fa;font-size:0.85em;padding:4px 0}}
    code{{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.85em;color:#7dd3fc}}
    pre{{white-space:pre-wrap;overflow-x:auto}}
    .general-rem{{background:#1e293b;border-radius:8px;padding:20px;margin-top:32px}}
    .general-rem h2{{margin-bottom:12px;color:#f1f5f9}}
    .general-rem pre{{color:#cbd5e1;font-size:0.85em;line-height:1.6}}
    h2{{margin:24px 0 12px;color:#f1f5f9}}
  </style>
</head>
<body>
  <h1>⚡ InjectorSQL Scan Report</h1>
  <p class="subtitle">Dynamic Application Security Testing — SQL Injection Scanner</p>

  <div class="meta">
    <div class="meta-item"><strong>{meta['target']}</strong>Target</div>
    <div class="meta-item"><strong>{meta['timestamp']}</strong>Timestamp (UTC)</div>
    <div class="meta-item"><strong>{meta['duration_sec']}s</strong>Scan Duration</div>
    <div class="meta-item"><strong>{meta['total_entry_points']}</strong>Entry Points Tested</div>
    <div class="meta-item"><strong>{len(findings)}</strong>Total Findings</div>
  </div>

  <div class="summary-cards">{summary_cards}</div>
  {no_findings_msg}

  {'<h2>Vulnerability Details</h2>' if findings else ''}
  {'<table><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th><th>DB</th><th>WAF Bypass</th><th>Resp. Time</th><th>Evidence</th></tr></thead><tbody>' + rows + '</tbody></table>' if findings else ''}

  <div class="general-rem">
    <h2>General Remediation Guidance</h2>
    <pre>{GENERAL_REMEDIATION}</pre>
  </div>
</body>
</html>"""

    # ── Output Writer ─────────────────────────────────────────────────────────

    def _write(self, content: str, fmt: str):
        ext = {"text": "txt", "json": "json", "html": "html"}.get(fmt, "txt")

        if self.report_file:
            path = Path(self.report_file)
        else:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            path = Path(f"injector_sql_report_{ts}.{ext}")

        # Write to reports dir if it exists, else CWD
        reports_dir = Path("reports")
        if reports_dir.is_dir() and not self.report_file:
            path = reports_dir / path

        path.write_text(content, encoding="utf-8")
        logger.info(f"  Report saved → {path.resolve()}")

        # Always print text summary to stdout
        if fmt == "text":
            print("\n" + content)
        else:
            logger.info(f"  (Use a viewer appropriate for .{ext} files)")

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _count_by_severity(findings: list[dict]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts

    @staticmethod
    def _count_by_key(findings: list[dict], key: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            v = f.get(key, "unknown")
            counts[v] = counts.get(v, 0) + 1
        return counts
