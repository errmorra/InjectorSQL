"""
InjectorSQL — Phase 4: Detection Logic
Analyses HTTP responses to identify SQLi indicators with minimal false-positives.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .payloads import Payload
from .utils import content_changed, clean_html, similarity_ratio, logger


# ── Database Error Signatures ─────────────────────────────────────────────────

DB_ERROR_PATTERNS: dict[str, list[re.Pattern]] = {
    "MySQL": [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"mysql_fetch_array\(\)", re.I),
        re.compile(r"mysql_fetch_assoc\(\)", re.I),
        re.compile(r"mysql_num_rows\(\)", re.I),
        re.compile(r"supplied argument is not a valid mysql", re.I),
        re.compile(r"mysql server version for the right syntax", re.I),
        re.compile(r"call to undefined function mysql", re.I),
        re.compile(r"mysqli_fetch_array\(\)", re.I),
        re.compile(r"\[mysqld\]", re.I),
        re.compile(r"ERROR \d{4} \(\d{5}\):", re.I),
    ],
    "MSSQL": [
        re.compile(r"microsoft sql server", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"mssql_query\(\)", re.I),
        re.compile(r"OLE DB.*SQL Server", re.I),
        re.compile(r"syntax error.*converting", re.I),
        re.compile(r"Microsoft OLE DB Provider for ODBC", re.I),
        re.compile(r"\bSQLSRV_ATTR\b", re.I),
        re.compile(r"Incorrect syntax near", re.I),
        re.compile(r"SQLExecDirectW", re.I),
        re.compile(r"\bSQL Server\b.*\bError\b", re.I),
    ],
    "Oracle": [
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"oracle error", re.I),
        re.compile(r"oracle.*driver", re.I),
        re.compile(r"warning.*oci_", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"OCI-\d{5}", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"pg_query\(\)", re.I),
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r"Warning.*pg_", re.I),
        re.compile(r"pgsql syntax error", re.I),
        re.compile(r"invalid input syntax for", re.I),
        re.compile(r"unterminated quoted string at or near", re.I),
        re.compile(r"ERROR:  operator does not exist", re.I),
    ],
    "SQLite": [
        re.compile(r"sqlite error", re.I),
        re.compile(r"sqlite3\.", re.I),
        re.compile(r"SQLite.*Exception", re.I),
        re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
        re.compile(r"unrecognized token", re.I),
    ],
    "Generic": [
        re.compile(r"sql syntax", re.I),
        re.compile(r"sql error", re.I),
        re.compile(r"database error", re.I),
        re.compile(r"unexpected end of SQL command", re.I),
        re.compile(r"DB Error", re.I),
        re.compile(r"ODBC SQL Server Driver", re.I),
        re.compile(r"jdbc:.*:sqlserver", re.I),
        re.compile(r"java\.sql\.SQLException", re.I),
        re.compile(r"ADODB\.Command", re.I),
        re.compile(r"Syntax error in string in query expression", re.I),
        re.compile(r"Data type mismatch in criteria expression", re.I),
    ],
}


# ── Finding Dataclass ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A confirmed SQLi vulnerability."""
    url: str
    method: str
    parameter: str
    payload: Payload
    detection_type: str      # 'error_based' | 'boolean_based' | 'time_based'
    evidence: str            # Excerpt or delta description
    severity: str
    db_type: str             # Detected DB engine or 'Unknown'
    response_time: float     # Seconds
    similarity: float        # Baseline vs injected similarity [0–1]
    source_page: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload.value,
            "payload_category": self.payload.category,
            "detection_type": self.detection_type,
            "evidence": self.evidence,
            "severity": self.severity,
            "db_type": self.db_type,
            "response_time_sec": round(self.response_time, 3),
            "similarity_ratio": round(self.similarity, 4),
            "source_page": self.source_page,
            "waf_bypass_used": self.payload.waf_bypass,
        }


# ── Analyst ───────────────────────────────────────────────────────────────────

class Analyst:
    """
    Stateless analysis methods called by the InjectionEngine per request.
    """

    def __init__(self, cfg: dict):
        self.delay_threshold = cfg.get("delay_threshold", 5.0)
        self.verbose = cfg.get("verbose", False)

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyse(
        self,
        *,
        payload: Payload,
        parameter: str,
        url: str,
        method: str,
        baseline_body: str,
        injected_body: str,
        baseline_status: int,
        injected_status: int,
        response_time: float,
        source_page: str = "",
    ) -> Optional[Finding]:
        """
        Run all detection strategies and return a Finding if vulnerable.
        Returns None if clean.
        """
        db_type = "Unknown"
        evidence = ""
        detection_type = ""

        # ── 1. Error-Based Detection ───────────────────────────────────────────
        if payload.category in ("error", "boolean"):
            db_type, evidence = self._check_db_errors(injected_body)
            if db_type != "Unknown":
                detection_type = "error_based"
                severity = "High"
                # Upgrade to Critical for MSSQL xp_cmdshell
                if "xp_cmdshell" in payload.value.lower():
                    severity = "Critical"
                logger.debug(f"  [!] Error-based hit: {db_type} | param={parameter}")
                return Finding(
                    url=url, method=method, parameter=parameter,
                    payload=payload, detection_type=detection_type,
                    evidence=self._excerpt(evidence), severity=severity,
                    db_type=db_type, response_time=response_time,
                    similarity=similarity_ratio(baseline_body, injected_body),
                    source_page=source_page,
                )

        # ── 2. Boolean-Based Detection ─────────────────────────────────────────
        if payload.category == "boolean":
            sim = similarity_ratio(
                clean_html(baseline_body),
                clean_html(injected_body),
            )
            # Significant content change while status stays same → boolean hit
            changed = sim < 0.85 and injected_status == baseline_status
            if changed:
                detection_type = "boolean_based"
                evidence = (
                    f"Content similarity dropped to {sim:.1%} "
                    f"(baseline={baseline_status}, injected={injected_status})"
                )
                logger.debug(f"  [!] Boolean hit: sim={sim:.3f} | param={parameter}")
                return Finding(
                    url=url, method=method, parameter=parameter,
                    payload=payload, detection_type=detection_type,
                    evidence=evidence, severity="High",
                    db_type="Unknown", response_time=response_time,
                    similarity=sim, source_page=source_page,
                )

        # ── 3. Time-Based Detection ────────────────────────────────────────────
        if payload.category == "time":
            if response_time >= self.delay_threshold:
                detection_type = "time_based"
                evidence = (
                    f"Response delayed {response_time:.2f}s "
                    f"(threshold {self.delay_threshold}s)"
                )
                logger.debug(f"  [!] Time-based hit: {response_time:.2f}s | param={parameter}")
                return Finding(
                    url=url, method=method, parameter=parameter,
                    payload=payload, detection_type=detection_type,
                    evidence=evidence, severity="Critical",
                    db_type=payload.db_target.upper() if payload.db_target != "generic" else "Unknown",
                    response_time=response_time,
                    similarity=similarity_ratio(baseline_body, injected_body),
                    source_page=source_page,
                )

        return None

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _check_db_errors(body: str) -> tuple[str, str]:
        """
        Scan response body for known DB error strings.
        Returns (db_type, matched_excerpt) or ('Unknown', '').
        """
        for db_name, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                m = pattern.search(body)
                if m:
                    start = max(0, m.start() - 40)
                    end   = min(len(body), m.end() + 100)
                    return db_name, body[start:end]
        return "Unknown", ""

    @staticmethod
    def _excerpt(text: str, max_len: int = 200) -> str:
        """Return a clean, truncated excerpt of error text."""
        clean = re.sub(r"\s+", " ", text.strip())
        if len(clean) > max_len:
            clean = clean[:max_len] + "…"
        return clean
