#!/usr/bin/env python3
"""
InjectorSQL — Professional SQL Injection Vulnerability Scanner
Author: InjectorSQL Contributors
License: MIT
WARNING: Use ONLY on systems you own or have explicit written permission to test.
"""

import argparse
import sys
import time
import json
from datetime import datetime
from urllib.parse import urlparse

from .crawler import Spider
from .engine import InjectionEngine
from .reporter import Reporter
from .utils import banner, logger, validate_target


def parse_args():
    parser = argparse.ArgumentParser(
        prog="injector-sql",
        description="InjectorSQL — DAST SQL Injection Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  injector-sql -u http://localhost:8080 --depth 3
  injector-sql -u http://dvwa.local/login.php --forms-only --cookie "PHPSESSID=abc123"
  injector-sql -u http://dvwa.local --waf-bypass --threads 10
  injector-sql -u http://localhost:8080 --time-based --delay-threshold 4.5
  injector-sql -u http://dvwa.local --output json --report-file results.json

⚠  Always test against DVWA, OWASP Juice Shop, or other intentionally vulnerable apps.
        """,
    )

    # --- Target ---
    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Target base URL (e.g. http://localhost:8080)",
    )

    # --- Scope ---
    scope = parser.add_argument_group("Scope")
    scope.add_argument(
        "--depth",
        type=int,
        default=2,
        metavar="N",
        help="Crawler depth (default: 2)",
    )
    scope.add_argument(
        "--forms-only",
        action="store_true",
        help="Skip URL parameter injection; test HTML forms only",
    )
    scope.add_argument(
        "--params-only",
        action="store_true",
        help="Skip forms; test URL query parameters only",
    )
    scope.add_argument(
        "--exclude",
        metavar="PATTERN",
        nargs="*",
        default=[],
        help="URL patterns to exclude (glob-style)",
    )

    # --- Auth ---
    auth = parser.add_argument_group("Authentication")
    auth.add_argument(
        "--cookie",
        metavar="COOKIES",
        help='Cookie string (e.g. "PHPSESSID=abc; security=low")',
    )
    auth.add_argument(
        "--header",
        metavar="HEADER",
        action="append",
        dest="headers",
        default=[],
        help='Extra header "Name: Value" (repeatable)',
    )
    auth.add_argument(
        "--auth",
        metavar="USER:PASS",
        help="Basic HTTP authentication",
    )

    # --- Payloads ---
    payloads = parser.add_argument_group("Payloads")
    payloads.add_argument(
        "--error-based",
        action="store_true",
        default=False,
        help="Include error-based SQLi payloads (default: all enabled)",
    )
    payloads.add_argument(
        "--boolean-based",
        action="store_true",
        default=False,
        help="Include boolean-based SQLi payloads",
    )
    payloads.add_argument(
        "--time-based",
        action="store_true",
        default=False,
        help="Include time-based SQLi payloads (slower)",
    )
    payloads.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Enable WAF bypass variants (hex encoding, case variation, comments)",
    )
    payloads.add_argument(
        "--delay-threshold",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Time-based detection threshold in seconds (default: 5.0)",
    )
    payloads.add_argument(
        "--custom-payloads",
        metavar="FILE",
        help="Path to a newline-delimited file of custom payloads",
    )

    # --- Engine ---
    engine = parser.add_argument_group("Engine")
    engine.add_argument(
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="Concurrent request threads (default: 5)",
    )
    engine.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SEC",
        help="Per-request timeout (default: 10s)",
    )
    engine.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Throttle delay between requests in seconds",
    )
    engine.add_argument(
        "--user-agent",
        metavar="UA",
        default="InjectorSQL/1.0 (Security Scanner; +https://github.com/yourname/InjectorSQL)",
        help="Custom User-Agent string",
    )
    engine.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)",
    )
    engine.add_argument(
        "--verify-ssl",
        action="store_true",
        default=False,
        help="Verify SSL certificates (disabled by default for lab environments)",
    )

    # --- Output ---
    output = parser.add_argument_group("Output")
    output.add_argument(
        "--output",
        choices=["text", "json", "html"],
        default="text",
        help="Report format (default: text)",
    )
    output.add_argument(
        "--report-file",
        metavar="FILE",
        help="Save report to file (auto-named if omitted)",
    )
    output.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    output.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and progress; print findings only",
    )

    return parser.parse_args()


def build_session_config(args) -> dict:
    """Translate CLI args into a unified config dict passed to all components."""
    headers = {}
    for h in args.headers:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    auth = None
    if args.auth and ":" in args.auth:
        u, p = args.auth.split(":", 1)
        auth = (u, p)

    # If no payload type explicitly chosen, enable all
    any_chosen = args.error_based or args.boolean_based or args.time_based
    return {
        "target": args.url.rstrip("/"),
        "depth": args.depth,
        "forms_only": args.forms_only,
        "params_only": args.params_only,
        "exclude": args.exclude,
        "headers": headers,
        "cookies": cookies,
        "auth": auth,
        "error_based": args.error_based if any_chosen else True,
        "boolean_based": args.boolean_based if any_chosen else True,
        "time_based": args.time_based if any_chosen else True,
        "waf_bypass": args.waf_bypass,
        "delay_threshold": args.delay_threshold,
        "custom_payloads": args.custom_payloads,
        "threads": args.threads,
        "timeout": args.timeout,
        "delay": args.delay,
        "user_agent": args.user_agent,
        "proxy": args.proxy,
        "verify_ssl": args.verify_ssl,
        "output": args.output,
        "report_file": args.report_file,
        "verbose": args.verbose,
        "quiet": args.quiet,
    }


def main():
    args = parse_args()
    cfg = build_session_config(args)

    if not cfg["quiet"]:
        banner()

    # Validate target
    ok, msg = validate_target(cfg["target"])
    if not ok:
        logger.error(msg)
        sys.exit(1)

    logger.info(f"Target  : {cfg['target']}")
    logger.info(f"Depth   : {cfg['depth']}")
    logger.info(f"Threads : {cfg['threads']}")
    logger.info(f"WAF bypass: {'ON' if cfg['waf_bypass'] else 'OFF'}")
    logger.info(f"Payloads: error={cfg['error_based']} | boolean={cfg['boolean_based']} | time={cfg['time_based']}")
    print()

    scan_start = time.time()

    # ── Phase 1: Reconnaissance ─────────────────────────────────────────────
    logger.info("Phase 1 — Reconnaissance & Discovery")
    spider = Spider(cfg)
    entry_points = spider.crawl()
    logger.info(f"Discovered {len(entry_points)} entry point(s)\n")

    if not entry_points:
        logger.warning("No injectable entry points found. Exiting.")
        sys.exit(0)

    # ── Phase 2–4: Injection & Detection ────────────────────────────────────
    logger.info("Phase 2–4 — Fuzzing, Injection & Analysis")
    engine = InjectionEngine(cfg)
    findings = engine.run(entry_points)

    scan_duration = round(time.time() - scan_start, 2)

    # ── Phase 5: Reporting ───────────────────────────────────────────────────
    logger.info("\nPhase 5 — Report Generation")
    reporter = Reporter(cfg)
    reporter.generate(
        findings=findings,
        entry_points=entry_points,
        scan_meta={
            "target": cfg["target"],
            "duration_sec": scan_duration,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_entry_points": len(entry_points),
        },
    )

    # Exit code: 1 if vulnerabilities found (useful for CI pipelines)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
