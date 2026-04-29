"""
InjectorSQL — Phase 3: Injection Engine
Orchestrates baseline requests, payload injection, and concurrent scanning.
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlencode, urlunparse, urlparse, parse_qs

import requests
import urllib3

from .crawler import EntryPoint
from .payloads import Payload, PayloadLibrary
from .detector import Analyst, Finding
from .utils import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Thread-safe counter for progress
_lock = threading.Lock()
_completed = 0
_total = 0


class InjectionEngine:
    """
    Core engine:
      1. Builds a payload library (Phase 2)
      2. Takes each EntryPoint from the spider
      3. Sends a baseline request
      4. Injects each payload into each parameter (Phase 3)
      5. Passes results to Analyst (Phase 4)
      6. Returns de-duplicated list of Findings
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.library = PayloadLibrary(cfg)
        self.analyst = Analyst(cfg)
        self._session = self._build_session()
        self._findings: list[Finding] = []
        self._seen_findings: set[tuple] = set()

    # ── Session ───────────────────────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = self.cfg.get("user_agent", "InjectorSQL/1.0")
        s.headers.update(self.cfg.get("headers", {}))
        s.cookies.update(self.cfg.get("cookies", {}))
        if self.cfg.get("auth"):
            s.auth = self.cfg["auth"]
        if self.cfg.get("proxy"):
            s.proxies = {
                "http": self.cfg["proxy"],
                "https": self.cfg["proxy"],
            }
        s.verify = self.cfg.get("verify_ssl", False)
        return s

    # ── Entry Point ───────────────────────────────────────────────────────────

    def run(self, entry_points: list[EntryPoint]) -> list[Finding]:
        global _completed, _total

        payloads = list(self.library)
        logger.info(f"  Total payloads  : {len(payloads)}")

        # Build work units: (entry_point, parameter_name, payload)
        work_units = []
        for ep in entry_points:
            for param in ep.params:
                for payload in payloads:
                    work_units.append((ep, param, payload))

        _total = len(work_units)
        _completed = 0
        logger.info(f"  Work units      : {_total}")
        logger.info(f"  Threads         : {self.cfg.get('threads', 5)}\n")

        # Baseline requests cache — keyed by (url, method, frozenset(params))
        baselines: dict[tuple, tuple[str, int]] = {}

        with ThreadPoolExecutor(max_workers=self.cfg.get("threads", 5)) as executor:
            futures = {
                executor.submit(
                    self._process_unit, ep, param, payload, baselines
                ): (ep, param, payload)
                for (ep, param, payload) in work_units
            }

            for future in as_completed(futures):
                try:
                    finding = future.result()
                    if finding:
                        self._record(finding)
                except Exception as exc:
                    ep, param, payload = futures[future]
                    logger.debug(f"Error scanning {ep.url} param={param}: {exc}")
                finally:
                    with _lock:
                        _completed += 1
                        if _completed % 50 == 0 or _completed == _total:
                            pct = _completed / _total * 100
                            logger.info(
                                f"  Progress: {_completed}/{_total} "
                                f"({pct:.0f}%)  Findings so far: {len(self._findings)}"
                            )

        return self._findings

    # ── Work Unit ─────────────────────────────────────────────────────────────

    def _process_unit(
        self,
        ep: EntryPoint,
        param: str,
        payload: Payload,
        baselines: dict,
    ) -> Optional[Finding]:
        """
        Send baseline (once per entry point) then injected request.
        Return Finding or None.
        """
        baseline_key = (ep.url, ep.method, frozenset(ep.params.keys()))

        # ── Baseline ───────────────────────────────────────────────────────────
        with _lock:
            cached = baselines.get(baseline_key)

        if cached is None:
            baseline_body, baseline_status = self._send(
                ep.url, ep.method, ep.params
            )
            with _lock:
                baselines[baseline_key] = (baseline_body, baseline_status)
        else:
            baseline_body, baseline_status = cached

        if baseline_body is None:
            return None

        # ── Injected Request ───────────────────────────────────────────────────
        injected_params = dict(ep.params)
        injected_params[param] = payload.value

        t0 = time.monotonic()
        injected_body, injected_status = self._send(ep.url, ep.method, injected_params)
        response_time = time.monotonic() - t0

        if injected_body is None:
            return None

        if self.cfg.get("delay"):
            time.sleep(self.cfg["delay"])

        # ── Analyse ────────────────────────────────────────────────────────────
        return self.analyst.analyse(
            payload=payload,
            parameter=param,
            url=ep.url,
            method=ep.method,
            baseline_body=baseline_body,
            injected_body=injected_body,
            baseline_status=baseline_status,
            injected_status=injected_status,
            response_time=response_time,
            source_page=ep.source,
        )

    # ── HTTP Helpers ──────────────────────────────────────────────────────────

    def _send(
        self,
        url: str,
        method: str,
        params: dict[str, str],
    ) -> tuple[Optional[str], int]:
        """
        Send a GET or POST request.
        Returns (body_text, status_code) or (None, 0) on error.
        """
        timeout = self.cfg.get("timeout", 10)

        # For time-based payloads the timeout needs to be longer
        effective_timeout = max(timeout, self.cfg.get("delay_threshold", 5) + 3)

        try:
            if method == "GET":
                full_url = self._build_get_url(url, params)
                resp = self._session.get(
                    full_url,
                    timeout=effective_timeout,
                    allow_redirects=True,
                )
            else:
                resp = self._session.post(
                    url,
                    data=params,
                    timeout=effective_timeout,
                    allow_redirects=True,
                )
            return resp.text, resp.status_code

        except requests.exceptions.Timeout:
            # A timeout itself can be a time-based indicator —
            # return a sentinel body and large time
            logger.debug(f"Request timed out: {url}")
            return "", 0

        except requests.exceptions.RequestException as exc:
            logger.debug(f"Request error {url}: {exc}")
            return None, 0

    @staticmethod
    def _build_get_url(base_url: str, params: dict[str, str]) -> str:
        """Append query parameters to a URL."""
        parsed = urlparse(base_url)
        query = urlencode(params)
        new = parsed._replace(query=query)
        return urlunparse(new)

    # ── De-duplication ────────────────────────────────────────────────────────

    def _record(self, finding: Finding):
        """Add finding if not a duplicate (same url + param + detection_type)."""
        key = (finding.url, finding.parameter, finding.detection_type, finding.payload.category)
        with _lock:
            if key not in self._seen_findings:
                self._seen_findings.add(key)
                self._findings.append(finding)
                severity_icon = {
                    "Critical": "🔴",
                    "High":     "🟠",
                    "Medium":   "🟡",
                    "Low":      "🟢",
                }.get(finding.severity, "⚪")
                logger.info(
                    f"  {severity_icon} FOUND [{finding.severity}] "
                    f"{finding.detection_type.upper()} | "
                    f"param={finding.parameter} | "
                    f"url={finding.url}"
                )
