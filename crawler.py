"""
InjectorSQL — Phase 1: Reconnaissance & Discovery
Spider that crawls the target domain, extracts HTML forms and URL parameters.
"""

from __future__ import annotations

import fnmatch
import time
from collections import deque
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlencode

import requests
from bs4 import BeautifulSoup

from .utils import logger, normalize_url


class EntryPoint:
    """
    Represents one injectable entry point discovered on the target.

    Attributes:
        url      – The URL where the request is sent
        method   – HTTP method ('GET' or 'POST')
        params   – dict of parameter names → baseline values
        kind     – 'form' | 'url_param'
        source   – The page URL where this entry point was found
    """

    def __init__(
        self,
        url: str,
        method: str,
        params: dict[str, str],
        kind: str,
        source: str,
    ):
        self.url = url
        self.method = method.upper()
        self.params = params
        self.kind = kind
        self.source = source

    def __repr__(self):
        return (
            f"<EntryPoint [{self.kind}] {self.method} {self.url} "
            f"params={list(self.params.keys())}>"
        )

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "kind": self.kind,
            "source": self.source,
        }


class Spider:
    """
    BFS crawler that stays within the target domain and collects EntryPoints.
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.base_url = cfg["target"]
        self.base_domain = urlparse(self.base_url).netloc
        self.depth = cfg.get("depth", 2)
        self.exclude_patterns = cfg.get("exclude", [])
        self.forms_only = cfg.get("forms_only", False)
        self.params_only = cfg.get("params_only", False)
        self.verbose = cfg.get("verbose", False)

        self._session = self._build_session()
        self._visited: set[str] = set()
        self._entry_points: list[EntryPoint] = []

    # ── Session ───────────────────────────────────────────────────────────────

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = self.cfg.get("user_agent", "InjectorSQL/1.0")
        s.headers.update(self.cfg.get("headers", {}))
        s.cookies.update(self.cfg.get("cookies", {}))
        if self.cfg.get("auth"):
            s.auth = self.cfg["auth"]
        if self.cfg.get("proxy"):
            s.proxies = {"http": self.cfg["proxy"], "https": self.cfg["proxy"]}
        s.verify = self.cfg.get("verify_ssl", False)
        return s

    # ── Crawl ────────────────────────────────────────────────────────────────

    def crawl(self) -> list[EntryPoint]:
        """BFS crawl. Returns list of EntryPoint objects."""
        queue: deque[tuple[str, int]] = deque()
        queue.append((self.base_url, 0))
        self._visited.add(normalize_url(self.base_url))

        while queue:
            url, depth = queue.popleft()

            if depth > self.depth:
                continue

            try:
                resp = self._session.get(
                    url,
                    timeout=self.cfg.get("timeout", 10),
                    allow_redirects=True,
                )
            except Exception as exc:
                logger.debug(f"Crawl error on {url}: {exc}")
                continue

            if self.cfg.get("delay"):
                time.sleep(self.cfg["delay"])

            logger.debug(f"Crawled [{resp.status_code}] {url}")

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract forms
            if not self.params_only:
                self._extract_forms(soup, url)

            # Extract URL parameters on the current URL
            if not self.forms_only:
                self._extract_url_params(url)

            # Find new links to follow
            if depth < self.depth:
                for link in soup.find_all("a", href=True):
                    href = link["href"].strip()
                    abs_url = urljoin(url, href).split("#")[0]
                    norm = normalize_url(abs_url)

                    if norm in self._visited:
                        continue
                    if not self._same_domain(abs_url):
                        continue
                    if self._is_excluded(abs_url):
                        continue

                    self._visited.add(norm)
                    queue.append((abs_url, depth + 1))

                    # Also extract URL params while discovering
                    if not self.forms_only:
                        self._extract_url_params(abs_url)

        # Deduplicate
        seen = set()
        unique = []
        for ep in self._entry_points:
            key = (ep.url, ep.method, frozenset(ep.params.keys()), ep.kind)
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        logger.info(f"  Pages crawled   : {len(self._visited)}")
        logger.info(f"  Forms found     : {sum(1 for e in unique if e.kind == 'form')}")
        logger.info(f"  URL params found: {sum(1 for e in unique if e.kind == 'url_param')}")

        return unique

    # ── Form Extraction ───────────────────────────────────────────────────────

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").strip().upper()
            target_url = urljoin(page_url, action) if action else page_url

            params: dict[str, str] = {}

            for tag in form.find_all(["input", "textarea", "select"]):
                input_type = tag.get("type", "text").lower()
                name = tag.get("name", "").strip()
                if not name:
                    continue
                if input_type in ("submit", "button", "reset", "image"):
                    continue
                value = tag.get("value", "test")
                params[name] = value if value else "test"

            if params:
                ep = EntryPoint(
                    url=target_url,
                    method=method,
                    params=params,
                    kind="form",
                    source=page_url,
                )
                self._entry_points.append(ep)
                logger.debug(f"  Form: {method} {target_url} → {list(params.keys())}")

    # ── URL Parameter Extraction ───────────────────────────────────────────────

    def _extract_url_params(self, url: str):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return

        # Flatten lists → single value
        params = {k: (v[0] if v else "") for k, v in qs.items()}

        # Reconstruct clean base URL without query string
        base = parsed._replace(query="", fragment="").geturl()

        ep = EntryPoint(
            url=base,
            method="GET",
            params=params,
            kind="url_param",
            source=url,
        )
        self._entry_points.append(ep)
        logger.debug(f"  URL params: GET {base} → {list(params.keys())}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_domain

    def _is_excluded(self, url: str) -> bool:
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(url, pattern):
                return True
        return False
