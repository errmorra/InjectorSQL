"""
InjectorSQL — Test Suite
Uses 'responses' library to mock HTTP calls; no live network required.
"""

import json
import pytest
import responses as resp_mock
from unittest.mock import MagicMock, patch

from injector_sql.crawler import Spider, EntryPoint
from injector_sql.payloads import PayloadLibrary, Payload, WafBypass
from injector_sql.detector import Analyst
from injector_sql.utils import (
    validate_target,
    content_changed,
    similarity_ratio,
    sort_findings,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

BASE_CFG = {
    "target": "http://localhost:8080",
    "depth": 1,
    "forms_only": False,
    "params_only": False,
    "exclude": [],
    "headers": {},
    "cookies": {},
    "auth": None,
    "error_based": True,
    "boolean_based": True,
    "time_based": True,
    "waf_bypass": False,
    "delay_threshold": 5.0,
    "custom_payloads": None,
    "threads": 2,
    "timeout": 5.0,
    "delay": 0,
    "user_agent": "InjectorSQL-Test/1.0",
    "proxy": None,
    "verify_ssl": False,
    "output": "text",
    "report_file": None,
    "verbose": False,
    "quiet": True,
}

MYSQL_ERROR_HTML = """
<html><body>
<p>You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near ''' at line 1</p>
</body></html>
"""

NORMAL_HTML = "<html><body><p>Welcome! Here are your results.</p></body></html>"


# ── Utility Tests ─────────────────────────────────────────────────────────────

class TestUtils:

    def test_validate_target_valid_http(self):
        ok, msg = validate_target("http://localhost:8080")
        assert ok

    def test_validate_target_valid_https(self):
        ok, msg = validate_target("https://192.168.1.10/dvwa")
        assert ok

    def test_validate_target_invalid_scheme(self):
        ok, _ = validate_target("ftp://example.com")
        assert not ok

    def test_validate_target_no_host(self):
        ok, _ = validate_target("http://")
        assert not ok

    def test_similarity_identical(self):
        assert similarity_ratio("hello world", "hello world") == 1.0

    def test_similarity_different(self):
        ratio = similarity_ratio("hello world", "completely different text here")
        assert ratio < 0.5

    def test_content_changed_same(self):
        assert content_changed("abc", "abc") is False

    def test_content_changed_different(self):
        long_a = "user john has 5 items in cart"
        long_b = "x" * 200
        assert content_changed(long_a, long_b) is True

    def test_sort_findings(self):
        findings = [
            {"severity": "Low"},
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]
        sorted_f = sort_findings(findings)
        assert [f["severity"] for f in sorted_f] == ["Critical", "High", "Medium", "Low"]


# ── Payload Tests ─────────────────────────────────────────────────────────────

class TestPayloadLibrary:

    def test_all_categories_loaded(self):
        lib = PayloadLibrary(BASE_CFG)
        cats = {p.category for p in lib}
        assert "error" in cats
        assert "boolean" in cats
        assert "time" in cats

    def test_error_only(self):
        cfg = {**BASE_CFG, "boolean_based": False, "time_based": False}
        lib = PayloadLibrary(cfg)
        assert all(p.category == "error" for p in lib)

    def test_boolean_only(self):
        cfg = {**BASE_CFG, "error_based": False, "time_based": False}
        lib = PayloadLibrary(cfg)
        assert all(p.category == "boolean" for p in lib)

    def test_time_only(self):
        cfg = {**BASE_CFG, "error_based": False, "boolean_based": False}
        lib = PayloadLibrary(cfg)
        assert all(p.category == "time" for p in lib)

    def test_waf_bypass_expands_payloads(self):
        base_count = len(PayloadLibrary(BASE_CFG))
        cfg = {**BASE_CFG, "waf_bypass": True}
        waf_count = len(PayloadLibrary(cfg))
        assert waf_count > base_count

    def test_custom_payloads_from_file(self, tmp_path):
        f = tmp_path / "custom.txt"
        f.write_text("' CUSTOM PAYLOAD 1--\n# comment\n' CUSTOM PAYLOAD 2--\n")
        cfg = {**BASE_CFG, "error_based": False, "boolean_based": False,
               "time_based": False, "custom_payloads": str(f)}
        lib = PayloadLibrary(cfg)
        values = [p.value for p in lib]
        assert "' CUSTOM PAYLOAD 1--" in values
        assert "' CUSTOM PAYLOAD 2--" in values
        # Comments should not be included
        assert "# comment" not in values

    def test_payload_dataclass_fields(self):
        p = Payload(
            value="' OR 1=1--",
            category="boolean",
            description="Test payload",
            db_target="generic",
            severity="High",
        )
        assert p.waf_bypass is False
        assert p.severity == "High"


# ── WAF Bypass Tests ──────────────────────────────────────────────────────────

class TestWafBypass:

    def test_case_variation(self):
        result = WafBypass.case_variation("SELECT * FROM users")
        # Keywords should be mixed case
        assert result != "SELECT * FROM users"
        assert result.lower() == "select * from users"

    def test_comment_injection(self):
        result = WafBypass.comment_injection("SELECT id FROM users")
        assert "/**/" in result

    def test_whitespace_sub(self):
        result = WafBypass.whitespace_sub("SELECT id FROM users")
        assert " " not in result
        assert "/**/" in result

    def test_tab_sub(self):
        result = WafBypass.tab_sub("SELECT id FROM users")
        assert " " not in result
        assert "\t" in result

    def test_all_variants_returns_list(self):
        p = Payload("SELECT * FROM users WHERE id=1", "boolean", "test", "generic", "High")
        variants = WafBypass.all_variants(p)
        assert isinstance(variants, list)
        assert len(variants) > 0
        for v in variants:
            assert v.waf_bypass is True

    def test_hex_encode(self):
        result = WafBypass.hex_encode_strings("SELECT * FROM users WHERE name='admin'")
        assert "0x" in result


# ── Detector / Analyst Tests ──────────────────────────────────────────────────

class TestAnalyst:

    def setup_method(self):
        self.analyst = Analyst(BASE_CFG)
        self.error_payload = Payload("'", "error", "Single quote", "generic", "Medium")
        self.bool_payload  = Payload("' OR 1=1--", "boolean", "OR true", "generic", "High")
        self.time_payload  = Payload("' AND SLEEP(5)--", "time", "SLEEP", "mysql", "Critical")

    def test_detects_mysql_error(self):
        finding = self.analyst.analyse(
            payload=self.error_payload,
            parameter="id",
            url="http://localhost/page",
            method="GET",
            baseline_body=NORMAL_HTML,
            injected_body=MYSQL_ERROR_HTML,
            baseline_status=200,
            injected_status=200,
            response_time=0.1,
        )
        assert finding is not None
        assert finding.detection_type == "error_based"
        assert finding.db_type == "MySQL"
        assert finding.severity in ("Medium", "High", "Critical")

    def test_clean_response_returns_none(self):
        finding = self.analyst.analyse(
            payload=self.error_payload,
            parameter="id",
            url="http://localhost/page",
            method="GET",
            baseline_body=NORMAL_HTML,
            injected_body=NORMAL_HTML,
            baseline_status=200,
            injected_status=200,
            response_time=0.1,
        )
        assert finding is None

    def test_detects_boolean_differential(self):
        # Drastically different content should flag
        large_diff_body = "x" * 5000  # Very different from NORMAL_HTML
        finding = self.analyst.analyse(
            payload=self.bool_payload,
            parameter="id",
            url="http://localhost/page",
            method="GET",
            baseline_body=NORMAL_HTML,
            injected_body=large_diff_body,
            baseline_status=200,
            injected_status=200,
            response_time=0.1,
        )
        assert finding is not None
        assert finding.detection_type == "boolean_based"

    def test_detects_time_based(self):
        finding = self.analyst.analyse(
            payload=self.time_payload,
            parameter="id",
            url="http://localhost/page",
            method="GET",
            baseline_body=NORMAL_HTML,
            injected_body=NORMAL_HTML,
            baseline_status=200,
            injected_status=200,
            response_time=5.5,  # Above threshold
        )
        assert finding is not None
        assert finding.detection_type == "time_based"
        assert finding.severity == "Critical"

    def test_time_based_below_threshold(self):
        finding = self.analyst.analyse(
            payload=self.time_payload,
            parameter="id",
            url="http://localhost/page",
            method="GET",
            baseline_body=NORMAL_HTML,
            injected_body=NORMAL_HTML,
            baseline_status=200,
            injected_status=200,
            response_time=1.0,  # Below threshold
        )
        assert finding is None

    def test_finding_to_dict(self):
        finding = self.analyst.analyse(
            payload=self.error_payload,
            parameter="id",
            url="http://localhost/page",
            method="GET",
            baseline_body=NORMAL_HTML,
            injected_body=MYSQL_ERROR_HTML,
            baseline_status=200,
            injected_status=200,
            response_time=0.2,
        )
        assert finding is not None
        d = finding.to_dict()
        assert "url" in d
        assert "payload" in d
        assert "severity" in d
        assert "evidence" in d


# ── Crawler Tests ─────────────────────────────────────────────────────────────

class TestSpider:

    FORM_HTML = """
    <html><body>
      <form action="/search" method="POST">
        <input type="text" name="q" value="">
        <input type="hidden" name="csrf" value="token123">
        <input type="submit" value="Search">
      </form>
      <a href="/about">About</a>
      <a href="http://external.com/page">External</a>
    </body></html>
    """

    @resp_mock.activate
    def test_extracts_form(self):
        resp_mock.add(resp_mock.GET, "http://localhost:8080", body=self.FORM_HTML, status=200)
        resp_mock.add(resp_mock.GET, "http://localhost:8080/about", body="<html><body>About</body></html>", status=200)

        cfg = {**BASE_CFG, "depth": 1}
        spider = Spider(cfg)
        eps = spider.crawl()

        form_eps = [e for e in eps if e.kind == "form"]
        assert len(form_eps) >= 1
        form = form_eps[0]
        assert form.method == "POST"
        assert "q" in form.params
        # Submit button should be excluded
        assert "submit" not in [k.lower() for k in form.params]

    @resp_mock.activate
    def test_extracts_url_params(self):
        resp_mock.add(
            resp_mock.GET, "http://localhost:8080",
            body='<html><body><a href="/search?id=1&cat=books">Search</a></body></html>',
            status=200,
        )
        resp_mock.add(
            resp_mock.GET, "http://localhost:8080/search",
            body="<html><body>Results</body></html>",
            status=200,
        )
        cfg = {**BASE_CFG, "depth": 1}
        spider = Spider(cfg)
        eps = spider.crawl()

        url_eps = [e for e in eps if e.kind == "url_param"]
        assert len(url_eps) >= 1
        params = url_eps[0].params
        assert "id" in params or "cat" in params

    @resp_mock.activate
    def test_does_not_follow_external_links(self):
        resp_mock.add(resp_mock.GET, "http://localhost:8080",
                      body='<html><body><a href="http://evil.com/page">Evil</a></body></html>',
                      status=200)
        cfg = {**BASE_CFG, "depth": 2}
        spider = Spider(cfg)
        eps = spider.crawl()
        # External domain should not be crawled
        for ep in eps:
            assert "evil.com" not in ep.url

    @resp_mock.activate
    def test_forms_only_skips_url_params(self):
        resp_mock.add(
            resp_mock.GET, "http://localhost:8080",
            body='<html><body><a href="/page?id=1">link</a>'
                 '<form action="/login" method="POST">'
                 '<input name="user"><input name="pass"></form></body></html>',
            status=200,
        )
        resp_mock.add(resp_mock.GET, "http://localhost:8080/page",
                      body="<html><body>page</body></html>", status=200)

        cfg = {**BASE_CFG, "forms_only": True}
        spider = Spider(cfg)
        eps = spider.crawl()
        assert all(e.kind == "form" for e in eps)

    @resp_mock.activate
    def test_params_only_skips_forms(self):
        resp_mock.add(
            resp_mock.GET, "http://localhost:8080",
            body='<html><body><a href="/page?id=1">link</a>'
                 '<form action="/login" method="POST">'
                 '<input name="user"></form></body></html>',
            status=200,
        )
        resp_mock.add(resp_mock.GET, "http://localhost:8080/page",
                      body="<html><body>page</body></html>", status=200)

        cfg = {**BASE_CFG, "params_only": True}
        spider = Spider(cfg)
        eps = spider.crawl()
        assert all(e.kind == "url_param" for e in eps)


# ── Entry Point Tests ─────────────────────────────────────────────────────────

class TestEntryPoint:

    def test_to_dict(self):
        ep = EntryPoint(
            url="http://localhost/search",
            method="GET",
            params={"q": "test"},
            kind="url_param",
            source="http://localhost/",
        )
        d = ep.to_dict()
        assert d["url"] == "http://localhost/search"
        assert d["method"] == "GET"
        assert d["params"] == {"q": "test"}
        assert d["kind"] == "url_param"

    def test_repr(self):
        ep = EntryPoint("http://localhost/", "POST", {"a": "1"}, "form", "http://localhost/")
        r = repr(ep)
        assert "form" in r
        assert "POST" in r
