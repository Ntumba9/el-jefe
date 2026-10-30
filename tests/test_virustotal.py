import sqlite3

import httpx
import respx
from httpx import Response

from app.intelligence.virustotal import check_domain, looks_like_domain
from app.models.db import SCHEMA


def make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def test_looks_like_domain_accepts_real_domains_and_rejects_generic_strings():
    assert looks_like_domain("okta.company.com") is True
    assert looks_like_domain("identity_provider") is False
    assert looks_like_domain("not a domain") is False


def test_check_domain_skips_without_api_key():
    conn = make_conn()
    result = check_domain(conn, "evil.example.com", api_key="", cache_ttl_minutes=60)
    assert "no API key configured" in result.summary


def test_check_domain_reports_malicious_verdict():
    conn = make_conn()
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://www.virustotal.com/api/v3/domains/evil.example.com").mock(
            return_value=Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 12, "suspicious": 3},
                            "reputation": -40,
                        }
                    }
                },
            )
        )
        result = check_domain(
            conn, "evil.example.com", api_key="dummy-key", cache_ttl_minutes=60,
            max_retries=0,
        )
    assert "12 engines flagged" in result.summary
    assert result.raw["malicious"] == 12


def test_check_domain_caches_result_and_skips_second_network_call():
    conn = make_conn()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://www.virustotal.com/api/v3/domains/clean.example.com").mock(
            return_value=Response(
                200,
                json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}, "reputation": 0}}},
            )
        )
        check_domain(conn, "clean.example.com", api_key="dummy-key", cache_ttl_minutes=60, max_retries=0)
        check_domain(conn, "clean.example.com", api_key="dummy-key", cache_ttl_minutes=60, max_retries=0)
    assert route.call_count == 1


def test_check_domain_rate_limit_after_retries_degrades_gracefully():
    conn = make_conn()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get("https://www.virustotal.com/api/v3/domains/busy.example.com")
        route.mock(return_value=Response(429, json={"error": "quota exceeded"}))
        result = check_domain(
            conn, "busy.example.com", api_key="dummy-key", cache_ttl_minutes=60,
            max_retries=1, retry_backoff_seconds=0,
        )
    assert "rate limit" in result.summary.lower()
    assert route.call_count == 2


def test_check_domain_http_error_degrades_gracefully():
    conn = make_conn()
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://www.virustotal.com/api/v3/domains/broken.example.com").mock(
            return_value=Response(500, json={"error": "server error"})
        )
        result = check_domain(
            conn, "broken.example.com", api_key="dummy-key", cache_ttl_minutes=60,
            max_retries=0,
        )
    assert "returned HTTP 500" in result.summary


def test_check_domain_connection_error_degrades_gracefully():
    conn = make_conn()
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://www.virustotal.com/api/v3/domains/unreachable.example.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        result = check_domain(
            conn, "unreachable.example.com", api_key="dummy-key", cache_ttl_minutes=60,
            max_retries=0,
        )
    assert "request failed" in result.summary
