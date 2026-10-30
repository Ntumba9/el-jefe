import sqlite3

import httpx

from app.intelligence.cache import get_cached, set_cached
from app.models.schemas import IntelResult

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip(
    conn: sqlite3.Connection,
    ip: str,
    api_key: str,
    cache_ttl_minutes: int,
    client: httpx.Client | None = None,
) -> tuple[IntelResult, int]:
    """Looks up an IP's abuse confidence score via AbuseIPDB, with caching.

    Returns (IntelResult, abuse_confidence_score). On a missing API key,
    network error, or non-2xx response, degrades to a neutral result
    (score 0, summary explaining why) rather than raising, so a threat-intel
    outage never blocks the detection pipeline. That is a deliberate
    trade-off for this project: a production system might instead retry or
    queue the lookup rather than silently treating it as "clean".
    """
    cache_key = f"abuseipdb:{ip}"
    cached = get_cached(conn, cache_key, cache_ttl_minutes)
    if cached is not None:
        return IntelResult(**cached["result"]), cached["score"]

    if not api_key:
        result = IntelResult(
            source="abuseipdb",
            summary="AbuseIPDB lookup skipped: no API key configured.",
            raw={},
        )
        return result, 0

    owns_client = client is None
    client = client or httpx.Client(timeout=5.0)
    try:
        response = client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        result = IntelResult(
            source="abuseipdb",
            summary=(
                f"AbuseIPDB confidence score {score} "
                f"({data.get('totalReports', 0)} reports, "
                f"country {data.get('countryCode', 'unknown')})."
            ),
            raw=data,
        )
    except httpx.HTTPStatusError as exc:
        result = IntelResult(
            source="abuseipdb",
            summary=f"AbuseIPDB returned HTTP {exc.response.status_code}; treating as unknown.",
            raw={"error": str(exc)},
        )
        score = 0
    except httpx.HTTPError as exc:
        result = IntelResult(
            source="abuseipdb",
            summary=f"AbuseIPDB request failed ({exc.__class__.__name__}); treating as unknown.",
            raw={"error": str(exc)},
        )
        score = 0
    finally:
        if owns_client:
            client.close()

    set_cached(conn, cache_key, "abuseipdb", {"result": result.model_dump(), "score": score})
    return result, score
