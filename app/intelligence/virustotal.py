import re
import sqlite3

import httpx

from app.intelligence.cache import get_cached, set_cached
from app.intelligence.retry import get_with_retry
from app.logging_config import get_logger
from app.models.schemas import IntelResult

VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

logger = get_logger(__name__)

# A loose check for "does this look like a domain", used only to decide
# whether to call VirusTotal at all. The authentication-event schema has
# no dedicated URL/domain field, so this only fires when the identity
# provider's own `source` value happens to look like one
# (e.g. "okta.company.com"), never on fabricated or synthetic values.
_DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")


def looks_like_domain(value: str) -> bool:
    return bool(_DOMAIN_PATTERN.match(value))


def check_domain(
    conn: sqlite3.Connection,
    domain: str,
    api_key: str,
    cache_ttl_minutes: int,
    client: httpx.Client | None = None,
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
) -> IntelResult:
    """Looks up a domain's reputation via VirusTotal, with caching.

    Transient failures (a connection error, or a 429/5xx response) are
    retried with exponential backoff up to max_retries. Degrades to a
    neutral result on a missing key, a still-failing request, or a
    rate limit that persists through retries, rather than raising — a
    threat-intel outage should not take down event ingestion.
    """
    cache_key = f"virustotal:{domain}"
    cached = get_cached(conn, cache_key, cache_ttl_minutes)
    if cached is not None:
        logger.debug("virustotal.cache_hit", extra={"domain": domain})
        return IntelResult(**cached)

    if not api_key:
        result = IntelResult(
            source="virustotal",
            summary="VirusTotal lookup skipped: no API key configured.",
            raw={},
        )
        return result

    owns_client = client is None
    client = client or httpx.Client(timeout=5.0)
    try:
        response = get_with_retry(
            client,
            VT_DOMAIN_URL.format(domain=domain),
            max_retries=max_retries,
            backoff_base_seconds=retry_backoff_seconds,
            headers={"x-apikey": api_key},
        )
        if response.status_code == 429:
            logger.warning("virustotal.rate_limited", extra={"domain": domain})
            result = IntelResult(
                source="virustotal",
                summary="VirusTotal rate limit reached; skipping this lookup.",
                raw={},
            )
        else:
            response.raise_for_status()
            attributes = response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            result = IntelResult(
                source="virustotal",
                summary=(
                    f"VirusTotal: {malicious} engines flagged '{domain}' malicious, "
                    f"{suspicious} suspicious, reputation {attributes.get('reputation', 0)}."
                ),
                raw=stats,
            )
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "virustotal.http_error", extra={"domain": domain, "status_code": exc.response.status_code}
        )
        result = IntelResult(
            source="virustotal",
            summary=f"VirusTotal returned HTTP {exc.response.status_code}; treating as unknown.",
            raw={"error": str(exc)},
        )
    except httpx.HTTPError as exc:
        logger.warning(
            "virustotal.request_failed", extra={"domain": domain, "error_type": exc.__class__.__name__}
        )
        result = IntelResult(
            source="virustotal",
            summary=f"VirusTotal request failed ({exc.__class__.__name__}); treating as unknown.",
            raw={"error": str(exc)},
        )
    finally:
        if owns_client:
            client.close()

    set_cached(conn, cache_key, "virustotal", result.model_dump())
    return result
