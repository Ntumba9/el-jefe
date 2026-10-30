"""Small retry helper shared by the AbuseIPDB and VirusTotal clients.

Only retries transient failures: connection-level errors and 5xx/429
responses. A 4xx other than 429 (bad request, bad key) is a client error
that retrying won't fix, so it's returned as-is for the caller to handle.
"""

import time

import httpx

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def get_with_retry(
    client: httpx.Client,
    url: str,
    *,
    max_retries: int,
    backoff_base_seconds: float,
    **kwargs,
) -> httpx.Response:
    attempt = 0
    while True:
        try:
            response = client.get(url, **kwargs)
        except httpx.HTTPError:
            if attempt >= max_retries:
                raise
            time.sleep(backoff_base_seconds * (2**attempt))
            attempt += 1
            continue

        if response.status_code in RETRYABLE_STATUS_CODES and attempt < max_retries:
            time.sleep(backoff_base_seconds * (2**attempt))
            attempt += 1
            continue

        return response
