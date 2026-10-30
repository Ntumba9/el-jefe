import os
from dotenv import load_dotenv

load_dotenv()


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value else default


class Settings:
    # Separate credentials for two different trust levels: anything that
    # can submit events (an automated pipeline, e.g. Activepieces) is not
    # automatically trusted to approve a containment decision for a human.
    ingest_api_key: str = os.getenv("ELJEFE_INGEST_API_KEY", "")
    decision_api_key: str = os.getenv("ELJEFE_DECISION_API_KEY", "")

    db_path: str = os.getenv("ELJEFE_DB_PATH", "./eljefe.db")

    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    correlation_window_minutes: int = _int_env("ELJEFE_CORRELATION_WINDOW_MINUTES", 15)
    failed_login_threshold: int = _int_env("ELJEFE_FAILED_LOGIN_THRESHOLD", 5)
    spray_distinct_accounts_threshold: int = _int_env(
        "ELJEFE_SPRAY_DISTINCT_ACCOUNTS_THRESHOLD", 4
    )
    abuseipdb_score_threshold: int = _int_env("ELJEFE_ABUSEIPDB_SCORE_THRESHOLD", 50)
    intel_cache_ttl_minutes: int = _int_env("ELJEFE_INTEL_CACHE_TTL_MINUTES", 60)

    # How far back to look when counting a username/IP's prior HIGH/CRITICAL
    # incidents for the cross-incident correlation context (not a detection
    # rule; see app/risk/correlation.py).
    incident_correlation_lookback_days: int = _int_env(
        "ELJEFE_INCIDENT_CORRELATION_LOOKBACK_DAYS", 30
    )

    intel_max_retries: int = _int_env("ELJEFE_INTEL_MAX_RETRIES", 2)
    intel_retry_backoff_seconds: float = float(os.getenv("ELJEFE_INTEL_RETRY_BACKOFF_SECONDS", "0.5"))

    log_level: str = os.getenv("ELJEFE_LOG_LEVEL", "INFO")


settings = Settings()
