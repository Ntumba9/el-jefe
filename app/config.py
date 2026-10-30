import os
from dotenv import load_dotenv

load_dotenv()


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    return int(value) if value else default


class Settings:
    api_key: str = os.getenv("SENTINEL_API_KEY", "")
    db_path: str = os.getenv("SENTINEL_DB_PATH", "./sentinel.db")

    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    correlation_window_minutes: int = _int_env("SENTINEL_CORRELATION_WINDOW_MINUTES", 15)
    failed_login_threshold: int = _int_env("SENTINEL_FAILED_LOGIN_THRESHOLD", 5)
    spray_distinct_accounts_threshold: int = _int_env(
        "SENTINEL_SPRAY_DISTINCT_ACCOUNTS_THRESHOLD", 4
    )
    abuseipdb_score_threshold: int = _int_env("SENTINEL_ABUSEIPDB_SCORE_THRESHOLD", 50)
    intel_cache_ttl_minutes: int = _int_env("SENTINEL_INTEL_CACHE_TTL_MINUTES", 60)


settings = Settings()
