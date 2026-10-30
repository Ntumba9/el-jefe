import importlib
import os
import uuid

import pytest
from fastapi.testclient import TestClient

API_KEY = "test-api-key"


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    def _make(**extra_env):
        db_path = tmp_path / f"sentinel-{uuid.uuid4().hex}.db"
        monkeypatch.setenv("SENTINEL_API_KEY", API_KEY)
        monkeypatch.setenv("SENTINEL_DB_PATH", str(db_path))
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
        for key, value in extra_env.items():
            monkeypatch.setenv(key, value)

        import app.config as config_module

        importlib.reload(config_module)

        import app.models.db as db_module

        importlib.reload(db_module)

        import app.main as main_module

        importlib.reload(main_module)

        test_client = TestClient(main_module.app)
        test_client.headers.update({"X-API-Key": API_KEY})
        return test_client

    return _make


@pytest.fixture
def client(make_client):
    with make_client() as test_client:
        yield test_client


def auth_event(**overrides) -> dict:
    event = {
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
        "username": "jane.doe@company.com",
        "source_ip": "203.0.113.10",
        "timestamp": "2026-10-30T09:30:00Z",
        "status": "failed",
        "authentication_method": "password",
        "user_role": "employee",
        "location": "Unknown",
        "source": "identity_provider",
    }
    event.update(overrides)
    return event
