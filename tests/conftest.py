import pytest


@pytest.fixture(autouse=True)
def test_environment(monkeypatch):
    monkeypatch.setenv("RPT_ENVIRONMENT", "development")
