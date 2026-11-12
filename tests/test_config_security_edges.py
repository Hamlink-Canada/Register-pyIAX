import pytest

from rpt_iax.config import load_settings
from rpt_iax.security import AbuseGuard


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))


@pytest.mark.parametrize(
    "overrides",
    [
        {"port": 65536},
        {"refresh": 0},
        {"lifetime": 60, "refresh": 60},
        {"server_id": ""},
        {"proxy_protocol": {"enabled": True}},
        {"proxy_protocol": {"trusted_proxies": ["not-a-cidr"]}},
        {"proxy_protocol": {"trusted_proxies": ["2001:db8::/32"]}},
        {"kafka": {"security_protocol": "SSL"}},
        {"kafka": {"security_protocol": "SASL_SSL"}},
    ],
)
def test_iax_config_rejects_invalid_values(overrides):
    with pytest.raises(ValueError):
        load_settings(**overrides)


def test_iax_config_accepts_trusted_ipv4_proxy_cidrs():
    settings = load_settings(proxy_protocol={"enabled": True, "trusted_proxies": ["192.0.2.10/24"]})
    assert settings.PROXY_PROTOCOL.TRUSTED_PROXIES == ["192.0.2.10/24"]


def test_iax_config_merges_file_and_environment(monkeypatch, tmp_path):
    (tmp_path / "settings.toml").write_text(
        '[proxy_protocol]\nenabled=true\ntrusted_proxies=["127.0.0.1/32"]\n'
    )
    monkeypatch.setenv("RPT_SERVER_ID", "from-environment")
    settings = load_settings()
    assert settings.SERVER_ID == "from-environment"
    assert settings.PROXY_PROTOCOL.ENABLED


def test_iax_abuse_guard_consumes_failures_and_bounds_state():
    settings = load_settings(
        limits={
            "state_size": 10,
            "global_burst": 10,
            "fail_ip_burst": 1,
            "fail_pair_burst": 1,
            "refresh_burst": 1,
        }
    )
    now = [5.0]
    guard = AbuseGuard(settings, timer=lambda: now[0])
    assert guard.ingress("192.0.2.1")
    assert guard.auth_allowed("192.0.2.1", "1234")
    guard.failure("192.0.2.1", "1234")
    assert not guard.auth_allowed("192.0.2.1", "1234")
    assert guard.success("192.0.2.1", "1234")
    assert guard.metrics["auth_failure"] == 1
    assert guard.metrics["auth_success"] == 1

    bounded = AbuseGuard(load_settings(limits={"state_size": 2}), timer=lambda: now[0])
    assert bounded.ingress("192.0.2.1")
    assert not bounded.ingress("192.0.2.2")
    assert len(bounded.buckets) == 2
    assert bounded.metrics["state_full"] == 1
