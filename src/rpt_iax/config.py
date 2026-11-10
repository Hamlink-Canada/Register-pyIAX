"""Dynaconf settings; files are resolved explicitly from RPT_CONFIG_DIR or cwd."""

import os
from pathlib import Path

from dynaconf import Dynaconf

DEFAULTS = {
    "environment": "production",
    "host": "0.0.0.0",
    "port": 4569,
    "refresh": 60,
    "lifetime": 180,
    "server_id": "registration",
    "auth": {"backend": "file", "file": "credentials.csv", "cache_size": 4096, "cache_ttl": 60},
    "grpc": {
        "target": "localhost:50051",
        "deadline": 2,
        "concurrency": 16,
        "insecure": False,
        "token": "",
        "ca": "",
        "client_cert": "",
        "client_key": "",
    },
    "kafka": {"bootstrap": "localhost:9092", "topic": "rpt.registrations", "timeout": 5},
    "http": {"max_body": 16384, "trusted_proxies": [], "proxy_hops": 1},
    "limits": {
        "state_size": 16384,
        "global_rate": 60000,
        "global_burst": 2000,
        "source_rate": 600,
        "source_burst": 120,
        "fail_ip_rate": 30,
        "fail_ip_burst": 30,
        "fail_pair_rate": 5,
        "fail_pair_burst": 5,
        "refresh_rate": 6,
        "refresh_burst": 3,
        "workers": 32,
        "challenge_ttl": 30,
        "call_size": 4096,
    },
}


def load_settings(**overrides):
    directory = Path(os.environ.get("RPT_CONFIG_DIR", ".")).resolve()
    # Preloading defaults lets nested file and environment settings merge predictably.
    settings = Dynaconf(
        envvar_prefix="RPT",
        environments=False,
        merge_enabled=True,
        settings_files=[],
        load_dotenv=False,
    )
    settings.update(DEFAULTS)
    for name in ("settings.toml", ".secrets.toml"):
        path = directory / name
        if path.exists():
            settings.load_file(path=str(path))
    # Reapply environment values after defaults/files.
    from dynaconf.loaders import env_loader

    env_loader.load(settings, env="RPT")
    settings.update(overrides, merge=True)
    for value in (
        settings.PORT,
        settings.REFRESH,
        settings.LIFETIME,
        settings.AUTH.CACHE_SIZE,
        settings.AUTH.CACHE_TTL,
        settings.GRPC.DEADLINE,
        settings.GRPC.CONCURRENCY,
        settings.KAFKA.TIMEOUT,
        *settings.LIMITS.values(),
    ):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
            raise ValueError("numeric configuration values must be positive")
    if settings.PORT > 65535 or settings.REFRESH > 65535 or settings.LIFETIME <= settings.REFRESH:
        raise ValueError("invalid port, refresh, or lifetime")
    if not settings.KAFKA.TOPIC or not settings.SERVER_ID:
        raise ValueError("Kafka topic and server ID are required")
    return settings
