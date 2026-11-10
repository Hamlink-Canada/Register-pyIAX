import time
from concurrent.futures import ThreadPoolExecutor

import grpc
import pytest
from rpt_protobuf.auth_request_pb2 import CredentialResponse
from rpt_protobuf.auth_request_pb2_grpc import (
    CredentialServiceServicer,
    add_CredentialServiceServicer_to_server,
)

from rpt_iax.auth import AuthUnavailable, FileCredentials, GrpcCredentials
from rpt_iax.config import load_settings
from rpt_iax.security import AbuseGuard


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))


@pytest.fixture
def rpc():
    class Service(CredentialServiceServicer):
        count = 0
        unavailable = False
        missing = False
        slow = False

        def GetNodeCredential(self, request, context):
            self.count += 1
            if self.slow:
                time.sleep(0.1)
            if self.unavailable:
                context.abort(grpc.StatusCode.UNAVAILABLE, "unavailable")
            if self.missing:
                context.abort(grpc.StatusCode.NOT_FOUND, "missing")
            return CredentialResponse(password="generated-secret")

    service = Service()
    server = grpc.server(ThreadPoolExecutor(max_workers=4))
    add_CredentialServiceServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    settings = load_settings(auth={"cache_size": 2, "cache_ttl": 60})
    yield service, channel, settings
    channel.close()
    server.stop(0).wait()


def test_csv_valid_and_missing(tmp_path):
    file = tmp_path / "credentials.csv"
    file.write_text("node_id,password\n1234,generated-secret\n")
    provider = FileCredentials(file)
    assert provider.get("1234") == "generated-secret"
    assert provider.get("1235") is None


@pytest.mark.parametrize(
    "contents",
    [
        "1234,password\n",
        "node_id,password\n1,x\n1,y\n",
        "node_id,password\nabc,x\n",
        "node_id,password\n1,\n",
        "node_id,password\n1,x,extra\n",
    ],
)
def test_csv_rejects_invalid(tmp_path, contents):
    file = tmp_path / "credentials.csv"
    file.write_text(contents)
    with pytest.raises(ValueError):
        FileCredentials(file)


def test_cache_lru_ttl_and_outage(rpc):
    service, channel, settings = rpc
    now = [100.0]
    provider = GrpcCredentials(settings, channel=channel, timer=lambda: now[0])
    assert provider.get("1") == "generated-secret"
    assert provider.get("2") == "generated-secret"
    provider.get("1")
    provider.get("3")
    assert list(provider.cache) == ["1", "3"]
    service.unavailable = True
    assert provider.get("1") == "generated-secret"
    with pytest.raises(AuthUnavailable):
        provider.get("2")
    now[0] += 60
    with pytest.raises(AuthUnavailable):
        provider.get("1")
    assert not provider.cache


def test_missing_is_not_cached(rpc):
    service, channel, settings = rpc
    service.missing = True
    provider = GrpcCredentials(settings, channel=channel)
    assert provider.get("1") is None
    assert provider.get("1") is None
    assert service.count == 2


def test_single_flight(rpc):
    service, channel, settings = rpc
    provider = GrpcCredentials(settings, channel=channel)
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(provider.get, ["1"] * 8)) == ["generated-secret"] * 8
    assert service.count == 1


def test_deadline(rpc):
    service, channel, settings = rpc
    service.slow = True
    settings.GRPC.DEADLINE = 0.01
    provider = GrpcCredentials(settings, channel=channel)
    with pytest.raises(AuthUnavailable):
        provider.get("1")
    assert not provider.cache


def test_transport_requires_service_identity():
    settings = load_settings()
    with pytest.raises(ValueError, match="service token"):
        GrpcCredentials(settings)
    settings.GRPC.INSECURE = True
    with pytest.raises(ValueError, match="development"):
        GrpcCredentials(settings)


def test_dynaconf_env_and_files(monkeypatch, tmp_path):
    (tmp_path / "settings.toml").write_text("[auth]\ncache_size = 100\n")
    (tmp_path / ".secrets.toml").write_text('[grpc]\ntoken = "hidden"\n')
    monkeypatch.setenv("RPT_AUTH__CACHE_TTL", "7")
    settings = load_settings()
    assert settings.AUTH.CACHE_SIZE == 100
    assert settings.AUTH.CACHE_TTL == 7
    assert settings.GRPC.TOKEN == "hidden"
    assert settings.GRPC.DEADLINE == 2
    assert settings.AUTH.BACKEND == "file"


def test_abuse_failure_pair_does_not_lock_node_globally():
    now = [1.0]
    guard = AbuseGuard(load_settings(), timer=lambda: now[0])
    for _ in range(5):
        assert guard.auth_allowed("192.0.2.1", "1234")
        guard.failure("192.0.2.1", "1234")
    assert guard.node_failures["1234"] == 5
    assert not guard.auth_allowed("192.0.2.1", "1234")
    assert guard.auth_allowed("192.0.2.2", "1234")
    now[0] += 12
    assert guard.auth_allowed("192.0.2.1", "1234")


def test_bounded_ingress_state():
    settings = load_settings(limits={"state_size": 2})
    guard = AbuseGuard(settings)
    assert guard.ingress("192.0.2.1")
    assert not guard.ingress("192.0.2.2")
    assert len(guard.buckets) == 2


def test_verified_tls_service_token(rpc, tmp_path):
    import subprocess

    from rpt_iax.auth import credentials

    service, _, settings = rpc
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    seen = []
    original = service.GetNodeCredential

    def authenticated(request, context):
        seen.append(dict(context.invocation_metadata()).get("authorization"))
        if seen[-1] != "Bearer service-secret":
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "unauthorized")
        return original(request, context)

    service.GetNodeCredential = authenticated
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    add_CredentialServiceServicer_to_server(service, server)
    creds = grpc.ssl_server_credentials(((key.read_bytes(), cert.read_bytes()),))
    port = server.add_secure_port("127.0.0.1:0", creds)
    server.start()
    settings.AUTH.BACKEND = "grpc"
    settings.GRPC.TARGET = f"localhost:{port}"
    settings.GRPC.CA = str(cert)
    settings.GRPC.TOKEN = "service-secret"
    provider = credentials(settings)
    try:
        assert provider.get("1234") == "generated-secret"
        assert seen == ["Bearer service-secret"]
        settings.GRPC.TOKEN = "wrong-secret"
        denied = credentials(settings)
        try:
            with pytest.raises(AuthUnavailable):
                denied.get("1234")
        finally:
            denied.close()
    finally:
        provider.close()
        server.stop(0).wait()
