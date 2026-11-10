"""Credential providers; protocol verification belongs to the caller.

Kept identical in both registrars. The protobuf repository owns messages only.
"""

import csv
import re
from collections import Counter
from pathlib import Path
from threading import BoundedSemaphore, RLock

import grpc
from cachetools import TTLCache
from rpt_protobuf.auth_request_pb2 import CredentialRequest
from rpt_protobuf.auth_request_pb2_grpc import CredentialServiceStub


class AuthUnavailable(Exception):
    """The credential service could not establish an authentication decision."""


def node_id(value):
    text = str(value)
    if not re.fullmatch(r"[1-9][0-9]{0,18}", text) or int(text) > 2**63 - 1:
        raise ValueError("invalid node ID")
    return text


def valid_password(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 79
        and value.isascii()
        and not any(ord(c) < 33 or ord(c) == 127 for c in value)
    )


class FileCredentials:
    def __init__(self, filename):
        self.accounts = {}
        with open(filename, newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != ["node_id", "password"]:
                raise ValueError("credential CSV requires node_id,password header")
            for row in reader:
                if set(row) != {"node_id", "password"}:
                    raise ValueError("invalid credential row")
                key = node_id(row["node_id"])
                if key in self.accounts or not valid_password(row["password"]):
                    raise ValueError("duplicate node or invalid password")
                self.accounts[key] = row["password"]

    def get(self, key):
        return self.accounts.get(node_id(key))

    def close(self):
        pass


class GrpcCredentials:
    def __init__(self, settings, *, channel=None, timer=None):
        self.timeout = float(settings.GRPC.DEADLINE)
        self.capacity = BoundedSemaphore(int(settings.GRPC.CONCURRENCY))
        self.locks = [RLock() for _ in range(64)]
        self.lock = RLock()
        self.metrics = Counter()
        kwargs = {} if timer is None else {"timer": timer}
        self.cache = TTLCache(
            int(settings.AUTH.CACHE_SIZE), float(settings.AUTH.CACHE_TTL), **kwargs
        )
        token = settings.GRPC.TOKEN
        self.metadata = (("authorization", f"Bearer {token}"),) if token else ()
        if channel is None:
            if settings.GRPC.INSECURE:
                if settings.ENVIRONMENT != "development":
                    raise ValueError("insecure gRPC requires development environment")
                channel = grpc.insecure_channel(settings.GRPC.TARGET)
            else:
                cert, key = settings.GRPC.CLIENT_CERT, settings.GRPC.CLIENT_KEY
                if bool(cert) != bool(key):
                    raise ValueError("client certificate and key must be configured together")
                if not token and not cert:
                    raise ValueError("gRPC requires a service token or client certificate")

                def read(filename):
                    return Path(filename).read_bytes() if filename else None

                credentials = grpc.ssl_channel_credentials(
                    root_certificates=read(settings.GRPC.CA),
                    private_key=read(key),
                    certificate_chain=read(cert),
                )
                channel = grpc.secure_channel(settings.GRPC.TARGET, credentials)
        self.channel = channel
        self.stub = CredentialServiceStub(channel)

    def get(self, key):
        key = node_id(key)
        # Fixed lock stripes bound memory and coalesce concurrent lookups for one node.
        stripe = self.locks[int(key) % len(self.locks)]
        if not stripe.acquire(timeout=self.timeout):
            raise AuthUnavailable("credential lookup wait exceeded deadline")
        try:
            with self.lock:
                try:
                    password = self.cache[key]
                except KeyError:
                    pass
                else:
                    self.metrics["cache_hit"] += 1
                    return password
            if not self.capacity.acquire(blocking=False):
                raise AuthUnavailable("credential lookup capacity exceeded")
            try:
                response = self.stub.GetNodeCredential(
                    CredentialRequest(node_id=int(key)),
                    timeout=self.timeout,
                    metadata=self.metadata,
                )
                if not valid_password(response.password):
                    raise AuthUnavailable("invalid credential service response")
                with self.lock:
                    self.cache[key] = response.password
                    self.metrics["lookup_success"] += 1
                return response.password
            except grpc.RpcError as error:
                with self.lock:
                    self.metrics["lookup_failure"] += 1
                if error.code() == grpc.StatusCode.NOT_FOUND:
                    return None
                raise AuthUnavailable("credential service unavailable") from None
            finally:
                self.capacity.release()
        finally:
            stripe.release()

    def close(self):
        self.channel.close()


def credentials(settings):
    if settings.AUTH.BACKEND == "file":
        return FileCredentials(settings.AUTH.FILE)
    if settings.AUTH.BACKEND == "grpc":
        return GrpcCredentials(settings)
    raise ValueError("auth.backend must be file or grpc")
