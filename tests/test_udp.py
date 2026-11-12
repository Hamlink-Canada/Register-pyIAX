"""Exercise a real UDP exchange, including server dispatch and worker admission."""

import socket
from hashlib import md5
from ipaddress import IPv4Address
from struct import pack, unpack
from threading import Thread

from rpt_iax.cli import Server
from rpt_iax.config import load_settings
from rpt_iax.protocol import RegistrationProtocol, elements, ie
from rpt_iax.security import AbuseGuard

PROXY_V2_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def proxy_v2_udp4(data, source_ip, source_port, destination_ip, destination_port):
    addresses = (
        IPv4Address(source_ip).packed
        + IPv4Address(destination_ip).packed
        + pack("!HH", source_port, destination_port)
    )
    return PROXY_V2_SIGNATURE + b"\x21\x12" + pack("!H", len(addresses)) + addresses + data


def test_udp_exchange(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))

    class Provider:
        def get(self, node):
            return "generated-secret"

    class Publisher:
        sent = []

        def publish(self, *args):
            self.sent.append(args)

    settings = load_settings()
    guard, publisher = AbuseGuard(settings), Publisher()
    protocol = RegistrationProtocol(settings, Provider(), publisher, guard)
    with Server(("127.0.0.1", 0), protocol, guard, 2) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                initial = pack("!HHIBBBB", 0x8001, 0, 0, 0, 0, 6, 13) + ie(6, "1234")
                sock.sendto(initial, server.server_address)
                response = sock.recv(4096)
                challenge = elements(response[12:])[15]
                dest = unpack("!H", response[:2])[0] & 0x7FFF
                proof = md5(challenge + b"generated-secret").hexdigest()
                request = (
                    pack("!HHIBBBB", 0x8001, dest, 1, 1, 0, 6, 13) + ie(6, "1234") + ie(16, proof)
                )
                sock.sendto(request, server.server_address)
                assert sock.recv(4096)[11] == 15
                assert publisher.sent == [("1234", "127.0.0.1", sock.getsockname()[1])]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_udp_exchange_through_proxy_protocol_v2(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))

    class Provider:
        def get(self, node):
            return "generated-secret"

    class Publisher:
        def __init__(self):
            self.sent = []

        def publish(self, *args):
            self.sent.append(args)

    client_ip, client_port = "198.51.100.25", 43210
    settings = load_settings(proxy_protocol={"enabled": True, "trusted_proxies": ["127.0.0.0/8"]})
    guard, publisher = AbuseGuard(settings), Publisher()
    protocol = RegistrationProtocol(settings, Provider(), publisher, guard)
    with Server(
        ("127.0.0.1", 0),
        protocol,
        guard,
        2,
        proxy_protocol=True,
        trusted_proxies=settings.PROXY_PROTOCOL.TRUSTED_PROXIES,
    ) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                initial = pack("!HHIBBBB", 0x8001, 0, 0, 0, 0, 6, 13) + ie(6, "1234")

                def proxy_header(payload):
                    return proxy_v2_udp4(
                        payload,
                        client_ip,
                        client_port,
                        "127.0.0.1",
                        server.server_address[1],
                    )

                sock.sendto(proxy_header(initial), server.server_address)
                response = sock.recv(4096)
                challenge = elements(response[12:])[15]
                dest = unpack("!H", response[:2])[0] & 0x7FFF
                proof = md5(challenge + b"generated-secret").hexdigest()
                request = (
                    pack("!HHIBBBB", 0x8001, dest, 1, 1, 0, 6, 13) + ie(6, "1234") + ie(16, proof)
                )
                sock.sendto(proxy_header(request), server.server_address)
                assert sock.recv(4096)[11] == 15
                assert publisher.sent == [("1234", client_ip, client_port)]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_proxy_mode_rejects_raw_datagrams_and_untrusted_senders(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))

    class Provider:
        def get(self, node):
            raise AssertionError("untrusted or raw packets must not reach IAX processing")

    class Publisher:
        def publish(self, *args):
            raise AssertionError("untrusted or raw packets must not be published")

    settings = load_settings(proxy_protocol={"enabled": True, "trusted_proxies": ["192.0.2.10/32"]})
    guard = AbuseGuard(settings)
    protocol = RegistrationProtocol(settings, Provider(), Publisher(), guard)
    with Server(
        ("127.0.0.1", 0),
        protocol,
        guard,
        2,
        proxy_protocol=True,
        trusted_proxies=settings.PROXY_PROTOCOL.TRUSTED_PROXIES,
    ) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.2)
                raw_iax = pack("!HHIBBBB", 0x8001, 0, 0, 0, 0, 6, 13) + ie(6, "1234")
                sock.sendto(raw_iax, server.server_address)
                try:
                    sock.recv(4096)
                    raise AssertionError("raw IAX must be rejected in proxy mode")
                except TimeoutError:
                    pass
                header = proxy_v2_udp4(
                    raw_iax, "198.51.100.25", 43210, "127.0.0.1", server.server_address[1]
                )
                sock.sendto(header, server.server_address)
                try:
                    sock.recv(4096)
                    raise AssertionError("untrusted proxy senders must be rejected")
                except TimeoutError:
                    pass
        finally:
            server.shutdown()
            thread.join(timeout=2)
