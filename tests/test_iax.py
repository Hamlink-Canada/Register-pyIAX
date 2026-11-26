from hashlib import md5
from struct import pack, unpack

import pytest

from rpt_iax.config import load_settings
from rpt_iax.protocol import RegistrationProtocol, elements, ie
from rpt_iax.security import AbuseGuard


class Provider:
    count = 0

    def get(self, node):
        self.count += 1
        return "generated-secret" if node == "1234" else None


class Publisher:
    def __init__(self):
        self.sent = []

    def publish(self, *args):
        self.sent.append(args)


def packet(payload, dest=0, timestamp=0, sequence=0, source=1):
    return pack("!HHIBBBB", source | 0x8000, dest, timestamp, sequence, 0, 6, 13) + payload


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("RPT_CONFIG_DIR", str(tmp_path))
    settings = load_settings()
    provider, publisher = Provider(), Publisher()
    now = [100.0]
    protocol = RegistrationProtocol(
        settings, provider, publisher, AbuseGuard(settings), timer=lambda: now[0]
    )
    return protocol, provider, publisher, now


def exchange(protocol, peer=("192.0.2.1", 4569)):
    initial = packet(ie(6, "1234"))
    challenge_packet = protocol.handle(initial, peer)
    assert challenge_packet[11] == 14
    challenge = elements(challenge_packet[12:])[15]
    dest = unpack("!H", challenge_packet[:2])[0] & 0x7FFF
    proof = md5(challenge + b"generated-secret").hexdigest()
    request = packet(ie(6, "1234") + ie(16, proof), dest=dest, timestamp=1, sequence=1)
    return initial, challenge_packet, request


def test_registration_and_retransmission(setup):
    protocol, provider, publisher, _ = setup
    peer = ("192.0.2.1", 4569)
    initial, challenge, request = exchange(protocol)
    assert protocol.handle(initial, peer) == challenge
    response = protocol.handle(request, peer)
    assert response[11] == 15
    assert unpack("!H", elements(response[12:])[19])[0] == 60
    assert publisher.sent == [("1234", *peer)]
    assert protocol.handle(request, peer) == response
    assert len(publisher.sent) == provider.count == 1


def test_peer_and_identity_binding(setup):
    protocol, provider, publisher, _ = setup
    _, _, request = exchange(protocol)
    assert protocol.handle(request, ("192.0.2.2", 4569)) is None
    assert protocol.handle(request, ("192.0.2.1", 4570)) is None
    changed = request.replace(b"1234", b"5678")
    assert protocol.handle(changed, ("192.0.2.1", 4569)) is None
    assert not publisher.sent and provider.count == 0


def test_challenge_expiry(setup):
    protocol, provider, publisher, now = setup
    _, _, request = exchange(protocol)
    now[0] += 30
    assert protocol.handle(request, ("192.0.2.1", 4569)) is None
    assert provider.count == 0


def test_wrong_proof_consumed(setup):
    protocol, provider, publisher, _ = setup
    _, _, request = exchange(protocol)
    bad = request[:18] + b"0" * 32  # rebuild well-formed proof instead below
    dest = unpack("!H", request[2:4])[0]
    bad = packet(ie(6, "1234") + ie(16, "0" * 32), dest, 1, 1)
    assert protocol.handle(bad, ("192.0.2.1", 4569))[11] == 16
    assert protocol.handle(request, ("192.0.2.1", 4569)) is None
    assert not publisher.sent and provider.count == 1


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a" * 11,
        packet(b"\x06"),
        packet(b"\x06\xffx"),
        packet(ie(6, "abc")),
        packet(ie(6, "1234") + ie(16, "bad")),
        packet(ie(6, "1234") + ie(6, "1234")),
        b"x" * 4097,
    ],
)
def test_malformed_is_dropped_without_backend(setup, data):
    protocol, provider, publisher, _ = setup
    assert protocol.handle(data, ("192.0.2.1", 4569)) is None
    assert not publisher.sent and provider.count == 0


def test_unknown_frame_allocates_no_state(setup):
    protocol, _, _, _ = setup
    data = bytearray(packet(ie(6, "1234")))
    data[11] = 255
    assert protocol.handle(bytes(data), ("192.0.2.1", 4569)) is None
    assert not protocol.calls


def test_rsa_rejected(setup):
    protocol, provider, publisher, _ = setup
    response = protocol.handle(packet(ie(6, "1234") + ie(17, "rsa")), ("192.0.2.1", 4569))
    assert response[11] == 16
    assert provider.count == 0 and not publisher.sent


def test_final_ack_allows_next_registration_using_same_call(setup):
    protocol, provider, publisher, _ = setup
    peer = ("192.0.2.1", 4569)
    initial, _, request = exchange(protocol)
    reply = protocol.handle(request, peer)
    server_call, client_call, timestamp, oseq, iseq, _, _ = unpack("!HHIBBBB", reply[:12])
    ack = pack(
        "!HHIBBBB",
        client_call | 0x8000,
        server_call & 0x7FFF,
        timestamp,
        iseq,
        (oseq + 1) & 255,
        6,
        4,
    )
    assert protocol.handle(ack, peer) is None
    assert not protocol.calls
    assert protocol.handle(request, peer) is None
    fresh = protocol.handle(initial, peer)
    assert fresh[11] == 14
    assert len(publisher.sent) == provider.count == 1
