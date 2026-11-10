"""Exercise a real UDP exchange, including server dispatch and worker admission."""

import socket
from hashlib import md5
from struct import pack, unpack
from threading import Thread

from rpt_iax.cli import Server
from rpt_iax.config import load_settings
from rpt_iax.protocol import RegistrationProtocol, elements, ie
from rpt_iax.security import AbuseGuard


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
