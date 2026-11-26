"""IAX UDP service with admission control before worker creation."""

import logging
import signal
import socketserver
from ipaddress import ip_address, ip_network
from threading import BoundedSemaphore

from .auth import credentials
from .config import load_settings
from .protocol import RegistrationProtocol
from .proxy_protocol import unwrap_datagram
from .publisher import Publisher
from .security import AbuseGuard


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock, *original_peer = self.request
        peer = original_peer[0] if original_peer else self.client_address
        response = self.server.protocol.handle(data, peer)
        if response:
            sock.sendto(response, self.client_address)


class Server(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 65535

    def __init__(
        self, address, protocol, guard, workers, *, proxy_protocol=False, trusted_proxies=()
    ):
        self.protocol, self.guard = protocol, guard
        self.proxy_protocol = proxy_protocol
        self.trusted_proxies = [ip_network(network, strict=False) for network in trusted_proxies]
        self.slots = BoundedSemaphore(workers)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        data, sock = request
        peer = client_address
        if self.proxy_protocol:
            try:
                proxy_ip = ip_address(client_address[0])
                if not any(proxy_ip in network for network in self.trusted_proxies):
                    return
                data, peer = unwrap_datagram(data)
            except ValueError:
                with self.guard.lock:
                    self.guard.metrics["malformed"] += 1
                return
        if not 12 <= len(data) <= 4096 or not self.guard.ingress(peer[0]):
            return
        if not self.slots.acquire(blocking=False):
            return
        try:
            if self.proxy_protocol:
                request = (data, sock, peer)
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    settings = load_settings()
    logging.basicConfig(level=logging.INFO)
    provider, publisher = credentials(settings), Publisher(settings)
    guard = AbuseGuard(settings)
    protocol = RegistrationProtocol(settings, provider, publisher, guard)
    stopped = False
    with Server(
        (settings.HOST, int(settings.PORT)),
        protocol,
        guard,
        int(settings.LIMITS.WORKERS),
        proxy_protocol=bool(settings.PROXY_PROTOCOL.ENABLED),
        trusted_proxies=settings.PROXY_PROTOCOL.TRUSTED_PROXIES,
    ) as server:

        def stop(signum, frame):
            nonlocal stopped
            stopped = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            server.timeout = 0.2
            while not stopped:
                server.handle_request()
        finally:
            provider.close()
            publisher.close()
