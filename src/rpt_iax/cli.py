"""IAX UDP service with admission control before worker creation."""

import logging
import signal
import socketserver
from threading import BoundedSemaphore

from .auth import credentials
from .config import load_settings
from .protocol import RegistrationProtocol
from .publisher import Publisher
from .security import AbuseGuard


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        response = self.server.protocol.handle(data, self.client_address)
        if response:
            sock.sendto(response, self.client_address)


class Server(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 4097

    def __init__(self, address, protocol, guard, workers):
        self.protocol, self.guard = protocol, guard
        self.slots = BoundedSemaphore(workers)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not 12 <= len(request[0]) <= 4096 or not self.guard.ingress(client_address[0]):
            return
        if not self.slots.acquire(blocking=False):
            return
        try:
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
        (settings.HOST, int(settings.PORT)), protocol, guard, int(settings.LIMITS.WORKERS)
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
