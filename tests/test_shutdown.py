import socketserver
import threading
import time
from threading import BoundedSemaphore

from rpt_iax.cli import Server


def test_server_close_waits_for_admitted_worker_before_closing_socket(monkeypatch):
    server = object.__new__(Server)
    server.worker_limit = 1
    server.slots = BoundedSemaphore(1)
    server.handlers_drained = False
    server.slots.acquire()
    closed = threading.Event()
    monkeypatch.setattr(socketserver.UDPServer, "server_close", lambda self: closed.set())
    thread = threading.Thread(target=server.server_close)
    thread.start()
    time.sleep(0.02)
    assert not closed.is_set()
    server.slots.release()
    thread.join(timeout=1)
    assert closed.is_set()
