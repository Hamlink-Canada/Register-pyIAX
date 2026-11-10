"""Bounded IAX2 registration transactions with local challenge verification."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import md5, sha256
from hmac import compare_digest
from ipaddress import IPv4Address
from secrets import randbelow, token_hex
from struct import pack, unpack
from threading import RLock
from time import monotonic

from cachetools import TTLCache

from .auth import AuthUnavailable, node_id
from .publisher import PublishUnavailable


def elements(data):
    result = {}
    while data:
        if len(data) < 2:
            raise ValueError("truncated IE header")
        kind, length = data[:2]
        if len(data) < length + 2 or kind in result:
            raise ValueError("invalid IE length or duplicate")
        result[kind] = data[2 : length + 2]
        data = data[length + 2 :]
    return result


def ie(kind, data):
    if isinstance(data, str):
        data = data.encode("ascii")
    return bytes((kind, len(data))) + data


@dataclass
class Transaction:
    node: str
    server_call: int
    challenge: str
    created: float
    lock: RLock = field(default_factory=RLock)
    initial: bytes = b""
    initial_reply: bytes = b""
    terminal: bytes = b""
    terminal_reply: bytes = b""


class RegistrationProtocol:
    def __init__(self, settings, provider, publisher, guard, *, timer=monotonic):
        self.settings, self.provider, self.publisher, self.guard = (
            settings,
            provider,
            publisher,
            guard,
        )
        self.timer = timer
        self.calls = TTLCache(int(settings.LIMITS.CALL_SIZE), 120, timer=timer)
        self.nodes = TTLCache(10000, int(settings.LIFETIME), timer=timer)
        self.lock = RLock()

    def handle(self, data, peer):
        try:
            return self._handle(data, peer)
        except (ValueError, UnicodeError, OverflowError):
            # Do not log attacker-controlled packets or credentials.
            with self.guard.lock:
                self.guard.metrics["malformed"] += 1
            return None

    def _handle(self, data, peer):
        if not 12 <= len(data) <= 4096:
            raise ValueError("invalid packet size")
        source, dest, timestamp, oseq, iseq, frame, sub = unpack("!HHIBBBB", data[:12])
        source, full = source & 0x7FFF, bool(source & 0x8000)
        dest &= 0x7FFF
        if not full or source == 0 or frame != 6 or sub & 0x80:
            return None
        IPv4Address(peer[0])
        if sub == 4:  # Final ACK releases a completed registration transaction.
            key = (peer[0], peer[1], source)
            with self.lock:
                state = self.calls.get(key)
            if state is not None:
                with state.lock:
                    if state.terminal_reply and dest == state.server_call:
                        expected = unpack("!HHIBBBB", state.terminal_reply[:12])
                        if timestamp == expected[2] and iseq == (expected[3] + 1) & 255:
                            with self.lock:
                                if self.calls.get(key) is state:
                                    del self.calls[key]
            return None
        if sub in (2, 11):  # PING/LAGRQ: stateless PONG/LAGRP
            return pack(
                "!HHIBBBB",
                0x8001,
                source,
                timestamp,
                iseq,
                (oseq + 1) & 255,
                6,
                3 if sub == 2 else 12,
            )
        if sub == 0x42:  # Existing discovery response, without allocating call state.
            with self.lock:
                count = min(255, len(self.nodes))
            return self._response(
                0x42,
                source,
                dest or 1,
                timestamp,
                oseq,
                iseq,
                ie(0x42, "rpt-iax 0.2.0") + ie(0x43, bytes([count])),
            )
        if sub != 13:  # Registration only; unsolicited response frames cannot allocate state.
            return None
        values = elements(data[12:])
        node = node_id(values.get(6, b"").decode("ascii"))
        proof = values.get(16)
        if 17 in values:  # RSA is not supported.
            return self._response(
                16,
                source,
                dest or 1,
                timestamp,
                oseq,
                iseq,
                ie(22, "Authentication failed") + ie(42, b"\x0d"),
            )
        if proof is not None and not re.fullmatch(rb"[0-9a-fA-F]{32}", proof):
            raise ValueError("invalid MD5 response")
        key = (peer[0], peer[1], source)
        # Normalize the retransmit flag by hashing only semantic transaction fields.
        fingerprint = sha256(pack("!IBB", timestamp, oseq, sub) + data[12:]).digest()
        with self.lock:
            state = self.calls.get(key)
            if state is None:
                if proof is not None or dest != 0:
                    return None
                if not self.guard.auth_allowed(peer[0], node):
                    return None
                if len(self.calls) >= self.calls.maxsize:
                    return None
                state = Transaction(node, randbelow(32767) + 1, token_hex(16), self.timer())
                self.calls[key] = state
        with state.lock:
            if node != state.node or (dest and dest != state.server_call):
                return None
            if state.terminal:
                return state.terminal_reply if compare_digest(state.terminal, fingerprint) else None
            if proof is None:
                if state.initial:
                    return (
                        state.initial_reply if compare_digest(state.initial, fingerprint) else None
                    )
                state.initial = fingerprint
                state.initial_reply = self._response(
                    14,
                    source,
                    state.server_call,
                    timestamp,
                    oseq,
                    iseq,
                    ie(6, node) + ie(14, pack("!H", 2)) + ie(15, state.challenge),
                )
                return state.initial_reply
            if not dest or self.timer() - state.created >= self.settings.LIMITS.CHALLENGE_TTL:
                return None
            if not self.guard.auth_allowed(peer[0], node):
                return None
            challenge = state.challenge
            state.challenge = ""  # Never reuse a proof for another verification attempt.
            state.terminal = fingerprint
            try:
                password = self.provider.get(node)
                expected = md5((challenge + (password or "")).encode("ascii")).hexdigest().encode()
                valid = password is not None and compare_digest(expected, proof.lower())
                if valid and self.guard.success(peer[0], node):
                    self.publisher.publish(node, peer[0], peer[1])
                    with self.lock:
                        self.nodes[node] = True
                    now = datetime.now(timezone.utc)
                    date = ((now.year - 2000) & 127) << 25 | now.month << 21 | now.day << 16
                    date |= now.hour << 11 | now.minute << 5 | now.second >> 1
                    payload = ie(6, node) + ie(31, pack("!I", date))
                    payload += ie(18, pack("!HH4s8x", 0x0200, peer[1], IPv4Address(peer[0]).packed))
                    payload += ie(19, pack("!H", int(self.settings.REFRESH)))
                    state.terminal_reply = self._response(
                        15, source, state.server_call, timestamp, oseq, iseq, payload
                    )
                    return state.terminal_reply
                if not valid:
                    self.guard.failure(peer[0], node)
            except (AuthUnavailable, PublishUnavailable):
                pass
            state.terminal_reply = self._response(
                16,
                source,
                state.server_call,
                timestamp,
                oseq,
                iseq,
                ie(22, "Authentication failed") + ie(42, b"\x0d"),
            )
            return state.terminal_reply

    @staticmethod
    def _response(sub, source, dest, timestamp, oseq, iseq, payload):
        return (
            pack("!HHIBBBB", dest | 0x8000, source, timestamp, iseq, (oseq + 1) & 255, 6, sub)
            + payload
        )
