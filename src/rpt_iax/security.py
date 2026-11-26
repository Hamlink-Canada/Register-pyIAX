"""Bounded per-process throttling. Deploy shared ingress limits for replicas."""

from collections import Counter
from threading import RLock
from time import monotonic

from cachetools import TTLCache


class AbuseGuard:
    def __init__(self, settings, *, timer=monotonic):
        self.settings = settings.LIMITS
        self.timer = timer
        self.lock = RLock()
        self.buckets = TTLCache(int(self.settings.STATE_SIZE), 600, timer=timer)
        self.node_failures = TTLCache(int(self.settings.STATE_SIZE), 300, timer=timer)
        self.metrics = Counter()

    def _allow(self, key, rate, burst):
        now = self.timer()
        with self.lock:
            if key not in self.buckets and len(self.buckets) >= self.buckets.maxsize:
                self.metrics["state_full"] += 1
                return False
            tokens, last = self.buckets.get(key, (float(burst), now))
            tokens = min(float(burst), tokens + max(0, now - last) * float(rate) / 60)
            allowed = tokens >= 1
            self.buckets[key] = (tokens - 1 if allowed else tokens, now)
            if not allowed:
                self.metrics["throttled"] += 1
            return allowed

    def ingress(self, ip):
        return self._allow(
            ("global",), self.settings.GLOBAL_RATE, self.settings.GLOBAL_BURST
        ) and self._allow(("source", ip), self.settings.SOURCE_RATE, self.settings.SOURCE_BURST)

    def auth_allowed(self, ip, node):
        # Failure tokens are consumed after failure, independently of successful refreshes.
        with self.lock:
            for key, rate, burst in [
                (("fail_ip", ip), self.settings.FAIL_IP_RATE, self.settings.FAIL_IP_BURST),
                (
                    ("fail_pair", ip, node),
                    self.settings.FAIL_PAIR_RATE,
                    self.settings.FAIL_PAIR_BURST,
                ),
            ]:
                if key not in self.buckets:
                    if len(self.buckets) >= self.buckets.maxsize:
                        self.metrics["state_full"] += 1
                        return False
                    self.buckets[key] = (float(burst), self.timer())
                tokens, last = self.buckets.get(key, (float(burst), self.timer()))
                if min(float(burst), tokens + max(0, self.timer() - last) * float(rate) / 60) < 1:
                    self.metrics["auth_throttled"] += 1
                    return False
        return True

    def failure(self, ip, node):
        self._allow(("fail_ip", ip), self.settings.FAIL_IP_RATE, self.settings.FAIL_IP_BURST)
        self._allow(
            ("fail_pair", ip, node), self.settings.FAIL_PAIR_RATE, self.settings.FAIL_PAIR_BURST
        )
        with self.lock:
            self.metrics["auth_failure"] += 1
            self.node_failures[node] = self.node_failures.get(node, 0) + 1

    def success(self, ip, node):
        allowed = self._allow(
            ("refresh", ip, node), self.settings.REFRESH_RATE, self.settings.REFRESH_BURST
        )
        with self.lock:
            self.metrics["auth_success"] += 1
        return allowed
