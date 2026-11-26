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

        def refill_ttl(*names):
            return max(
                600,
                *(
                    60
                    * float(getattr(self.settings, f"{name}_BURST"))
                    / float(getattr(self.settings, f"{name}_RATE"))
                    for name in names
                ),
            )

        capacity = int(self.settings.STATE_SIZE)
        self.global_buckets = TTLCache(1, refill_ttl("GLOBAL"), timer=timer)
        self.source_buckets = TTLCache(capacity, refill_ttl("SOURCE"), timer=timer)
        self.auth_buckets = TTLCache(capacity, refill_ttl("FAIL_IP", "FAIL_PAIR"), timer=timer)
        self.refresh_buckets = TTLCache(capacity, refill_ttl("REFRESH"), timer=timer)
        self.node_failures = TTLCache(int(self.settings.STATE_SIZE), 300, timer=timer)
        self.metrics = Counter()

    def _allow(self, buckets, key, rate, burst):
        now = self.timer()
        with self.lock:
            if key not in buckets and len(buckets) >= buckets.maxsize:
                self.metrics["state_full"] += 1
                return False
            tokens, last = buckets.get(key, (float(burst), now))
            tokens = min(float(burst), tokens + max(0, now - last) * float(rate) / 60)
            allowed = tokens >= 1
            buckets[key] = (tokens - 1 if allowed else tokens, now)
            if not allowed:
                self.metrics["throttled"] += 1
            return allowed

    def ingress(self, ip):
        with self.lock:
            now = self.timer()
            if (
                ip not in self.source_buckets
                and len(self.source_buckets) >= self.source_buckets.maxsize
            ):
                self.metrics["state_full"] += 1
                return False
            tokens, last = self.source_buckets.get(ip, (float(self.settings.SOURCE_BURST), now))
            tokens = min(
                float(self.settings.SOURCE_BURST),
                tokens + max(0, now - last) * float(self.settings.SOURCE_RATE) / 60,
            )
            if tokens < 1:
                self.source_buckets[ip] = (tokens, now)
                self.metrics["throttled"] += 1
                return False
            if not self._allow(
                self.global_buckets,
                "global",
                self.settings.GLOBAL_RATE,
                self.settings.GLOBAL_BURST,
            ):
                return False
            self.source_buckets[ip] = (tokens - 1, now)
            return True

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
                if key not in self.auth_buckets:
                    if len(self.auth_buckets) >= self.auth_buckets.maxsize:
                        self.metrics["state_full"] += 1
                        return False
                    self.auth_buckets[key] = (float(burst), self.timer())
                tokens, last = self.auth_buckets.get(key, (float(burst), self.timer()))
                if min(float(burst), tokens + max(0, self.timer() - last) * float(rate) / 60) < 1:
                    self.metrics["auth_throttled"] += 1
                    return False
        return True

    def failure(self, ip, node):
        self._allow(
            self.auth_buckets,
            ("fail_ip", ip),
            self.settings.FAIL_IP_RATE,
            self.settings.FAIL_IP_BURST,
        )
        self._allow(
            self.auth_buckets,
            ("fail_pair", ip, node),
            self.settings.FAIL_PAIR_RATE,
            self.settings.FAIL_PAIR_BURST,
        )
        with self.lock:
            self.metrics["auth_failure"] += 1
            self.node_failures[node] = self.node_failures.get(node, 0) + 1

    def success(self, ip, node):
        allowed = self._allow(
            self.refresh_buckets,
            (ip, node),
            self.settings.REFRESH_RATE,
            self.settings.REFRESH_BURST,
        )
        with self.lock:
            self.metrics["auth_success"] += 1
        return allowed
