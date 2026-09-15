"""Thread-safe token bucket shared by all workers calling one API."""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate: float, burst: float | None = None) -> None:
        if rate <= 0:
            raise ValueError("rate must be positive")
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._stamp = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0, stop: threading.Event | None = None) -> bool:
        """Block until `tokens` are available. Returns False if `stop` was set while waiting.

        Requests larger than the bucket capacity are allowed; they drive the balance negative so
        the average rate still holds.
        """
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._stamp) * self.rate)
                self._stamp = now
                if self._tokens >= min(tokens, self.capacity):
                    self._tokens -= tokens
                    return True
                wait = (min(tokens, self.capacity) - self._tokens) / self.rate
            if stop is not None:
                if stop.wait(wait):
                    return False
            else:
                time.sleep(wait)
