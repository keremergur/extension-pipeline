"""Sliding-window token counter to stay under a provider's TPM limit.

Moved verbatim from the original script; used by the Gemini paths to proactively
throttle input tokens across parallel workers.
"""

import threading
import time


class TokenBucket:
    def __init__(self, limit: int = 800_000, window: int = 60):
        self._limit = limit
        self._window = window
        self._entries = []  # [(submit_time, token_count), ...]
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        cutoff = now - self._window
        self._entries = [(t, n) for t, n in self._entries if t > cutoff]

    def current(self) -> int:
        with self._lock:
            self._evict(time.time())
            return sum(n for _, n in self._entries)

    def add(self, tokens: int) -> None:
        with self._lock:
            self._evict(time.time())
            self._entries.append((time.time(), tokens))

    def remove(self, tokens: int) -> None:
        with self._lock:
            for i in range(len(self._entries) - 1, -1, -1):
                if self._entries[i][1] == tokens:
                    self._entries.pop(i)
                    return

    def wait_and_add(self, tokens: int) -> None:
        """Atomically wait until tokens fit, then add them in one lock acquisition."""
        while True:
            with self._lock:
                self._evict(time.time())
                total = sum(n for _, n in self._entries)
                if total + tokens <= self._limit:
                    self._entries.append((time.time(), tokens))
                    return
            print(f"  🪣  Token bucket full ({total:,}/{self._limit:,}) - waiting 10s...")
            time.sleep(10)
