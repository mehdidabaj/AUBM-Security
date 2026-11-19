from __future__ import annotations

import time


class RateLimiter:
    """Espace les requêtes. L'horloge est injectable pour les tests."""

    def __init__(self, interval: float = 6.5, sleep=time.sleep, clock=time.monotonic):
        self.interval = interval
        self.sleep = sleep
        self.clock = clock
        self.last: float | None = None

    def wait(self) -> None:
        now = self.clock()
        if self.last is not None:
            delay = self.interval - (now - self.last)
            if delay > 0:
                self.sleep(delay)
                now = self.clock()
        self.last = now
