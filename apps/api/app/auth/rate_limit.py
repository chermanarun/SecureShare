from collections import defaultdict, deque
from collections.abc import Hashable
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock


@dataclass
class LoginRateLimiter:
    attempts: int
    window_seconds: int

    def __post_init__(self) -> None:
        self._events: dict[Hashable, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: Hashable) -> bool:
        now = datetime.now(UTC).timestamp()
        with self._lock:
            events = self._events[key]
            self._prune(events, now)
            if len(events) >= self.attempts:
                return False
            return True

    def record_failure(self, key: Hashable) -> None:
        now = datetime.now(UTC).timestamp()
        with self._lock:
            events = self._events[key]
            self._prune(events, now)
            events.append(now)

    def clear(self, key: Hashable) -> None:
        with self._lock:
            self._events.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()

    def _prune(self, events: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
