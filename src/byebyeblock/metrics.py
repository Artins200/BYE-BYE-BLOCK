from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Metrics:
    started_at: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    connections: int = 0
    active: int = 0
    successes: int = 0
    failures: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    strategies: Counter = field(default_factory=Counter)
    failures_by_reason: Counter = field(default_factory=Counter)
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    redact_domains: bool = True

    def event(self, kind: str, host: str = "", strategy: str = "", reason: str = "", **extra: Any) -> None:
        with self.lock:
            if host and self.redact_domains:
                host = "h:" + hashlib.sha256(host.encode()).hexdigest()[:12]
            item = {"ts": round(time.time(), 3), "kind": kind, "host": host, "strategy": strategy, "reason": reason}
            item.update(extra)
            self.events.append(item)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "connections": self.connections,
                "active": self.active,
                "successes": self.successes,
                "failures": self.failures,
                "bytes_up": self.bytes_up,
                "bytes_down": self.bytes_down,
                "strategies": dict(self.strategies),
                "failures_by_reason": dict(self.failures_by_reason),
                "events": list(self.events),
                "redact_domains": self.redact_domains,
            }

    def begin(self) -> None:
        with self.lock:
            self.connections += 1
            self.active += 1

    def end(self, success: bool, strategy: str = "", reason: str = "", up: int = 0, down: int = 0) -> None:
        with self.lock:
            self.active = max(0, self.active - 1)
            self.bytes_up += up
            self.bytes_down += down
            if success:
                self.successes += 1
                if strategy:
                    self.strategies[strategy] += 1
            else:
                self.failures += 1
                self.failures_by_reason[reason or "unknown"] += 1
