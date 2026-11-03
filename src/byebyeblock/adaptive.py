from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Entry:
    preferred: str | None = None
    last_success: float = 0
    failures: dict[str, float] = field(default_factory=dict)
    successes: dict[str, int] = field(default_factory=dict)


class StrategyCache:
    """Per-destination strategy memory with cooldown for failed strategies."""

    def __init__(self, ttl: int = 1800, cooldown: int = 60):
        self.ttl = ttl
        self.cooldown = cooldown
        self.entries: dict[tuple[str, int, str], Entry] = {}

    def _entry(self, key: tuple[str, int, str]) -> Entry:
        now = time.monotonic()
        e = self.entries.get(key)
        if e is None or (e.last_success and now - e.last_success > self.ttl):
            e = Entry()
            self.entries[key] = e
        if len(self.entries) > 8192:
            oldest = sorted(self.entries, key=lambda k: self.entries[k].last_success)[:1024]
            for k in oldest:
                self.entries.pop(k, None)
        return e

    def choose(self, host: str, port: int, protocol: str, order: list[str]) -> list[str]:
        e = self._entry((host, port, protocol))
        now = time.monotonic()
        available = [s for s in order if now - e.failures.get(s, -1e9) >= self.cooldown]
        if not available:
            available = list(order)
        if e.preferred and e.preferred in available:
            available.remove(e.preferred)
            available.insert(0, e.preferred)
        else:
            available.sort(key=lambda s: (-e.successes.get(s, 0), e.failures.get(s, 0)))
        return available

    def success(self, host: str, port: int, protocol: str, strategy: str) -> None:
        e = self._entry((host, port, protocol))
        e.preferred = strategy
        e.last_success = time.monotonic()
        e.successes[strategy] = e.successes.get(strategy, 0) + 1
        e.failures.pop(strategy, None)

    def failure(self, host: str, port: int, protocol: str, strategy: str) -> None:
        e = self._entry((host, port, protocol))
        e.failures[strategy] = time.monotonic()
        if e.preferred == strategy:
            e.preferred = None

    def stats(self) -> dict:
        return {
            "entries": len(self.entries),
            "preferred": sum(1 for e in self.entries.values() if e.preferred),
        }
