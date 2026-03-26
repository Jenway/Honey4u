from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any


def _label_key(labels: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((key, str(value)) for key, value in labels.items()))


@dataclass
class MetricsRegistry:
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = field(
        default_factory=dict, init=False, repr=False
    )
    _timings: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = field(
        default_factory=dict, init=False, repr=False
    )

    def increment(self, name: str, amount: int = 1, **labels: Any) -> None:
        key = (name, _label_key(labels))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def observe(self, name: str, value: float, **labels: Any) -> None:
        key = (name, _label_key(labels))
        with self._lock:
            self._timings.setdefault(key, []).append(value)

    def timing_summary(self, name: str) -> dict[str, float | int]:
        with self._lock:
            matched = [
                values
                for (metric_name, _labels), values in self._timings.items()
                if metric_name == name
            ]

        if not matched:
            return {"count": 0, "total": 0.0, "max": 0.0}

        return {
            "count": sum(len(values) for values in matched),
            "total": sum(sum(values) for values in matched),
            "max": max(max(values) for values in matched),
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = {
                f"{name}{dict(labels) if labels else ''}": value
                for (name, labels), value in self._counters.items()
            }
            timings = {
                f"{name}{dict(labels) if labels else ''}": {
                    "count": len(values),
                    "total": sum(values),
                    "max": max(values),
                }
                for (name, labels), values in self._timings.items()
            }
        return {"counters": counters, "timings": timings}

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._timings.clear()


METRICS = MetricsRegistry()


def log_event(
    logger: logging.Logger | logging.LoggerAdapter, level: int, event: str, **fields: Any
) -> None:
    suffix = " ".join(f"{key}={fields[key]}" for key in sorted(fields))
    message = f"event={event}"
    if suffix:
        message = f"{message} {suffix}"
    logger.log(level, message)


@contextmanager
def timed_metric(name: str, **labels: Any):
    start = time.perf_counter()
    try:
        yield
    finally:
        METRICS.observe(name, time.perf_counter() - start, **labels)
