from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from queue import Empty, Queue
from typing import Literal

from honey_shared.params import CryptoParams, HBConfig

from honey_acs.data.broadcast_mempool import BroadcastMempool

type AcsProtocol = Literal["hb", "dumbo"]
type AcsEvent = dict[str, object]


class AcsService(ABC):
    """Async ACS round service without runtime-owned worker state."""

    def __init__(
        self,
        *,
        protocol: AcsProtocol,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: CryptoParams,
        config: HBConfig | None = None,
        mempool: BroadcastMempool | None = None,
        logger_name: str,
        event_notifier: Callable[[], None] | None = None,
    ) -> None:
        self.protocol = protocol
        self.pid = pid
        self.nodes = nodes
        self.faulty = faulty
        self.crypto = crypto
        self.config = config or HBConfig()
        self.mempool = mempool or BroadcastMempool(
            max_size=1000,
            expire_rounds=self.config.pool_expire_rounds,
        )
        self.logger = logging.LoggerAdapter(logging.getLogger(logger_name), extra={"node": pid})
        self._events: Queue[AcsEvent] = Queue()
        self._event_notifier = event_notifier
        self._rounds_started = 0
        self._rounds_finished = 0
        self._track_internal_stats = os.environ.get("HONEY_PROFILE_ACS_INTERNAL") is not None
        self._event_kind_counts: dict[str, int] = {}
        self._outbound_channel_counts: dict[str, int] = {}
        self._inbound_channel_counts: dict[str, int] = {}
        self._delivery_call_counts: dict[str, int] = {"single": 0, "batch": 0}
        self._delivery_item_counts: dict[str, int] = {"single": 0, "batch": 0}
        self._max_delivery_batch = 0
        self._queue_peaks: dict[str, int] = {}

    def drain_events(self, limit: int = 128) -> list[AcsEvent]:
        drained: list[AcsEvent] = []
        while len(drained) < limit:
            try:
                drained.append(self._events.get_nowait())
            except Empty:
                break
        return drained

    def event_backlog(self) -> int:
        return self._events.qsize()

    def stats(self) -> dict[str, object]:
        stats = {
            "protocol": self.protocol,
            "pid": self.pid,
            "nodes": self.nodes,
            "faulty": self.faulty,
            "active_rounds": sorted(self.active_round_ids()),
            "rounds_started": self._rounds_started,
            "rounds_finished": self._rounds_finished,
            "event_backlog": self._events.qsize(),
        }
        if self._track_internal_stats:
            stats.update(
                {
                    "event_kind_counts": dict(self._event_kind_counts),
                    "outbound_channel_counts": dict(self._outbound_channel_counts),
                    "inbound_channel_counts": dict(self._inbound_channel_counts),
                    "delivery_call_counts": dict(self._delivery_call_counts),
                    "delivery_item_counts": dict(self._delivery_item_counts),
                    "max_delivery_batch": self._max_delivery_batch,
                    "queue_peaks": dict(self._queue_peaks),
                }
            )
        return stats

    async def start_round(self, *, round_id: int, sid: str, proposal_input: bytes) -> None:
        await self._start_round(round_id=round_id, sid=sid, proposal_input=proposal_input)
        self._rounds_started += 1

    @abstractmethod
    async def _start_round(
        self,
        *,
        round_id: int,
        sid: str,
        proposal_input: bytes,
    ) -> None: ...

    @abstractmethod
    async def deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool: ...

    async def deliver_batch_decoded(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int:
        delivered = 0
        for sender, round_id, channel, instance_id, message in items:
            if await self.deliver_decoded(
                sender=sender,
                round_id=round_id,
                channel=channel,
                instance_id=instance_id,
                message=message,
            ):
                delivered += 1
        return delivered

    @abstractmethod
    async def abort_round(self, round_id: int) -> None: ...

    @abstractmethod
    async def shutdown_rounds(self) -> None: ...

    @abstractmethod
    def active_round_ids(self) -> list[int]: ...

    def emit_event(self, event: AcsEvent) -> None:
        if self._track_internal_stats:
            kind = str(event.get("kind"))
            self._bump_counter(self._event_kind_counts, kind)
            if kind == "send":
                self._bump_counter(self._outbound_channel_counts, str(event.get("channel")))
        self._events.put(event)
        if self._event_notifier is not None:
            self._event_notifier()

    def emit_failure(self, *, round_id: int, exc: Exception) -> None:
        self.emit_event(
            {
                "kind": "failure",
                "round_id": round_id,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            }
        )

    def finish_round(self, round_id: int) -> None:
        self._rounds_finished += 1

    def _record_delivery_call(self, *, mode: str, items: int) -> None:
        if not self._track_internal_stats:
            return
        self._bump_counter(self._delivery_call_counts, mode)
        self._bump_counter(self._delivery_item_counts, mode, items)
        if items > self._max_delivery_batch:
            self._max_delivery_batch = items

    def _record_inbound_channel(self, channel: str, items: int = 1) -> None:
        if not self._track_internal_stats:
            return
        self._bump_counter(self._inbound_channel_counts, channel, items)

    def _update_queue_peak(self, name: str, size: int) -> None:
        if not self._track_internal_stats:
            return
        current = self._queue_peaks.get(name, 0)
        if size > current:
            self._queue_peaks[name] = size

    @staticmethod
    def _bump_counter(counter: dict[str, int], key: str, amount: int = 1) -> None:
        counter[key] = counter.get(key, 0) + amount
