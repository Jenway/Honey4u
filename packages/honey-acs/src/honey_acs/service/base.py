from __future__ import annotations

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Literal

from honey_acs.crypto.protocols import AcsRuntimeCrypto
from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.params import HBConfig

type AcsProtocol = Literal["hb", "dumbo"]
type AcsOutputMode = Literal["selected_pids", "payloads"]
type AcsEvent = dict[str, object]


@dataclass(slots=True)
class AcsRoundContext:
    protocol: AcsProtocol
    pid: int
    nodes: int
    faulty: int
    crypto: AcsRuntimeCrypto
    config: HBConfig
    output_mode: AcsOutputMode
    logger: logging.LoggerAdapter
    emit_event: Callable[[AcsEvent], None]
    emit_failure: Callable[[int, Exception], None]
    complete_round: Callable[[ManagedRoundSession], None]
    record_inbound_channel: Callable[[str, int], None]
    update_queue_peak: Callable[[str, int], None]
    track_internal_stats: bool


class ManagedRoundSession(ABC):
    def __init__(self, *, context: AcsRoundContext, round_id: int, sid: str) -> None:
        self.context = context
        self.round_id = round_id
        self.sid = sid
        self.task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self.task is not None:
            raise RuntimeError(f"round {self.round_id} was already started")
        self.task = asyncio.create_task(self._run())

    async def abort(self) -> None:
        if self.task is None or self.task.done():
            return
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass

    @abstractmethod
    async def deliver_decoded(
        self,
        *,
        sender: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool: ...

    @abstractmethod
    async def _run(self) -> None: ...


class AcsService:
    """
    Host-facing ACS facade that manages protocol-owned round sessions.
    """

    def __init__(
        self,
        *,
        protocol: AcsProtocol,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: AcsRuntimeCrypto,
        config: HBConfig | None = None,
        logger_name: str | None = None,
        event_notifier: Callable[[], None] | None = None,
        output_mode: AcsOutputMode = "selected_pids",
    ) -> None:
        self.protocol = protocol
        self.pid = pid
        self.nodes = nodes
        self.faulty = faulty
        self.crypto = crypto
        self.config = config or HBConfig()
        self.output_mode = output_mode
        self.logger = logging.LoggerAdapter(
            logging.getLogger(logger_name or self._default_logger_name(protocol)),
            extra={"node": pid},
        )
        self._events: Queue[AcsEvent] = Queue()
        self._event_notifier = event_notifier
        self._rounds_started = 0
        self._rounds_finished = 0
        self._rounds: dict[int, ManagedRoundSession] = {}
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
            "output_mode": self.output_mode,
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
        if round_id in self._rounds:
            raise ValueError(f"round {round_id} is already active")
        session = self._build_round_session(
            round_id=round_id, sid=sid, proposal_input=proposal_input
        )
        self._rounds[round_id] = session
        session.start()
        self._rounds_started += 1

    async def deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        if self._track_internal_stats:
            self._record_delivery_call(mode="single", items=1)
        session = self._rounds.get(round_id)
        if session is None:
            return False
        return await session.deliver_decoded(
            sender=sender,
            channel=channel,
            instance_id=instance_id,
            message=message,
        )

    async def deliver_batch_decoded(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int:
        if self._track_internal_stats:
            self._record_delivery_call(mode="batch", items=len(items))
        delivered = 0
        for sender, round_id, channel, instance_id, message in items:
            session = self._rounds.get(round_id)
            if session is None:
                continue
            if await session.deliver_decoded(
                sender=sender,
                channel=channel,
                instance_id=instance_id,
                message=message,
            ):
                delivered += 1
        return delivered

    async def abort_round(self, round_id: int) -> None:
        session = self._rounds.get(round_id)
        if session is None:
            return
        await session.abort()

    async def shutdown_rounds(self) -> None:
        for session in list(self._rounds.values()):
            await session.abort()

    def active_round_ids(self) -> list[int]:
        return list(self._rounds)

    def emit_event(self, event: AcsEvent) -> None:
        if self._track_internal_stats:
            kind = str(event.get("kind"))
            self._bump_counter(self._event_kind_counts, kind)
            if kind in {"send", "broadcast"}:
                self._bump_counter(self._outbound_channel_counts, str(event.get("channel")))
        self._events.put(event)
        if self._event_notifier is not None:
            self._event_notifier()

    def emit_failure(self, round_id: int, exc: Exception) -> None:
        self.emit_event(
            {
                "kind": "failure",
                "round_id": round_id,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            }
        )

    def _build_round_context(self) -> AcsRoundContext:
        return AcsRoundContext(
            protocol=self.protocol,
            pid=self.pid,
            nodes=self.nodes,
            faulty=self.faulty,
            crypto=self.crypto,
            config=self.config,
            output_mode=self.output_mode,
            logger=self.logger,
            emit_event=self.emit_event,
            emit_failure=self.emit_failure,
            complete_round=self._finish_round_session,
            record_inbound_channel=self._record_inbound_channel,
            update_queue_peak=self._update_queue_peak,
            track_internal_stats=self._track_internal_stats,
        )

    def _build_round_session(
        self,
        *,
        round_id: int,
        sid: str,
        proposal_input: bytes,
    ) -> ManagedRoundSession:
        if self.protocol == "hb":
            if self.output_mode == "payloads":
                raise ProtocolInvariantError(
                    "HB payload output mode has been removed; use selected_pids output only"
                )
            from honey_acs.service.hb import HBRoundSession

            return HBRoundSession(
                context=self._build_round_context(),
                round_id=round_id,
                sid=sid,
                proposal_input=proposal_input,
            )
        if self.protocol == "dumbo":
            from honey_acs.service.dumbo import DumboRoundSession

            return DumboRoundSession(
                context=self._build_round_context(),
                round_id=round_id,
                sid=sid,
                proposal_input=proposal_input,
            )
        raise ValueError(f"unsupported ACS protocol: {self.protocol}")

    def _finish_round_session(self, session: ManagedRoundSession) -> None:
        current = self._rounds.get(session.round_id)
        if current is session:
            self._rounds.pop(session.round_id, None)
        self._rounds_finished += 1

    def _record_delivery_call(self, *, mode: str, items: int) -> None:
        self._bump_counter(self._delivery_call_counts, mode)
        self._bump_counter(self._delivery_item_counts, mode, items)
        if items > self._max_delivery_batch:
            self._max_delivery_batch = items

    def _record_inbound_channel(self, channel: str, items: int = 1) -> None:
        self._bump_counter(self._inbound_channel_counts, channel, items)

    def _update_queue_peak(self, name: str, size: int) -> None:
        current = self._queue_peaks.get(name, 0)
        if size > current:
            self._queue_peaks[name] = size

    @staticmethod
    def _default_logger_name(protocol: AcsProtocol) -> str:
        if protocol == "hb":
            return "honey.acs.hb.service"
        return "honey.acs.dumbo.service"

    def _bump_counter(self, counter: dict[str, int], key: str, amount: int = 1) -> None:
        if not self._track_internal_stats:
            return
        counter[key] = counter.get(key, 0) + amount


def build_proposal_id(round_id: int, proposer: int, digest: bytes) -> str:
    return f"{round_id}:{proposer}:{digest.hex()}"
