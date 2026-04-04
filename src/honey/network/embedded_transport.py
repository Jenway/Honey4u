from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Mapping
from typing import Any, cast

import honey_native

from honey.support.messages import InboundEnvelope, ProtocolEnvelope


class EmbeddedTransport:
    def __init__(
        self,
        pid: int,
        handle: Any,
        *,
        poll_seconds: float = 0.001,
        recv_batch_size: int = 64,
    ) -> None:
        self._pid = pid
        self._handle = handle
        self._poll_seconds = poll_seconds
        self._recv_batch_size = recv_batch_size
        self._recv_buffer: deque[bytes] = deque()

    async def send(self, recipient: int, envelope: ProtocolEnvelope) -> None:
        payload = envelope.to_bytes(sender=self._pid)
        await asyncio.to_thread(self._handle.send, recipient, payload)

    async def recv(self) -> InboundEnvelope:
        while True:
            if self._recv_buffer:
                sender, envelope = ProtocolEnvelope.from_bytes(self._recv_buffer.popleft())
                return InboundEnvelope(sender=sender, envelope=envelope)
            batch = await asyncio.to_thread(self._handle.recv_batch, self._recv_batch_size)
            if batch:
                self._recv_buffer.extend(batch)
                continue
            await asyncio.sleep(self._poll_seconds)

    async def close(self) -> None:
        await asyncio.to_thread(self._handle.close)

    def pending_inbound(self) -> int:
        return int(self._handle.pending_inbound()) + len(self._recv_buffer)

    def pending_outbound(self) -> int:
        return int(self._handle.pending_outbound())

    def stats(self) -> Mapping[str, int]:
        stats_fn = getattr(self._handle, "stats", None)
        if not callable(stats_fn):
            return {}
        return cast(Mapping[str, int], stats_fn())

    def wakeup_seq(self) -> int:
        wakeup_seq = getattr(self._handle, "wakeup_seq", None)
        if not callable(wakeup_seq):
            return 0
        return int(wakeup_seq())


def _embedded_transport_cls() -> Any:
    return cast(
        Any,
        honey_native.__dict__.get("EmbeddedTransportHandle")
        or honey_native.__dict__["LocalTcpTransport"],
    )


def create_embedded_transport(
    pid: int,
    addresses: list[tuple[str, int]],
    *,
    poll_seconds: float = 0.001,
    recv_batch_size: int = 64,
) -> EmbeddedTransport:
    handle = _embedded_transport_cls()(pid, addresses)
    return EmbeddedTransport(
        pid,
        handle,
        poll_seconds=poll_seconds,
        recv_batch_size=recv_batch_size,
    )
