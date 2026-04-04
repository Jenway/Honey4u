from __future__ import annotations

import asyncio
from collections import deque
from typing import Any, cast

import honey_native

from honey.network.transport import Transport
from honey.support.messages import InboundEnvelope, ProtocolEnvelope


class RustTransport(Transport):
    def __init__(
        self,
        *,
        pid: int,
        handle: Any,
        poll_seconds: float = 0.001,
        recv_batch_size: int = 128,
    ) -> None:
        self._pid = pid
        self._handle = handle
        self._poll_seconds = poll_seconds
        self._recv_batch_size = recv_batch_size
        self._recv_buffer: deque[tuple[int, ProtocolEnvelope]] = deque()

    async def send(self, recipient: int, envelope: ProtocolEnvelope) -> None:
        payload = honey_native.encode_protocol_envelope_py(self._pid, envelope)
        await asyncio.to_thread(self._handle.send, recipient, payload)

    async def recv(self) -> InboundEnvelope:
        while True:
            if self._recv_buffer:
                sender, envelope = self._recv_buffer.popleft()
                return InboundEnvelope(sender=sender, envelope=envelope)
            raw_batch = await asyncio.to_thread(self._handle.recv_batch, self._recv_batch_size)
            batch = [
                cast(
                    tuple[int, ProtocolEnvelope], honey_native.decode_protocol_envelope_py(payload)
                )
                for payload in raw_batch
            ]
            if batch:
                self._recv_buffer.extend(cast(list[tuple[int, ProtocolEnvelope]], batch))
                continue
            await asyncio.sleep(self._poll_seconds)

    async def close(self) -> None:
        close_fn = getattr(self._handle, "close", None)
        if callable(close_fn):
            await asyncio.to_thread(close_fn)

    def pending_inbound(self) -> int:
        pending_inbound = getattr(self._handle, "pending_inbound", None)
        if not callable(pending_inbound):
            return len(self._recv_buffer)
        value = cast(Any, pending_inbound())
        return int(value) + len(self._recv_buffer)

    def pending_outbound(self) -> int:
        pending_outbound = getattr(self._handle, "pending_outbound", None)
        if not callable(pending_outbound):
            return 0
        value = cast(Any, pending_outbound())
        return int(value)

    def stats(self) -> dict[str, int]:
        stats_fn = getattr(self._handle, "stats", None)
        if not callable(stats_fn):
            return {}
        raw = cast(dict[str, Any], stats_fn())
        return {k: int(v) for k, v in raw.items()}


def _transport_handle_cls() -> Any:
    return cast(Any, honey_native.__dict__["LocalTcpTransport"])


def create_rust_transport(
    *,
    pid: int,
    addresses: list[tuple[str, int]],
    poll_seconds: float = 0.001,
    recv_batch_size: int = 128,
) -> RustTransport:
    handle = _transport_handle_cls()(pid, addresses)
    return RustTransport(
        pid=pid,
        handle=handle,
        poll_seconds=poll_seconds,
        recv_batch_size=recv_batch_size,
    )
