from __future__ import annotations

import asyncio
from typing import Protocol

from honey.support.messages import InboundEnvelope, OutboundEnvelope, ProtocolEnvelope


class Transport(Protocol):
    async def send(self, recipient: int, envelope: ProtocolEnvelope) -> None: ...

    async def recv(self) -> InboundEnvelope: ...


class QueueTransport:
    def __init__(self) -> None:
        self.outbound: asyncio.Queue[OutboundEnvelope] = asyncio.Queue()
        self.inbound: asyncio.Queue[InboundEnvelope] = asyncio.Queue()

    async def send(self, recipient: int, envelope: ProtocolEnvelope) -> None:
        await self.outbound.put(OutboundEnvelope(recipient=recipient, envelope=envelope))

    async def recv(self) -> InboundEnvelope:
        return await self.inbound.get()

    def deliver_nowait(self, sender: int, envelope: ProtocolEnvelope) -> None:
        self.inbound.put_nowait(InboundEnvelope(sender=sender, envelope=envelope))
