from __future__ import annotations

import asyncio
import heapq
import itertools
import random
from collections.abc import Callable
from dataclasses import dataclass, field

from honey.support.messages import ProtocolEnvelope
from network.transport import QueueTransport

FaultPredicate = Callable[[int, int, int, ProtocolEnvelope], bool]


@dataclass(order=True)
class ScheduledEnvelope:
    deliver_at: int
    sequence: int
    sender: int = field(compare=False)
    recipient: int = field(compare=False)
    envelope: ProtocolEnvelope = field(compare=False)


class DeterministicNetworkSimulator:
    def __init__(
        self,
        num_nodes: int,
        *,
        seed: int = 0,
        min_delay_steps: int = 0,
        max_delay_steps: int = 0,
        drop_predicate: FaultPredicate | None = None,
        duplicate_predicate: FaultPredicate | None = None,
    ) -> None:
        self._rng = random.Random(seed)
        self.seed = seed
        self.transports = [QueueTransport() for _ in range(num_nodes)]
        self.min_delay_steps = min_delay_steps
        self.max_delay_steps = max_delay_steps
        self.drop_predicate = drop_predicate
        self.duplicate_predicate = duplicate_predicate
        self.step_no = 0
        self._scheduled: list[ScheduledEnvelope] = []
        self._seq = itertools.count()
        self.delivery_trace: list[tuple[int, int, int, str]] = []

    def idle(self) -> bool:
        return not self._scheduled and all(t.outbound.empty() for t in self.transports)

    async def step(self) -> None:
        for sender, transport in enumerate(self.transports):
            while True:
                try:
                    outbound = transport.outbound.get_nowait()
                except asyncio.QueueEmpty:
                    break
                envelope = outbound.envelope
                recipient = outbound.recipient

                if self.drop_predicate and self.drop_predicate(
                    self.step_no, sender, recipient, envelope
                ):
                    continue

                copies = (
                    2
                    if self.duplicate_predicate
                    and self.duplicate_predicate(self.step_no, sender, recipient, envelope)
                    else 1
                )
                for _ in range(copies):
                    delay = self._rng.randint(self.min_delay_steps, self.max_delay_steps)
                    heapq.heappush(
                        self._scheduled,
                        ScheduledEnvelope(
                            deliver_at=self.step_no + delay,
                            sequence=next(self._seq),
                            sender=sender,
                            recipient=recipient,
                            envelope=envelope,
                        ),
                    )

        while self._scheduled and self._scheduled[0].deliver_at <= self.step_no:
            scheduled = heapq.heappop(self._scheduled)
            self.transports[scheduled.recipient].deliver_nowait(
                scheduled.sender, scheduled.envelope
            )
            self.delivery_trace.append(
                (
                    self.step_no,
                    scheduled.sender,
                    scheduled.recipient,
                    scheduled.envelope.channel.value,
                )
            )

        self.step_no += 1

    async def run(self, stop_event: asyncio.Event, tick_sleep: float = 0.0) -> None:
        while not stop_event.is_set():
            await self.step()
            await asyncio.sleep(tick_sleep)

    async def flush(self, max_steps: int = 1000) -> None:
        for _ in range(max_steps):
            await self.step()
            if self.idle():
                return
        raise TimeoutError("deterministic simulator did not become idle")
