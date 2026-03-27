import asyncio
import logging
from collections.abc import Mapping

from honey.network.transport import InboundEnvelope, Transport


class NodeMailboxRouter:
    """Consumes the transport's global inbound stream and exposes per-round inboxes."""

    def __init__(self, transport: Transport, logger: logging.LoggerAdapter):
        self._transport = transport
        self._logger = logger
        self._round_inboxes: dict[int, asyncio.Queue[InboundEnvelope]] = {}
        self._closed_through = -1
        self.peak_inbox_size = 0
        self.peak_round_inbox_sizes: dict[int, int] = {}

    def inbox(self, round_id: int) -> asyncio.Queue[InboundEnvelope]:
        if round_id <= self._closed_through:
            raise ValueError(f"round {round_id} is already closed")
        if round_id not in self._round_inboxes:
            self._round_inboxes[round_id] = asyncio.Queue()
        return self._round_inboxes[round_id]

    def close_round(self, round_id: int) -> None:
        self._closed_through = max(self._closed_through, round_id)
        self._round_inboxes = {
            active_round: queue
            for active_round, queue in self._round_inboxes.items()
            if active_round > self._closed_through
        }
        self.peak_round_inbox_sizes = {
            active_round: peak
            for active_round, peak in self.peak_round_inbox_sizes.items()
            if active_round > self._closed_through
        }

    def stats(self) -> Mapping[str, int | dict[int, int]]:
        return {
            "active_rounds": len(self._round_inboxes),
            "closed_through": self._closed_through,
            "peak_inbox_size": self.peak_inbox_size,
            "peak_round_inbox_sizes": dict(self.peak_round_inbox_sizes),
        }

    async def run(self) -> None:
        while True:
            try:
                inbound = await self._transport.recv()
                round_id = inbound.envelope.round_id
                if round_id <= self._closed_through:
                    continue
                queue = self.inbox(round_id)
                queue.put_nowait(inbound)
                size = queue.qsize()
                if size > self.peak_inbox_size:
                    self.peak_inbox_size = size
                previous_peak = self.peak_round_inbox_sizes.get(round_id, 0)
                if size > previous_peak:
                    self.peak_round_inbox_sizes[round_id] = size
            except asyncio.CancelledError:
                break
            except Exception:
                self._logger.exception("Mailbox router failed")
                raise
