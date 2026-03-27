import asyncio
import logging

from network.transport import InboundEnvelope, Transport


class NodeMailboxRouter:
    """Consumes the transport's global inbound stream and exposes per-round inboxes."""

    def __init__(self, transport: Transport, logger: logging.LoggerAdapter):
        self._transport = transport
        self._logger = logger
        self._round_inboxes: dict[int, asyncio.Queue[InboundEnvelope]] = {}
        self._closed_rounds: set[int] = set()
        self.peak_inbox_size = 0
        self.peak_round_inbox_sizes: dict[int, int] = {}

    def inbox(self, round_id: int) -> asyncio.Queue[InboundEnvelope]:
        if round_id not in self._round_inboxes:
            self._round_inboxes[round_id] = asyncio.Queue()
        return self._round_inboxes[round_id]

    def close_round(self, round_id: int) -> None:
        self._closed_rounds.add(round_id)
        self._round_inboxes.pop(round_id, None)

    async def run(self) -> None:
        while True:
            try:
                inbound = await self._transport.recv()
                round_id = inbound.envelope.round_id
                if round_id in self._closed_rounds:
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
