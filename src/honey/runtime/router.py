from __future__ import annotations

import asyncio
import logging
import sys
import traceback

from honey.support.exceptions import UnknownTagError
from honey.support.messages import Channel, ProtocolEnvelope, ProtocolMessage
from network.transport import InboundEnvelope, Transport

CoinRecv = tuple[int, ProtocolMessage]
AbaRecv = tuple[int, ProtocolMessage]
RbcRecv = tuple[int, ProtocolMessage]
TpkeRecv = tuple[int, ProtocolMessage]
DumboRecv = tuple[int, object]
DumboPoolRecv = tuple[int, object]
PointToPointOutbound = tuple[int, ProtocolMessage]


class RoundProtocolRouter:
    """Round-local message demux and outbound envelope routing."""

    def __init__(
        self,
        round_id: int,
        num_nodes: int,
        transport: Transport,
        inbound_queue: asyncio.Queue[InboundEnvelope],
        coin_recvs: list[asyncio.Queue[CoinRecv]] | None,
        aba_recvs: list[asyncio.Queue[AbaRecv]] | None,
        rbc_recvs: list[asyncio.Queue[RbcRecv]] | None,
        tpke_recv: asyncio.Queue[TpkeRecv],
        logger: logging.LoggerAdapter,
        dumbo_recv: asyncio.Queue[DumboRecv] | None = None,
        dumbo_pool_recv: asyncio.Queue[DumboPoolRecv] | None = None,
    ):
        self.round_id = round_id
        self.num_nodes = num_nodes
        self.transport = transport
        self.inbound_queue = inbound_queue
        self.coin_recvs = coin_recvs
        self.aba_recvs = aba_recvs
        self.rbc_recvs = rbc_recvs
        self.tpke_recv = tpke_recv
        self.dumbo_recv = dumbo_recv
        self.dumbo_pool_recv = dumbo_pool_recv
        self.logger = logger

    def register_acs_channels(
        self,
        *,
        coin_recvs: list[asyncio.Queue[CoinRecv]],
        aba_recvs: list[asyncio.Queue[AbaRecv]],
        rbc_recvs: list[asyncio.Queue[RbcRecv]],
    ) -> None:
        self.coin_recvs = coin_recvs
        self.aba_recvs = aba_recvs
        self.rbc_recvs = rbc_recvs

    def register_dumbo_channel(self, *, dumbo_recv: asyncio.Queue[DumboRecv]) -> None:
        self.dumbo_recv = dumbo_recv

    def register_dumbo_pool_channel(
        self,
        *,
        dumbo_pool_recv: asyncio.Queue[DumboPoolRecv],
    ) -> None:
        self.dumbo_pool_recv = dumbo_pool_recv

    def _log_fatal(self, location: str, exc: Exception) -> None:
        tb_str = traceback.format_exc()
        print(
            f"[FATAL] Exception in {location}: {exc}\n{tb_str}",
            file=sys.stderr,
            flush=True,
        )
        self.logger.error(
            f"[FATAL] Exception in {location}: {exc}\n{tb_str}",
            extra={"round": self.round_id},
        )

    async def recv_dispatcher(self) -> None:
        while True:
            try:
                inbound = await self.inbound_queue.get()
                sender = inbound.sender
                envelope = inbound.envelope

                if envelope.channel == Channel.ACS_COIN:
                    if envelope.instance_id is None:
                        raise UnknownTagError("Coin envelope missing instance_id")
                    if self.coin_recvs is None:
                        raise UnknownTagError("Coin channel not registered")
                    self.coin_recvs[envelope.instance_id].put_nowait((sender, envelope.message))
                elif envelope.channel == Channel.ACS_ABA:
                    if envelope.instance_id is None:
                        raise UnknownTagError("ABA envelope missing instance_id")
                    if self.aba_recvs is None:
                        raise UnknownTagError("ABA channel not registered")
                    self.aba_recvs[envelope.instance_id].put_nowait((sender, envelope.message))
                elif envelope.channel == Channel.ACS_RBC:
                    if envelope.instance_id is None:
                        raise UnknownTagError("RBC envelope missing instance_id")
                    if self.rbc_recvs is None:
                        raise UnknownTagError("RBC channel not registered")
                    self.rbc_recvs[envelope.instance_id].put_nowait((sender, envelope.message))
                elif envelope.channel in (
                    Channel.DUMBO_PRBC,
                    Channel.DUMBO_PROOF,
                    Channel.DUMBO_MVBA,
                ):
                    if self.dumbo_recv is None:
                        raise UnknownTagError("Dumbo channel not registered")
                    self.dumbo_recv.put_nowait((sender, envelope.message))
                elif envelope.channel == Channel.DUMBO_POOL:
                    if self.dumbo_pool_recv is None:
                        raise UnknownTagError("Dumbo pool channel not registered")
                    self.dumbo_pool_recv.put_nowait((sender, envelope.message))
                elif envelope.channel == Channel.TPKE:
                    self.tpke_recv.put_nowait((sender, envelope.message))
                else:
                    raise UnknownTagError(f"Unknown tag: {envelope.channel}")
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._log_fatal("_recv_dispatcher", exc)
                raise

    async def route_broadcast_queue(
        self,
        queue: asyncio.Queue[ProtocolMessage] | asyncio.Queue[PointToPointOutbound],
        channel: Channel,
        instance_id: int | None,
        *,
        broadcast: bool,
    ) -> None:
        while True:
            try:
                msg = await queue.get()
                if broadcast:
                    for recipient in range(self.num_nodes):
                        await self.transport.send(
                            recipient,
                            ProtocolEnvelope(
                                round_id=self.round_id,
                                channel=channel,
                                instance_id=instance_id,
                                message=msg,
                            ),
                        )
                else:
                    recipient, payload = msg
                    await self.transport.send(
                        recipient,
                        ProtocolEnvelope(
                            round_id=self.round_id,
                            channel=channel,
                            instance_id=instance_id,
                            message=payload,
                        ),
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self._log_fatal("route_bcast loop", exc)
                raise
