from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, cast

from honey_acs.crypto.protocols import AcsRuntimeCrypto
from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.hb.bkr93 import CSParams, run_bkr93_acs_with_send
from honey_acs.messages import Channel
from honey_acs.params import HBConfig
from honey_acs.service.base import (
    AcsOutputMode,
    AcsRoundContext,
    AcsService,
    ManagedRoundSession,
    build_proposal_id,
)
from honey_acs.subprotocols.provable_reliable_broadcast import PrbcOutcome, serialize_prbc_proof
from honey_acs.subprotocols.reliable_broadcast import RbcOutput


class HBRoundSession(ManagedRoundSession):
    def __init__(
        self,
        *,
        context: AcsRoundContext,
        round_id: int,
        sid: str,
        proposal_input: bytes,
    ) -> None:
        super().__init__(context=context, round_id=round_id, sid=sid)
        self.coin_recvs = [asyncio.Queue() for _ in range(context.nodes)]
        self.aba_recvs = [asyncio.Queue() for _ in range(context.nodes)]
        self.rbc_recvs = [asyncio.Queue() for _ in range(context.nodes)]
        self.my_rbc_input: asyncio.Queue[bytes | str] = asyncio.Queue(1)
        self.my_rbc_input.put_nowait(proposal_input)
        self._proposal_ids: dict[int, str] = {}

    async def deliver_decoded(
        self,
        *,
        sender: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        channel_tag = Channel(channel)
        if channel_tag == Channel.ACS_COIN:
            if instance_id is None or not 0 <= instance_id < self.context.nodes:
                raise ProtocolInvariantError("HB coin envelope missing valid instance_id")
            self.coin_recvs[instance_id].put_nowait((sender, message))
            self.context.record_inbound_channel(channel_tag.value, 1)
            self.context.update_queue_peak("coin", self.coin_recvs[instance_id].qsize())
            return True
        if channel_tag == Channel.ACS_ABA:
            if instance_id is None or not 0 <= instance_id < self.context.nodes:
                raise ProtocolInvariantError("HB ABA envelope missing valid instance_id")
            self.aba_recvs[instance_id].put_nowait((sender, message))
            self.context.record_inbound_channel(channel_tag.value, 1)
            self.context.update_queue_peak("aba", self.aba_recvs[instance_id].qsize())
            return True
        if channel_tag == Channel.ACS_RBC:
            if instance_id is None or not 0 <= instance_id < self.context.nodes:
                raise ProtocolInvariantError("HB RBC envelope missing valid instance_id")
            self.rbc_recvs[instance_id].put_nowait((sender, message))
            self.context.record_inbound_channel(channel_tag.value, 1)
            self.context.update_queue_peak("rbc", self.rbc_recvs[instance_id].qsize())
            return True
        return False

    async def _run(self) -> None:
        tasks: list[asyncio.Task[Any]] = []
        output_queue: asyncio.Queue[tuple[int | None, ...]] = asyncio.Queue(1)

        async def send(
            recipient: int,
            channel: Channel,
            instance_id: int | None,
            message: object,
        ) -> None:
            self.context.emit_event(
                {
                    "kind": "send",
                    "round_id": self.round_id,
                    "recipient": recipient,
                    "channel": channel.value,
                    "instance_id": instance_id,
                    "message": message,
                }
            )

        async def broadcast(
            channel: Channel,
            instance_id: int | None,
            message: object,
        ) -> None:
            self.context.emit_event(
                {
                    "kind": "broadcast",
                    "round_id": self.round_id,
                    "channel": channel.value,
                    "instance_id": instance_id,
                    "include_self": True,
                    "message": message,
                }
            )

        backend = self.context.config.broadcast_mempool_backend
        if backend not in {"none", "rust"}:
            raise ProtocolInvariantError(f"unsupported broadcast mempool backend: {backend}")

        def on_broadcast_output(output: RbcOutput | PrbcOutcome) -> None:
            if isinstance(output, RbcOutput):
                leader = output.leader
                payload = output.payload
                digest = output.roothash
                certificate = output.roothash
            else:
                leader = output.leader
                payload = output.value
                digest = output.proof.roothash
                certificate = serialize_prbc_proof(output.proof)

            proposal_id = build_proposal_id(self.round_id, leader, digest)
            self._proposal_ids[leader] = proposal_id
            self.context.emit_event(
                {
                    "kind": "proposal_ready",
                    "round_id": self.round_id,
                    "proposer": leader,
                    "proposal_id": proposal_id,
                    "payload": payload,
                    "digest": digest,
                    "certificate": certificate,
                }
            )

        try:
            async with asyncio.TaskGroup() as task_group:

                def spawn(coro: Awaitable[Any]) -> asyncio.Task[Any]:
                    task = task_group.create_task(cast(Coroutine[Any, Any, Any], coro))
                    tasks.append(task)
                    return task

                await run_bkr93_acs_with_send(
                    params=CSParams(
                        sid=f"{self.sid}CS",
                        pid=self.context.pid,
                        N=self.context.nodes,
                        f=self.context.faulty,
                        leader=self.context.pid,
                    ),
                    crypto=self.context.crypto,
                    task_group=task_group,
                    spawn=spawn,
                    coin_recvs=self.coin_recvs,
                    aba_recvs=self.aba_recvs,
                    rbc_recvs=self.rbc_recvs,
                    round_id=self.round_id,
                    my_rbc_input=self.my_rbc_input,
                    output_queue=output_queue,
                    logger=self.context.logger,
                    send=send,
                    broadcast=broadcast,
                    broadcast_protocol=self.context.config.hb_broadcast_protocol,
                    on_broadcast_output=on_broadcast_output,
                )
                for task in tasks:
                    if not task.done():
                        task.cancel()

            decision = await output_queue.get()
            selected_proposal_ids = []
            for pid in decision:
                if pid is None:
                    continue
                proposal_id = self._proposal_ids.get(pid)
                if proposal_id is None:
                    raise ProtocolInvariantError(
                        f"HB ACS decided proposer {pid} before proposal_ready was emitted"
                    )
                selected_proposal_ids.append(proposal_id)
            self.context.emit_event(
                {
                    "kind": "decision",
                    "round_id": self.round_id,
                    "selected_proposal_ids": selected_proposal_ids,
                }
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.context.logger.exception("HB ACS round failed", extra={"round": self.round_id})
            self.context.emit_failure(self.round_id, exc)
        finally:
            self.context.complete_round(self)


class HoneyBadgerAcsService(AcsService):
    def __init__(
        self,
        *,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: AcsRuntimeCrypto,
        config: HBConfig | None = None,
        event_notifier: Callable[[], None] | None = None,
        output_mode: AcsOutputMode = "selected_pids",
    ) -> None:
        super().__init__(
            protocol="hb",
            pid=pid,
            nodes=nodes,
            faulty=faulty,
            crypto=crypto,
            config=config,
            event_notifier=event_notifier,
            output_mode=output_mode,
        )
