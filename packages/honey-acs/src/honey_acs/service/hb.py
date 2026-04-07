from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Coroutine
from dataclasses import dataclass
from typing import Any, Callable, cast

from honey_shared.exceptions import ProtocolInvariantError
from honey_shared.messages import Channel, ProtocolMessage
from honey_shared.params import CryptoParams, HBConfig

from honey_acs.data.broadcast_mempool import BroadcastMempool
from honey_acs.hb.bkr93 import CSParams, run_bkr93_acs_with_send
from honey_acs.service.base import AcsService


@dataclass(slots=True)
class HBRoundState:
    round_id: int
    sid: str
    coin_recvs: list[asyncio.Queue[tuple[int, object]]]
    aba_recvs: list[asyncio.Queue[tuple[int, object]]]
    rbc_recvs: list[asyncio.Queue[tuple[int, object]]]
    my_rbc_input: asyncio.Queue[bytes]
    task: asyncio.Task[None] | None = None


class HoneyBadgerAcsService(AcsService):
    def __init__(
        self,
        *,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: CryptoParams,
        config: HBConfig | None = None,
        mempool: BroadcastMempool | None = None,
        event_notifier: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(
            protocol="hb",
            pid=pid,
            nodes=nodes,
            faulty=faulty,
            crypto=crypto,
            config=config,
            mempool=mempool,
            logger_name="honey.acs.hb.service",
            event_notifier=event_notifier,
        )
        self._rounds: dict[int, HBRoundState] = {}

    def active_round_ids(self) -> list[int]:
        return list(self._rounds)

    async def _start_round(self, *, round_id: int, sid: str, proposal_input: bytes) -> None:
        if round_id in self._rounds:
            raise ValueError(f"round {round_id} is already active")
        state = HBRoundState(
            round_id=round_id,
            sid=sid,
            coin_recvs=[asyncio.Queue() for _ in range(self.nodes)],
            aba_recvs=[asyncio.Queue() for _ in range(self.nodes)],
            rbc_recvs=[asyncio.Queue() for _ in range(self.nodes)],
            my_rbc_input=asyncio.Queue(1),
        )
        state.my_rbc_input.put_nowait(proposal_input)
        state.task = asyncio.create_task(self._run_round(state))
        self._rounds[round_id] = state

    async def deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        track_stats = self._track_internal_stats
        if track_stats:
            self._record_delivery_call(mode="single", items=1)
        state = self._rounds.get(round_id)
        if state is None:
            return False

        channel_tag = Channel(channel)
        if channel_tag == Channel.ACS_COIN:
            if instance_id is None or not 0 <= instance_id < self.nodes:
                raise ProtocolInvariantError("HB coin envelope missing valid instance_id")
            state.coin_recvs[instance_id].put_nowait((sender, message))
            if track_stats:
                self._record_inbound_channel(channel_tag.value)
                self._update_queue_peak("coin", state.coin_recvs[instance_id].qsize())
            return True
        if channel_tag == Channel.ACS_ABA:
            if instance_id is None or not 0 <= instance_id < self.nodes:
                raise ProtocolInvariantError("HB ABA envelope missing valid instance_id")
            state.aba_recvs[instance_id].put_nowait((sender, message))
            if track_stats:
                self._record_inbound_channel(channel_tag.value)
                self._update_queue_peak("aba", state.aba_recvs[instance_id].qsize())
            return True
        if channel_tag == Channel.ACS_RBC:
            if instance_id is None or not 0 <= instance_id < self.nodes:
                raise ProtocolInvariantError("HB RBC envelope missing valid instance_id")
            state.rbc_recvs[instance_id].put_nowait((sender, message))
            if track_stats:
                self._record_inbound_channel(channel_tag.value)
                self._update_queue_peak("rbc", state.rbc_recvs[instance_id].qsize())
            return True
        return False

    async def deliver_batch_decoded(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int:
        track_stats = self._track_internal_stats
        if track_stats:
            self._record_delivery_call(mode="batch", items=len(items))
        delivered = 0
        for sender, round_id, channel, instance_id, message in items:
            state = self._rounds.get(round_id)
            if state is None:
                continue

            channel_tag = Channel(channel)
            if channel_tag == Channel.ACS_COIN:
                if instance_id is None or not 0 <= instance_id < self.nodes:
                    raise ProtocolInvariantError("HB coin envelope missing valid instance_id")
                state.coin_recvs[instance_id].put_nowait((sender, message))
                if track_stats:
                    self._update_queue_peak("coin", state.coin_recvs[instance_id].qsize())
                    self._record_inbound_channel(channel_tag.value)
                delivered += 1
                continue
            if channel_tag == Channel.ACS_ABA:
                if instance_id is None or not 0 <= instance_id < self.nodes:
                    raise ProtocolInvariantError("HB ABA envelope missing valid instance_id")
                state.aba_recvs[instance_id].put_nowait((sender, message))
                if track_stats:
                    self._update_queue_peak("aba", state.aba_recvs[instance_id].qsize())
                    self._record_inbound_channel(channel_tag.value)
                delivered += 1
                continue
            if channel_tag == Channel.ACS_RBC:
                if instance_id is None or not 0 <= instance_id < self.nodes:
                    raise ProtocolInvariantError("HB RBC envelope missing valid instance_id")
                state.rbc_recvs[instance_id].put_nowait((sender, message))
                if track_stats:
                    self._update_queue_peak("rbc", state.rbc_recvs[instance_id].qsize())
                    self._record_inbound_channel(channel_tag.value)
                delivered += 1
        return delivered

    async def abort_round(self, round_id: int) -> None:
        state = self._rounds.pop(round_id, None)
        if state is None:
            return
        if state.task is not None and not state.task.done():
            state.task.cancel()
            try:
                await state.task
            except asyncio.CancelledError:
                pass

    async def shutdown_rounds(self) -> None:
        for round_id in list(self._rounds):
            await self.abort_round(round_id)

    async def _run_round(self, state: HBRoundState) -> None:
        tasks: list[asyncio.Task[Any]] = []
        output_queue: asyncio.Queue[tuple[int | None, ...]] = asyncio.Queue(1)

        async def send(
            recipient: int,
            channel: Channel,
            instance_id: int | None,
            message: ProtocolMessage,
        ) -> None:
            self.emit_event(
                {
                    "kind": "send",
                    "round_id": state.round_id,
                    "recipient": recipient,
                    "channel": channel.value,
                    "instance_id": instance_id,
                    "message": message,
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
                        sid=f"{state.sid}CS",
                        pid=self.pid,
                        N=self.nodes,
                        f=self.faulty,
                        leader=self.pid,
                    ),
                    crypto=self.crypto,
                    task_group=task_group,
                    spawn=spawn,
                    coin_recvs=state.coin_recvs,
                    aba_recvs=state.aba_recvs,
                    rbc_recvs=state.rbc_recvs,
                    mempool=self.mempool,
                    round_id=state.round_id,
                    my_rbc_input=state.my_rbc_input,
                    output_queue=output_queue,
                    logger=self.logger,
                    send=send,
                )
                for task in tasks:
                    if not task.done():
                        task.cancel()

            self.emit_event(
                {
                    "kind": "decision",
                    "round_id": state.round_id,
                    "selected_pids": [
                        pid for pid in await output_queue.get() if pid is not None
                    ],
                }
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.exception("HB ACS round failed", extra={"round": state.round_id})
            self.emit_failure(round_id=state.round_id, exc=exc)
        finally:
            self._rounds.pop(state.round_id, None)
            self.finish_round(state.round_id)
