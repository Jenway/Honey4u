from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from dataclasses import dataclass
from typing import Any, cast

from honey_acs.data.broadcast_mempool import (
    BroadcastStore,
    NullBroadcastStore,
    RustEventBroadcastStore,
)
from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.hb.bkr93 import CSParams, run_bkr93_acs_with_send
from honey_acs.messages import Channel, ProtocolMessage
from honey_acs.params import CryptoParams, HBConfig
from honey_acs.service.base import AcsOutputMode, AcsService


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
        mempool: BroadcastStore | None = None,
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
            mempool=mempool,
            logger_name="honey.acs.hb.service",
            event_notifier=event_notifier,
            output_mode=output_mode,
        )
        self._rounds: dict[int, HBRoundState] = {}

    def active_round_ids(self) -> list[int]:
        return list(self._rounds)

    async def _start_round(self, *, round_id: int, sid: str, proposal_input: bytes) -> None:
        if self.output_mode == "payloads":
            raise ProtocolInvariantError(
                "HB payload output mode has been removed; use selected_pids output only"
            )
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
        output_queue: asyncio.Queue[tuple[int | bytes | None, ...]] = asyncio.Queue(1)

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

        backend = self.config.broadcast_mempool_backend

        broadcast_store: BroadcastStore
        if backend == "none":
            broadcast_store = NullBroadcastStore()
        elif backend == "rust":

            def on_broadcast_output(
                payload_id: str,
                payload: bytes,
                roothash: bytes,
                _shards: Sequence[bytes | None],
                _proofs: Sequence[bytes | None],
                round_no: int,
                sender_id: int,
                _timestamp: float,
            ) -> None:
                self.emit_event(
                    {
                        "kind": "broadcast_output",
                        "round_id": round_no,
                        "sender": sender_id,
                        "payload_id": payload_id,
                        "payload": payload,
                        "roothash": roothash,
                    }
                )

            broadcast_store = RustEventBroadcastStore(on_broadcast_output)
        else:
            raise ProtocolInvariantError(f"unsupported broadcast mempool backend: {backend}")

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
                    mempool=broadcast_store,
                    round_id=state.round_id,
                    my_rbc_input=state.my_rbc_input,
                    output_queue=output_queue,
                    logger=self.logger,
                    send=send,
                    output_mode=self.output_mode,
                )
                for task in tasks:
                    if not task.done():
                        task.cancel()

            decision = await output_queue.get()
            self.emit_event(
                {
                    "kind": "decision",
                    "round_id": state.round_id,
                    "selected_pids": [pid for pid in decision if pid is not None],
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
