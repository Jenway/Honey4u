import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from honey_shared.exceptions import ProtocolInvariantError
from honey_shared.messages import Channel, ProtocolMessage
from honey_shared.params import CommonParams, CryptoParams

from honey_acs.data.broadcast_mempool import BroadcastMempool
from honey_acs.subprotocols.binary_agreement import BAParams, binaryagreement
from honey_acs.subprotocols.common_coin import CoinParams, SharedCoin
from honey_acs.subprotocols.reliable_broadcast import BroadcastParams, reliablebroadcast

from . import bkr93_core

type HBOutboundSend = Callable[[int, Channel, int | None, ProtocolMessage], Awaitable[None]]
type CoinRecv = tuple[int, object]
type AbaRecv = tuple[int, object]
type RbcRecv = tuple[int, object]
type PointToPointOutbound = tuple[int, ProtocolMessage]


@dataclass
class CSParams(CommonParams):
    """Parameters for asynchronous common subset."""


async def commonsubset(
    params: CSParams,
    rbc_queues: list[asyncio.Queue],
    aba_input_queues: list[asyncio.Queue],
    aba_output_queues: list[asyncio.Queue],
) -> tuple[Any | None, ...]:
    """Queue-driven adapter over the BKR93 ACS core."""
    n = params.N
    state = bkr93_core.new_state(n, params.f)

    if len(rbc_queues) != n:
        raise ProtocolInvariantError(f"expected {n} RBC queues, got {len(rbc_queues)}")
    if len(aba_input_queues) != n:
        raise ProtocolInvariantError(f"expected {n} ABA input queues, got {len(aba_input_queues)}")
    if len(aba_output_queues) != n:
        raise ProtocolInvariantError(
            f"expected {n} ABA output queues, got {len(aba_output_queues)}"
        )

    def apply_effects(effects: list[bkr93_core.ProvideAbaInput]) -> None:
        for effect in effects:
            try:
                aba_input_queues[effect.index].put_nowait(effect.value)
            except asyncio.QueueFull:
                pass

    async with asyncio.TaskGroup() as task_group:

        async def recv_rbc(index: int) -> None:
            try:
                value = await rbc_queues[index].get()
                apply_effects(bkr93_core.on_rbc_delivered(state, index, value))
            except asyncio.CancelledError:
                pass

        async def recv_aba(index: int) -> None:
            outcome = await aba_output_queues[index].get()
            apply_effects(bkr93_core.on_aba_decided(state, index, outcome))

        rbc_tasks = [task_group.create_task(recv_rbc(index)) for index in range(n)]
        aba_tasks = [task_group.create_task(recv_aba(index)) for index in range(n)]

        await asyncio.gather(*aba_tasks)

        if bkr93_core.count_ones(state) < n - params.f:
            raise ProtocolInvariantError("BKR93 completed ABA without enough positive decisions")

        for index in range(n):
            if state.aba_outcomes[index] == 1:
                await rbc_tasks[index]
            else:
                rbc_tasks[index].cancel()
                state.rbc_values[index] = None

    return bkr93_core.build_output(state)


async def _forward_broadcast_queue(
    queue: asyncio.Queue[ProtocolMessage],
    *,
    channel: Channel,
    instance_id: int,
    num_nodes: int,
    send: HBOutboundSend,
) -> None:
    try:
        while True:
            message = await queue.get()
            for recipient in range(num_nodes):
                await send(recipient, channel, instance_id, message)
    except asyncio.CancelledError:
        pass


async def _forward_point_to_point_queue(
    queue: asyncio.Queue[PointToPointOutbound],
    *,
    channel: Channel,
    instance_id: int,
    send: HBOutboundSend,
) -> None:
    try:
        while True:
            recipient, message = await queue.get()
            await send(recipient, channel, instance_id, message)
    except asyncio.CancelledError:
        pass


async def run_bkr93_acs_with_send(
    *,
    params: CSParams,
    crypto: CryptoParams,
    task_group: asyncio.TaskGroup,
    spawn: Callable[[Awaitable[Any]], asyncio.Task[Any]],
    coin_recvs: list[asyncio.Queue[CoinRecv]],
    aba_recvs: list[asyncio.Queue[AbaRecv]],
    rbc_recvs: list[asyncio.Queue[RbcRecv]],
    mempool: BroadcastMempool,
    round_id: int,
    my_rbc_input: asyncio.Queue[bytes],
    output_queue: asyncio.Queue[tuple[int | bytes | None, ...]],
    logger: logging.LoggerAdapter,
    send: HBOutboundSend,
    output_mode: Literal["selected_pids", "payloads"] = "selected_pids",
) -> None:
    n = params.N
    f = params.f
    pid = params.pid
    sid = params.sid

    aba_inputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    aba_outputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    rbc_outputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    coins: list[SharedCoin] = []

    def log_fatal(location: str, exc: Exception) -> None:
        logger.error(
            f"[FATAL] Exception in {location}: {exc}",
            extra={"round": round_id},
        )

    def bridge_rbc(instance_id: int, rbc_task: asyncio.Task[str]) -> None:
        async def loop() -> None:
            try:
                payload_id = await rbc_task
                if payload_id:
                    rbc_outputs[instance_id].put_nowait(instance_id)
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                log_fatal("bridge_rbc loop", exc)
                raise

        spawn(loop())

    try:
        for j in range(n):
            coin_broadcast_queue: asyncio.Queue[ProtocolMessage] = asyncio.Queue()
            spawn(
                _forward_broadcast_queue(
                    coin_broadcast_queue,
                    channel=Channel.ACS_COIN,
                    instance_id=j,
                    num_nodes=n,
                    send=send,
                )
            )

            coin = SharedCoin(
                CoinParams(
                    sid=f"{sid}COIN{j}",
                    pid=pid,
                    N=n,
                    f=f,
                    leader=j,
                    PK=crypto.sig_pk,
                    SK=crypto.sig_sk,
                )
            )
            coins.append(coin)
            coin.start(task_group, coin_recvs[j])

            aba_send_queue: asyncio.Queue[PointToPointOutbound] = asyncio.Queue()
            spawn(
                _forward_point_to_point_queue(
                    aba_send_queue,
                    channel=Channel.ACS_ABA,
                    instance_id=j,
                    send=send,
                )
            )
            spawn(
                binaryagreement(
                    BAParams(sid=f"{sid}ABA{j}", pid=pid, N=n, f=f, leader=j),
                    coin,
                    coin_broadcast_queue,
                    aba_inputs[j],
                    aba_outputs[j],
                    aba_recvs[j],
                    aba_send_queue,
                )
            )

            rbc_send_queue: asyncio.Queue[PointToPointOutbound] = asyncio.Queue()
            spawn(
                _forward_point_to_point_queue(
                    rbc_send_queue,
                    channel=Channel.ACS_RBC,
                    instance_id=j,
                    send=send,
                )
            )
            rbc_input = my_rbc_input if j == pid else asyncio.Queue()
            rbc_task = spawn(
                reliablebroadcast(
                    BroadcastParams(sid=f"{sid}RBC{j}", pid=pid, N=n, f=f, leader=j),
                    rbc_input,
                    rbc_recvs[j],
                    rbc_send_queue,
                    mempool,
                    round_id,
                )
            )
            bridge_rbc(j, rbc_task)

        result = await commonsubset(params, rbc_outputs, aba_inputs, aba_outputs)
        if output_mode == "payloads":
            payload_result: list[bytes | None] = []
            for selected in result:
                if selected is None:
                    payload_result.append(None)
                    continue
                data = mempool.get_by_round_sender(round_id, int(selected))
                if data is None:
                    raise ProtocolInvariantError(
                        f"missing RBC payload for round={round_id} sender={selected}"
                    )
                payload_result.append(data.payload)
            output_queue.put_nowait(tuple(payload_result))
            return
        output_queue.put_nowait(result)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log_fatal("run_bkr93_acs", exc)
        raise
    finally:
        for coin in coins:
            coin.stop()
