import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from honey.data.broadcast_mempool import BroadcastMempool
from honey.runtime.router import (
    AbaRecv,
    CoinRecv,
    PointToPointOutbound,
    RbcRecv,
    RoundProtocolRouter,
)
from honey.subprotocols.binary_agreement import BAParams, binaryagreement
from honey.subprotocols.common_coin import CoinParams, SharedCoin
from honey.subprotocols.reliable_broadcast import BroadcastParams, reliablebroadcast
from honey.support.messages import Channel, ProtocolMessage
from honey.support.params import CommonParams, CryptoParams

from . import bkr93_core


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

    assert len(rbc_queues) == n
    assert len(aba_input_queues) == n
    assert len(aba_output_queues) == n

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

        assert bkr93_core.count_ones(state) >= n - params.f

        for index in range(n):
            if state.aba_outcomes[index] == 1:
                await rbc_tasks[index]
            else:
                rbc_tasks[index].cancel()
                state.rbc_values[index] = None

    return bkr93_core.build_output(state)


async def run_bkr93_acs(
    *,
    params: CSParams,
    crypto: CryptoParams,
    task_group: asyncio.TaskGroup,
    spawn: Callable[[Awaitable[Any]], asyncio.Task[Any]],
    router: RoundProtocolRouter,
    coin_recvs: list[asyncio.Queue[CoinRecv]],
    aba_recvs: list[asyncio.Queue[AbaRecv]],
    rbc_recvs: list[asyncio.Queue[RbcRecv]],
    mempool: BroadcastMempool,
    round_id: int,
    my_rbc_input: asyncio.Queue[bytes],
    output_queue: asyncio.Queue[tuple[bytes | None, ...]],
    logger: logging.LoggerAdapter,
) -> None:
    n = params.N
    f = params.f
    pid = params.pid
    sid = params.sid

    aba_inputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    aba_outputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    rbc_outputs: list[asyncio.Queue[bytes]] = [asyncio.Queue(1) for _ in range(n)]
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
                    data = getattr(mempool.get(payload_id), "payload", None)
                    if data is not None:
                        rbc_outputs[instance_id].put_nowait(data)
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
                router.route_broadcast_queue(
                    coin_broadcast_queue, Channel.ACS_COIN, j, broadcast=True
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
            spawn(router.route_broadcast_queue(aba_send_queue, Channel.ACS_ABA, j, broadcast=False))
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
            spawn(router.route_broadcast_queue(rbc_send_queue, Channel.ACS_RBC, j, broadcast=False))
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
        output_queue.put_nowait(result)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log_fatal("run_bkr93_acs", exc)
        raise
    finally:
        for coin in coins:
            coin.stop()
