import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, cast

from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.messages import Channel, ProtocolMessage
from honey_acs.params import CommonParams, CryptoParams
from honey_acs.subprotocols.binary_agreement import BAParams, binaryagreement
from honey_acs.subprotocols.common_coin import CoinParams, SharedCoin
from honey_acs.subprotocols.provable_reliable_broadcast import (
    PrbcEcho,
    PrbcOutcome,
    PRBCParams,
    PrbcReady,
    PrbcVal,
    provable_reliable_broadcast,
)
from honey_acs.subprotocols.reliable_broadcast import BroadcastParams, RbcOutput, reliablebroadcast

type HBBroadcastMessage = ProtocolMessage | PrbcVal | PrbcEcho | PrbcReady
type HBBroadcastOutput = RbcOutput | PrbcOutcome
type HBOutboundSend = Callable[[int, Channel, int | None, HBBroadcastMessage], Awaitable[None]]
type HBBroadcastSend = Callable[[Channel, int | None, ProtocolMessage], Awaitable[None]]
type CoinRecv = tuple[int, object]
type AbaRecv = tuple[int, object]
type RbcRecv = tuple[int, object]
type BroadcastInput = bytes | str
type PointToPointOutbound = tuple[int, HBBroadcastMessage]


@dataclass
class CSParams(CommonParams):
    """Parameters for asynchronous common subset."""


@dataclass(frozen=True)
class ProvideAbaInput:
    index: int
    value: int


@dataclass
class Bkr93State:
    n: int
    f: int
    aba_input_sent: list[bool]
    aba_outcomes: list[int | None]
    rbc_values: list[Any | None]


def new_state(n: int, f: int) -> Bkr93State:
    return Bkr93State(
        n=n,
        f=f,
        aba_input_sent=[False] * n,
        aba_outcomes=[None] * n,
        rbc_values=[None] * n,
    )


def on_rbc_delivered(state: Bkr93State, index: int, value: Any) -> list[ProvideAbaInput]:
    state.rbc_values[index] = value
    return _provide_aba_input(state, index, 1)


def on_aba_decided(state: Bkr93State, index: int, value: int) -> list[ProvideAbaInput]:
    state.aba_outcomes[index] = value

    if count_ones(state) < state.n - state.f:
        return []

    effects: list[ProvideAbaInput] = []
    for k in range(state.n):
        effects.extend(_provide_aba_input(state, k, 0))
    return effects


def count_ones(state: Bkr93State) -> int:
    return sum(1 for outcome in state.aba_outcomes if outcome == 1)


def aba_complete(state: Bkr93State) -> bool:
    return all(outcome is not None for outcome in state.aba_outcomes)


def output_ready(state: Bkr93State) -> bool:
    if not aba_complete(state):
        return False
    if count_ones(state) < state.n - state.f:
        return False
    return all(
        outcome != 1 or state.rbc_values[index] is not None
        for index, outcome in enumerate(state.aba_outcomes)
    )


def build_output(state: Bkr93State) -> tuple[Any | None, ...]:
    if not output_ready(state):
        raise ProtocolInvariantError("BKR93 output is not ready")

    return tuple(
        value if outcome == 1 else None
        for value, outcome in zip(state.rbc_values, state.aba_outcomes, strict=True)
    )


def _provide_aba_input(state: Bkr93State, index: int, value: int) -> list[ProvideAbaInput]:
    if state.aba_input_sent[index]:
        return []
    state.aba_input_sent[index] = True
    return [ProvideAbaInput(index=index, value=value)]


def _make_prbc_send(
    send: HBOutboundSend, instance_id: int
) -> Callable[[int, object], Awaitable[None]]:
    async def prbc_send(recipient: int, message: object) -> None:
        await send(
            recipient,
            Channel.ACS_RBC,
            instance_id,
            cast(HBBroadcastMessage, message),
        )

    return prbc_send


def _make_prbc_broadcast_others(
    send: HBOutboundSend,
    instance_id: int,
    *,
    pid: int,
    n: int,
) -> Callable[[object], Awaitable[None]]:
    async def prbc_broadcast_others(message: object) -> None:
        for recipient in range(n):
            if recipient == pid:
                continue
            await send(
                recipient,
                Channel.ACS_RBC,
                instance_id,
                cast(HBBroadcastMessage, message),
            )

    return prbc_broadcast_others


async def commonsubset(
    params: CSParams,
    rbc_queues: list[asyncio.Queue],
    aba_input_queues: list[asyncio.Queue],
    aba_output_queues: list[asyncio.Queue],
) -> tuple[Any | None, ...]:
    """Queue-driven adapter over the BKR93 ACS core."""
    n = params.N
    state = new_state(n, params.f)

    if len(rbc_queues) != n:
        raise ProtocolInvariantError(f"expected {n} RBC queues, got {len(rbc_queues)}")
    if len(aba_input_queues) != n:
        raise ProtocolInvariantError(f"expected {n} ABA input queues, got {len(aba_input_queues)}")
    if len(aba_output_queues) != n:
        raise ProtocolInvariantError(
            f"expected {n} ABA output queues, got {len(aba_output_queues)}"
        )

    def apply_effects(effects: list[ProvideAbaInput]) -> None:
        for effect in effects:
            try:
                aba_input_queues[effect.index].put_nowait(effect.value)
            except asyncio.QueueFull:
                pass

    async with asyncio.TaskGroup() as task_group:

        async def recv_rbc(index: int) -> None:
            try:
                value = await rbc_queues[index].get()
                apply_effects(on_rbc_delivered(state, index, value))
            except asyncio.CancelledError:
                pass

        async def recv_aba(index: int) -> None:
            outcome = await aba_output_queues[index].get()
            apply_effects(on_aba_decided(state, index, outcome))

        rbc_tasks = [task_group.create_task(recv_rbc(index)) for index in range(n)]
        aba_tasks = [task_group.create_task(recv_aba(index)) for index in range(n)]

        await asyncio.gather(*aba_tasks)

        if count_ones(state) < n - params.f:
            raise ProtocolInvariantError("BKR93 completed ABA without enough positive decisions")

        for index in range(n):
            if state.aba_outcomes[index] == 1:
                await rbc_tasks[index]
            else:
                rbc_tasks[index].cancel()
                state.rbc_values[index] = None

    return build_output(state)


async def _forward_broadcast_queue(
    queue: asyncio.Queue[ProtocolMessage],
    *,
    channel: Channel,
    instance_id: int,
    broadcast: HBBroadcastSend,
) -> None:
    try:
        while True:
            message = await queue.get()
            await broadcast(channel, instance_id, message)
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
    round_id: int,
    my_rbc_input: asyncio.Queue[BroadcastInput],
    output_queue: asyncio.Queue[tuple[int | None, ...]],
    logger: logging.LoggerAdapter,
    send: HBOutboundSend,
    broadcast: HBBroadcastSend,
    broadcast_protocol: str = "rbc",
    on_broadcast_output: Callable[[HBBroadcastOutput], None] | None = None,
) -> None:
    n = params.N
    f = params.f
    pid = params.pid
    sid = params.sid
    if broadcast_protocol not in {"rbc", "prbc"}:
        raise ProtocolInvariantError(
            f"unsupported HoneyBadger broadcast protocol: {broadcast_protocol}"
        )
    if broadcast_protocol == "prbc" and (not crypto.ecdsa_pks or crypto.ecdsa_sk is None):
        raise ProtocolInvariantError("HB PRBC requires ECDSA public keys and private key")
    ecdsa_sk = cast(bytes, crypto.ecdsa_sk)

    aba_inputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    aba_outputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    rbc_outputs: list[asyncio.Queue[int]] = [asyncio.Queue(1) for _ in range(n)]
    coins: list[SharedCoin] = []

    def log_fatal(location: str, exc: Exception) -> None:
        logger.error(
            f"[FATAL] Exception in {location}: {exc}",
            extra={"round": round_id},
        )

    def bridge_rbc(instance_id: int, rbc_task: asyncio.Task[HBBroadcastOutput]) -> None:
        async def loop() -> None:
            try:
                output = await rbc_task
                if on_broadcast_output is not None:
                    on_broadcast_output(output)
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
                    broadcast=broadcast,
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
                binaryagreement(
                    BAParams(sid=f"{sid}ABA{j}", pid=pid, N=n, f=f, leader=j),
                    coin,
                    coin_broadcast_queue,
                    aba_inputs[j],
                    aba_outputs[j],
                    aba_recvs[j],
                    aba_send_queue,
                    broadcast=lambda message, instance_id=j: broadcast(
                        Channel.ACS_ABA, instance_id, message
                    ),
                )
            )

            rbc_input: asyncio.Queue[BroadcastInput] = my_rbc_input if j == pid else asyncio.Queue()
            if broadcast_protocol == "prbc":
                prbc_send = _make_prbc_send(send, j)
                prbc_broadcast_others = _make_prbc_broadcast_others(send, j, pid=pid, n=n)

                rbc_task = spawn(
                    provable_reliable_broadcast(
                        PRBCParams(
                            sid=f"{sid}RBC{j}",
                            pid=pid,
                            N=n,
                            f=f,
                            leader=j,
                            ecdsa_pks=crypto.ecdsa_pks,
                            ecdsa_sk=ecdsa_sk,
                        ),
                        rbc_input,
                        rbc_recvs[j],
                        prbc_send,
                        broadcast_others=prbc_broadcast_others,
                    )
                )
            else:
                rbc_send_queue: asyncio.Queue[PointToPointOutbound] = asyncio.Queue()
                spawn(
                    _forward_point_to_point_queue(
                        rbc_send_queue,
                        channel=Channel.ACS_RBC,
                        instance_id=j,
                        send=send,
                    )
                )
                rbc_task = spawn(
                    reliablebroadcast(
                        BroadcastParams(sid=f"{sid}RBC{j}", pid=pid, N=n, f=f, leader=j),
                        rbc_input,
                        rbc_recvs[j],
                        rbc_send_queue,
                        broadcast=lambda message, instance_id=j: broadcast(
                            Channel.ACS_RBC, instance_id, message
                        ),
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
