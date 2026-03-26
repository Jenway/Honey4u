import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from honey.subprotocols.common_coin import SharedCoin
from honey.support.messages import BaAux, BaConf, BaEst
from honey.support.params import CommonParams
from honey.support.telemetry import METRICS


def _canonical_conf_value(values: set[int]) -> tuple[int, ...]:
    return tuple(sorted(values))


@dataclass
class BAParams(CommonParams):
    """Parameters for binary agreement with validation"""

    pass


async def binaryagreement(
    params: BAParams,
    coin: SharedCoin,
    coin_send_queue: asyncio.Queue,
    input_queue: asyncio.Queue,
    decide_queue: asyncio.Queue,
    receive_queue: asyncio.Queue,
    send_queue: asyncio.Queue,
) -> None:
    pid = params.pid
    N = params.N
    f = params.f

    logger_adapter = logging.LoggerAdapter(logging.getLogger(__name__), extra={"node": pid})

    est_values: dict[int, dict[int, set[int]]] = defaultdict(lambda: {0: set(), 1: set()})
    aux_values: dict[int, dict[int, set[int]]] = defaultdict(lambda: {0: set(), 1: set()})
    conf_values: dict[int, dict[tuple, set[int]]] = defaultdict(
        lambda: {(0,): set(), (1,): set(), (0, 1): set()}
    )

    est_sent: dict[int, dict[int, bool]] = defaultdict(lambda: {0: False, 1: False})
    conf_sent: dict[int, dict[tuple, bool]] = defaultdict(
        lambda: {(0,): False, (1,): False, (0, 1): False}
    )

    bin_values: dict[int, set[int]] = defaultdict(set)

    state_changed = asyncio.Event()

    async def broadcast(msg: tuple) -> None:
        """Point-to-point simulate broadcast to everyone including self."""
        for i in range(N):
            await send_queue.put((i, msg))

    async def wait_for_condition(cond_func: Callable[[], bool]) -> None:
        while True:
            if cond_func():
                return
            state_changed.clear()
            # 必须在 clear 之后再次检查，防止状态在我们 clear 期间被其他协程更新！
            if cond_func():
                return
            await state_changed.wait()

    async def recv_loop() -> None:
        try:
            while True:
                sender, msg = await receive_queue.get()
                if isinstance(msg, BaEst):
                    r = msg.epoch
                    v = msg.value
                    if sender not in est_values[r][v]:
                        est_values[r][v].add(sender)
                    if len(est_values[r][v]) >= 2 * f + 1 and v not in bin_values[r]:
                        bin_values[r].add(v)
                elif isinstance(msg, BaAux):
                    r = msg.epoch
                    v = msg.value
                    if sender not in aux_values[r][v]:
                        aux_values[r][v].add(sender)
                elif isinstance(msg, BaConf):
                    r = msg.epoch
                    v = msg.values
                    if sender not in conf_values[r][v]:
                        conf_values[r][v].add(sender)
                else:
                    continue

                # 无论发生什么，唤醒所有正在 wait_for_condition 的协程
                state_changed.set()
        except asyncio.CancelledError:
            pass

    async def est_phase(r: int, est: int) -> None:
        if not est_sent[r][est]:
            est_sent[r][est] = True
            await broadcast(BaEst(epoch=r, value=est))

        await wait_for_condition(lambda: bool(bin_values[r]))

    async def aux_phase(r: int) -> set[int]:
        w = next(iter(bin_values[r]))
        await broadcast(BaAux(epoch=r, value=w))

        def aux_condition() -> bool:
            if 1 in bin_values[r] and len(aux_values[r][1]) >= N - f:
                return True
            if 0 in bin_values[r] and len(aux_values[r][0]) >= N - f:
                return True
            if sum(len(aux_values[r][v]) for v in bin_values[r]) >= N - f:
                return True
            return False

        await wait_for_condition(aux_condition)

        if 1 in bin_values[r] and len(aux_values[r][1]) >= N - f:
            return {1}
        if 0 in bin_values[r] and len(aux_values[r][0]) >= N - f:
            return {0}
        return {0, 1}

    async def conf_phase(r: int, values: set[int]) -> set[int]:
        conf_key = _canonical_conf_value(values)
        if not conf_sent[r][conf_key]:
            conf_sent[r][conf_key] = True
            await broadcast(BaConf(epoch=r, values=conf_key))

        def conf_condition() -> bool:
            if 1 in bin_values[r] and len(conf_values[r][(1,)]) >= N - f:
                return True
            if 0 in bin_values[r] and len(conf_values[r][(0,)]) >= N - f:
                return True
            subset_senders = sum(
                len(senders)
                for val, senders in conf_values[r].items()
                if set(val).issubset(bin_values[r])
            )
            return subset_senders >= N - f

        await wait_for_condition(conf_condition)

        if 1 in bin_values[r] and len(conf_values[r][(1,)]) >= N - f:
            return {1}
        if 0 in bin_values[r] and len(conf_values[r][(0,)]) >= N - f:
            return {0}
        return {0, 1}

    # ─────────────────────────────────────────────────────────────────────────────
    # Main BA Loop
    # ─────────────────────────────────────────────────────────────────────────────
    vi = await input_queue.get()
    est = vi
    already_decided = None
    r = 0

    async with asyncio.TaskGroup() as tg:
        recv_task = tg.create_task(recv_loop())
        try:
            while True:
                await est_phase(r, est)
                values = await aux_phase(r)
                values = await conf_phase(r, values)

                s = await coin.get_coin(r, coin_send_queue)

                if len(values) == 1:
                    v = next(iter(values))
                    if v == s:
                        if already_decided is None:
                            already_decided = v
                            await decide_queue.put(v)
                            METRICS.increment("ba.decision", node=pid, value=v)
                            logger_adapter.info(f"Decision reached: {v} at round {r}")
                        elif already_decided == v:
                            return
                    est = v
                else:
                    est = s

                old_r = r - 2
                if old_r >= 0:
                    est_values.pop(old_r, None)
                    aux_values.pop(old_r, None)
                    conf_values.pop(old_r, None)
                    est_sent.pop(old_r, None)
                    conf_sent.pop(old_r, None)
                    bin_values.pop(old_r, None)

                r += 1
        finally:
            recv_task.cancel()
