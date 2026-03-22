import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from honeybadgerbft.exceptions import AbandonedNodeError, RedundantMessageError
from honeybadgerbft.params import CommonParams

logger = logging.getLogger(__name__)


def _canonical_conf_value(values: set[int]) -> tuple[int, ...]:
    return tuple(sorted(values))


@dataclass
class BAParams(CommonParams):
    """Parameters for binary agreement with validation"""

    pass  # All common params already inherited


async def handle_conf_messages(
    sender: int,
    message: tuple,
    conf_values: dict,
    pid: int,
    bv_signal: asyncio.Event,
) -> None:
    _, r, v = message
    if v == (1, 0):
        v = (0, 1)
    assert v in ((0,), (1,), (0, 1))
    if sender in conf_values[r][v]:
        logger.warn(
            f"Redundant CONF received {message} by {sender}",
            extra={"nodeid": pid, "epoch": r},
        )
        # FIXME: Raise for now to simplify things & be consistent
        # with how other TAGs are handled. Will replace the raise
        # with a continue statement as part of
        # https://github.com/initc3/HoneyBadgerBFT-Python/issues/10
        raise RedundantMessageError(f"Redundant CONF received {message}")

    conf_values[r][v].add(sender)
    logger.debug(
        f"add v = {v} to conf_value[{r}] = {conf_values[r]}",
        extra={"nodeid": pid, "epoch": r},
    )

    bv_signal.set()


async def wait_for_conf_values(
    pid: int,
    N: int,
    f: int,
    epoch: Any,
    conf_sent: dict,
    bin_values: dict,
    values: set,
    conf_values: dict,
    bv_signal: asyncio.Event,
    broadcast: Callable[[tuple], asyncio.Future],
) -> set:
    conf_key = _canonical_conf_value(values)
    conf_sent[epoch][conf_key] = True
    logger.debug(
        f"broadcast {('CONF', epoch, conf_key)}",
        extra={"nodeid": pid, "epoch": epoch},
    )
    await broadcast(("CONF", epoch, conf_key))
    while True:
        logger.debug(
            f"looping ... conf_values[epoch] is: {conf_values[epoch]}",
            extra={"nodeid": pid, "epoch": epoch},
        )
        if 1 in bin_values[epoch] and len(conf_values[epoch][(1,)]) >= N - f:
            return set((1,))
        if 0 in bin_values[epoch] and len(conf_values[epoch][(0,)]) >= N - f:
            return set((0,))
        if (
            sum(
                len(senders)
                for conf_value, senders in conf_values[epoch].items()
                if senders and set(conf_value).issubset(bin_values[epoch])
            )
            >= N - f
        ):
            return set((0, 1))

        bv_signal.clear()
        await bv_signal.wait()


async def binaryagreement(
    params: BAParams,
    coin: Callable,
    input_queue: asyncio.Queue,
    decide_queue: asyncio.Queue,
    receive_queue: asyncio.Queue,
    send_queue: asyncio.Queue,
) -> None:
    """Binary consensus from [MMR14].

    :param BAParams params: validated consensus parameters
    :param Callable coin: async function to get a coin for round r
    :param asyncio.Queue input_queue: queue containing input value
    :param asyncio.Queue decide_queue: queue to put decided value
    :param asyncio.Queue receive_queue: queue of (sender, message) tuples
    :param asyncio.Queue send_queue: queue to put (recipient, message) tuples
    """
    # sid = params.sid
    pid = params.pid
    N = params.N
    f = params.f

    # Messages received are routed to either a shared coin, the broadcast, or AUX
    est_values: dict = defaultdict(lambda: [set(), set()])
    aux_values: dict = defaultdict(lambda: [set(), set()])
    conf_values: dict = defaultdict(lambda: {(0,): set(), (1,): set(), (0, 1): set()})
    est_sent: dict = defaultdict(lambda: [False, False])
    conf_sent: dict = defaultdict(lambda: {(0,): False, (1,): False, (0, 1): False})
    bin_values: dict = defaultdict(set)

    # This event is triggered whenever bin_values or aux_values changes
    bv_signal = asyncio.Event()

    async def broadcast(o: tuple) -> None:
        for i in range(N):
            await send_queue.put((i, o))

    async def _recv() -> None:
        while True:
            (sender, msg) = await receive_queue.get()
            logger.debug(
                f"receive {msg} from node {sender}",
                extra={"nodeid": pid, "epoch": msg[1]},
            )
            assert sender in range(N)
            if msg[0] == "EST":
                # BV_Broadcast message
                _, r, v = msg
                assert v in (0, 1)
                if sender in est_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue.
                    # print(f'Redundant EST received by {sender}', msg)
                    logger.warn(
                        f"Redundant EST message received by {sender}: {msg}",
                        extra={"nodeid": pid, "epoch": msg[1]},
                    )
                    # raise RedundantMessageError(
                    #    'Redundant EST received {}'.format(msg))
                    continue

                est_values[r][v].add(sender)
                # Relay after reaching first threshold
                if len(est_values[r][v]) >= f + 1 and not est_sent[r][v]:
                    est_sent[r][v] = True
                    await broadcast(("EST", r, v))
                    logger.debug(f"broadcast {('EST', r, v)}", extra={"nodeid": pid, "epoch": r})

                # Output after reaching second threshold
                if len(est_values[r][v]) >= 2 * f + 1:
                    logger.debug(
                        f"add v = {v} to bin_value[{r}] = {bin_values[r]}",
                        extra={"nodeid": pid, "epoch": r},
                    )
                    bin_values[r].add(v)
                    logger.debug(
                        f"bin_values[{r}] is now: {bin_values[r]}",
                        extra={"nodeid": pid, "epoch": r},
                    )
                    bv_signal.set()

            elif msg[0] == "AUX":
                # Aux message
                _, r, v = msg
                assert v in (0, 1)
                if sender in aux_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue.
                    print("Redundant AUX received", msg)
                    raise RedundantMessageError(f"Redundant AUX received {msg}")

                logger.debug(
                    f"add sender = {sender} to aux_value[{r}][{v}] = {aux_values[r][v]}",
                    extra={"nodeid": pid, "epoch": r},
                )
                aux_values[r][v].add(sender)
                logger.debug(
                    f"aux_value[{r}][{v}] is now: {aux_values[r][v]}",
                    extra={"nodeid": pid, "epoch": r},
                )

                bv_signal.set()

            elif msg[0] == "CONF":
                await handle_conf_messages(
                    sender=sender,
                    message=msg,
                    conf_values=conf_values,
                    pid=pid,
                    bv_signal=bv_signal,
                )

    # Start the receive loop as an asyncio task
    asyncio.create_task(_recv())

    # Block waiting for the input
    vi = await input_queue.get()

    assert vi in (0, 1)
    est = vi
    r = 0
    already_decided = None
    while True:  # Unbounded number of rounds
        # gevent.sleep(0)
        # print("debug", pid, sid, 'deciding', already_decided, "at epoch", r)

        logger.info(f"Starting with est = {est}", extra={"nodeid": pid, "epoch": r})

        if not est_sent[r][est]:
            est_sent[r][est] = True
            await broadcast(("EST", r, est))

        # print("debug", pid, sid, 'WAITS BIN VAL at epoch', r)

        while len(bin_values[r]) == 0:
            # Block until a value is output
            bv_signal.clear()
            await bv_signal.wait()

        # print("debug", pid, sid, 'GETS BIN VAL at epoch', r)

        w = next(iter(bin_values[r]))  # take an element
        logger.debug(f"broadcast {('AUX', r, w)}", extra={"nodeid": pid, "epoch": r})
        await broadcast(("AUX", r, w))

        logger.debug(
            f"block until at least N-f ({N - f}) AUX values are received",
            extra={"nodeid": pid, "epoch": r},
        )
        while True:
            # gevent.sleep(0)
            logger.debug(f"bin_values[{r}]: {bin_values[r]}", extra={"nodeid": pid, "epoch": r})
            logger.debug(f"aux_values[{r}]: {aux_values[r]}", extra={"nodeid": pid, "epoch": r})
            # Block until at least N-f AUX values are received
            if 1 in bin_values[r] and len(aux_values[r][1]) >= N - f:
                values = set((1,))
                # print('[sid:%s] [pid:%d] VALUES 1 %d' % (sid, pid, r))
                break
            if 0 in bin_values[r] and len(aux_values[r][0]) >= N - f:
                values = set((0,))
                # print('[sid:%s] [pid:%d] VALUES 0 %d' % (sid, pid, r))
                break
            if sum(len(aux_values[r][v]) for v in bin_values[r]) >= N - f:
                values = set((0, 1))
                # print('[sid:%s] [pid:%d] VALUES BOTH %d' % (sid, pid, r))
                break
            bv_signal.clear()
            await bv_signal.wait()

        logger.debug(
            f"Completed AUX phase with values = {values}",
            extra={"nodeid": pid, "epoch": r},
        )

        # CONF phase
        logger.debug(
            f"block until at least N-f ({N - f}) CONF values are received",
            extra={"nodeid": pid, "epoch": r},
        )
        conf_key = _canonical_conf_value(values)
        if not conf_sent[r][conf_key]:
            values = await wait_for_conf_values(
                pid=pid,
                N=N,
                f=f,
                epoch=r,
                conf_sent=conf_sent,
                bin_values=bin_values,
                values=values,
                conf_values=conf_values,
                bv_signal=bv_signal,
                broadcast=broadcast,
            )

        logger.debug(
            f"Completed CONF phase with values = {values}",
            extra={"nodeid": pid, "epoch": r},
        )

        logger.debug(
            "Block until receiving the common coin value",
            extra={"nodeid": pid, "epoch": r},
        )

        s = await coin(r)

        logger.info(f"Received coin with value = {s}", extra={"nodeid": pid, "epoch": r})

        try:
            est, already_decided = await set_new_estimate(
                values=values,
                s=s,
                already_decided=already_decided,
                decide_queue=decide_queue,
            )
        except AbandonedNodeError:
            logger.debug("QUIT!", extra={"nodeid": pid, "epoch": r})
            return

        r += 1


async def set_new_estimate(
    values: set,
    s: int,
    already_decided: int | None,
    decide_queue: asyncio.Queue,
) -> tuple[int, int | None]:
    if len(values) == 1:
        v = next(iter(values))
        if v == s:
            if already_decided is None:
                already_decided = v
                await decide_queue.put(v)
            elif already_decided == v:
                raise AbandonedNodeError
        est = v
    else:
        est = s
    return est, already_decided
