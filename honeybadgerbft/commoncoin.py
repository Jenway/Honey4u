import asyncio
import hashlib
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from crypto import threshsig
from honeybadgerbft.params import CommonParams

logger = logging.getLogger(__name__)


def hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


@dataclass
class CoinParams(CommonParams):
    """Parameters for shared coin with validation"""

    PK: Any
    SK: Any

    def __post_init__(self) -> None:
        """Validate parameters after initialization"""
        super().__post_init__()
        assert self.PK.threshold == self.f + 1, (
            f"PK.threshold={self.PK.threshold} must equal f+1={self.f + 1}"
        )
        assert self.PK.players == self.N, f"PK.players={self.PK.players} must equal N={self.N}"


class CommonCoinFailureException(Exception):
    """Raised for common coin failures."""

    pass


async def shared_coin(
    params: CoinParams,
    broadcast_queue: asyncio.Queue,
    receive_queue: asyncio.Queue,
    single_bit: bool = True,
    logger: Any | None = None,
) -> Callable:
    """A shared coin based on threshold signatures

    :param CoinParams params: validated coin parameters
        (sid, pid, N, f, PK, SK)
    :param asyncio.Queue broadcast_queue: queue to put outgoing broadcast
        messages as tuples
    :param asyncio.Queue receive_queue: queue containing received messages
        as (sender_id, (tag, round, signature)) tuples
    :param bool single_bit: is the output coin a single bit or not?
    :return: an async function ``getCoin(round)`` that returns a coin value
    """
    sid = params.sid
    pid = params.pid
    N = params.N
    f = params.f
    PK = params.PK
    SK = params.SK

    received: dict = defaultdict(dict)
    outputQueue: dict = defaultdict(lambda: asyncio.Queue(1))

    def _try_output(r: Any) -> None:
        if outputQueue[r].full() or len(received[r]) < f + 1:
            return

        sigs = dict(list(received[r].items())[: f + 1])
        msg = str((sid, r)).encode()
        sig_combined = threshsig.combine_shares(PK, sigs, msg)
        coin = hash(sig_combined)[0]
        outputQueue[r].put_nowait(coin % 2 if single_bit else coin)

    async def _recv() -> None:
        """Main receive loop for coin signatures"""
        while True:
            # New shares for some round r, from sender i
            (i, (_, r, raw_sig)) = await receive_queue.get()

            assert i in range(N)
            if i in received[r]:
                logger and logger.debug(f"redundant coin sig received {(sid, pid, i, r)}")
                continue

            msg = str((sid, r)).encode()

            # TODO: Accountability: Optimistically skip verifying
            # each share, knowing evidence available later
            try:
                if i != pid:
                    assert threshsig.verify_share(PK, raw_sig, i, msg)
            except AssertionError:
                continue

            received[r][i] = raw_sig
            _try_output(r)

    # Start the receive loop as an asyncio task
    asyncio.create_task(_recv())

    async def getCoin(round: Any) -> int:
        """Gets a coin.

        :param round: the epoch/round.
        :returns: a coin value (bit or full byte).
        """
        msg = str((sid, round)).encode()
        sig = threshsig.sign(SK, msg)
        await broadcast_queue.put(("COIN", round, sig))
        received[round][pid] = sig
        _try_output(round)
        coin = await outputQueue[round].get()
        return coin

    return getCoin
