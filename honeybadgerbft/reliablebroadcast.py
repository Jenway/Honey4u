import asyncio
import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from crypto.erasure import decode, encode
from crypto.merkle import getMerkleBranch, merkleTree, merkleVerify
from honeybadgerbft.params import CommonParams

logger = logging.getLogger(__name__)


@dataclass
class BroadcastParams(CommonParams):
    """Parameters for RBC (reliable broadcast)"""

    def __post_init__(self) -> None:
        """Validate parameters"""
        super().__post_init__()

    @property
    def K(self) -> int:
        """Erasure code threshold: need this many to reconstruct"""
        return self.N - 2 * self.f

    @property
    def EchoThreshold(self) -> int:
        """Wait for this many ECHO messages to send READY"""
        return self.N - self.f

    @property
    def ReadyThreshold(self) -> int:
        """Wait for this many READY messages to amplify READY"""
        return self.f + 1

    @property
    def OutputThreshold(self) -> int:
        """Wait for this many READY messages to output result"""
        return 2 * self.f + 1


async def reliablebroadcast(
    params: CommonParams,
    input_queue: asyncio.Queue,
    receive_queue: asyncio.Queue,
    send_queues: Sequence[asyncio.Queue],
) -> bytes:
    """Reliable broadcast (RBC) protocol

    :param BroadcastParams params: validated broadcast parameters
        (sid, pid, N, f, leader)
    :param asyncio.Queue input_queue: queue containing the input value
        (only used if ``params.pid == params.leader``)
    :param asyncio.Queue receive_queue: queue containing received messages
        as (sender_id, message) tuples where message is of the form::

            (tag, ...)

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param Sequence[asyncio.Queue] send_queues: sequence of queues to put outgoing messages
        as (recipient_id, message) tuples to be sent asynchronously

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages

        .. important:: **Messages**

            ``VAL( roothash, branch[i], stripe[i] )``
                sent from ``leader`` to each other party
            ``ECHO( roothash, branch[i], stripe[i] )``
                sent after receiving ``VAL`` message
            ``READY( roothash )``
                sent after receiving :math:`N-f` ``ECHO`` messages
                or after receiving :math:`f+1` ``READY`` messages

    .. todo::
        **Accountability**

        A large computational expense occurs when attempting to
        decode the value from erasure codes, and recomputing to check it
        is formed correctly. By transmitting a signature along with
        ``VAL`` and ``ECHO``, we can ensure that if the value is decoded
        but not necessarily reconstructed, then evidence incriminates
        the leader.

    """
    N = params.N
    pid = params.pid
    leader = params.leader
    rbcParams = BroadcastParams(**params.__dict__)
    K = rbcParams.K
    EchoThreshold = rbcParams.EchoThreshold
    ReadyThreshold = rbcParams.ReadyThreshold
    OutputThreshold = rbcParams.OutputThreshold

    assert send_queues is not None and len(send_queues) == N, (
        "send_queues must be a sequence of length N"
    )

    async def broadcast(o: tuple) -> None:
        for i in range(N):
            # send_queues is indexed by sender pid; each item carries recipient id
            await send_queues[pid].put((i, o))

    if pid == leader:
        # The leader erasure encodes the input, sending one strip to each participant
        m = await input_queue.get()  # get input from queue
        assert isinstance(m, (str, bytes))
        # print('Input received: %d bytes' % (len(m),))

        stripes = encode(K, N, m)
        mt = merkleTree(stripes)  # full binary tree
        roothash = mt[1]

        for i in range(N):
            branch = getMerkleBranch(i, mt)
            await send_queues[pid].put((i, ("VAL", roothash, branch, stripes[i])))

    # TODO: filter policy: if leader, discard all messages until sending VAL

    fromLeader = None
    stripes = defaultdict(lambda: [None for _ in range(N)])
    echoCounter = defaultdict(lambda: 0)
    echoSenders = set()  # Peers that have sent us ECHO messages
    ready = defaultdict(set)
    readySent = False
    readySenders = set()  # Peers that have sent us READY messages

    def decode_output(roothash: bytes) -> bytes:
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K, N, stripes[roothash])
        _stripes = encode(K, N, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]
        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash
        return m

    while True:  # main receive loop
        sender, msg = await receive_queue.get()
        if msg[0] == "VAL" and fromLeader is None:
            # Validation
            (_, roothash, branch, stripe) = msg
            if sender != leader:
                logger.warning("VAL message from other than leader: %d", sender)
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, pid)
            except Exception as e:
                logger.warning("Failed to validate VAL message: %s", e)
                continue

            # Update
            fromLeader = roothash
            await broadcast(("ECHO", roothash, branch, stripe, pid))

        elif msg[0] == "ECHO":
            (_, roothash, branch, stripe, stripe_idx) = msg
            # Validation
            if (
                roothash in stripes
                and stripes[roothash][sender] is not None
                or sender in echoSenders
            ):
                logger.warning("Redundant ECHO")
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, stripe_idx)
            except AssertionError as e:
                logger.warning("Failed to validate ECHO message: %s", e)
                continue

            # Update
            stripes[roothash][sender] = stripe
            echoSenders.add(sender)
            echoCounter[roothash] += 1

            if echoCounter[roothash] >= EchoThreshold and not readySent:
                readySent = True
                await broadcast(("READY", roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                return decode_output(roothash)

        elif msg[0] == "READY":
            (_, roothash) = msg
            # Validation
            if sender in ready[roothash] or sender in readySenders:
                logger.warning("Redundant READY")
                continue

            # Update
            ready[roothash].add(sender)
            readySenders.add(sender)

            # Amplify ready messages
            if len(ready[roothash]) >= ReadyThreshold and not readySent:
                readySent = True
                await broadcast(("READY", roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                return decode_output(roothash)
