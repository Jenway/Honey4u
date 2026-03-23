import asyncio
import logging
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

import honey_native

from crypto.merkle import decode, encode
from honeybadgerbft.broadcast_mempool import BroadcastMempool
from honeybadgerbft.params import CommonParams


@dataclass
class BroadcastParams(CommonParams):
    """Parameters for RBC (reliable broadcast)"""

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
    mempool: BroadcastMempool,
    round_no: int,
) -> str:
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
    :param BroadcastMempool mempool: mempool to store broadcast data
    :param int round_no: current round number for mempool indexing

    :return str: ``payload_id`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages. The complete broadcast data is
        stored in the mempool and can be retrieved using this payload_id.

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

    # Setup logger with node context
    logger = logging.LoggerAdapter(logging.getLogger(__name__), extra={"node": pid})

    assert send_queues is not None and len(send_queues) == N, (
        "send_queues must be a sequence of length N"
    )

    async def broadcast(o: tuple) -> None:
        for i in range(N):
            # send_queues is indexed by sender pid; each item carries recipient id
            await send_queues[pid].put((i, o))

    # Cache for merkle proofs indexed by roothash
    merkle_proofs_cache = {}

    if pid == leader:
        # The leader erasure encodes the input using Rust implementation
        m = await input_queue.get()  # get input from queue
        assert isinstance(m, (str, bytes))
        if isinstance(m, str):
            m = m.encode()
        # print('Input received: %d bytes' % (len(m),))

        roothash, shards, proofs = encode(m, K, N)

        # Cache proofs for reference
        merkle_proofs_cache[roothash] = proofs

        for i in range(N):
            # Send (roothash, proof, shard) to each participant
            # proof is the serialized merkle proof for this shard
            await send_queues[pid].put((i, ("VAL", roothash, proofs[i].to_bytes(), shards[i])))

    # TODO: filter policy: if leader, discard all messages until sending VAL

    fromLeader = None
    stripes = defaultdict(lambda: [None for _ in range(N)])
    merkle_proofs = defaultdict(lambda: [None for _ in range(N)])
    echoCounter = defaultdict(lambda: 0)
    echoSenders = set()  # Peers that have sent us ECHO messages
    ready = defaultdict(set)
    readySent = False
    readySenders = set()  # Peers that have sent us READY messages

    def decode_output(roothash: bytes) -> bytes:
        # Collect available shards with their proofs
        available = []

        for i in range(N):
            s = stripes[roothash][i]
            p = merkle_proofs[roothash][i]

            if s is not None and p is not None:
                available.append(honey_native.EncodedShard(i, s, p))
        if len(available) < K:
            # This shouldn't happen if we've verified all proofs
            raise ValueError(f"Not enough verified shards ({len(available)} < {K})")

        # Use Rust merkle_decode which verifies proofs internally
        m = decode(available, roothash, K, N)

        # Note: The original code re-encoded to verify, but Rust implementation
        # already verified all proofs during decode
        return m

    async def store_and_return(roothash: bytes) -> str:
        """Decode output and store in mempool, returning payload_id."""
        # Decode the complete payload
        payload = decode_output(roothash)

        # Collect all shards for mempool storage
        all_shards = [stripes[roothash][i] for i in range(N)]
        all_proofs = [merkle_proofs[roothash][i] for i in range(N)]

        # Store complete broadcast data in mempool
        payload_id = mempool.add(
            payload=payload,
            roothash=roothash,
            shards=all_shards,
            proofs=all_proofs,
            round_no=round_no,
            sender_id=leader,
            timestamp=time.time(),
        )

        logger.debug(
            f"Stored RBC output in mempool: payload_id={payload_id[:8]}...", extra={"node": pid}
        )
        return payload_id

    while True:  # main receive loop
        sender, msg = await receive_queue.get()
        if msg[0] == "VAL" and fromLeader is None:
            # Validation
            (_, roothash, proof_bytes, stripe) = msg
            proof = honey_native.MerkleProof.from_bytes(proof_bytes)
            if sender != leader:
                logger.warning(
                    "VAL message from other than leader", extra={"node": pid, "sender": sender}
                )
                continue
            try:
                is_valid = honey_native.merkle_verify(stripe, proof, roothash)
                assert is_valid, "Merkle proof verification failed"
            except Exception as e:
                logger.warning(f"Failed to validate VAL message: {e}", extra={"node": pid})
                continue

            # Update
            fromLeader = roothash
            await broadcast(("ECHO", roothash, proof_bytes, stripe, pid))

        elif msg[0] == "ECHO":
            (_, roothash, proof_bytes, stripe, stripe_idx) = msg
            proof = honey_native.MerkleProof.from_bytes(proof_bytes)
            # Validation
            if (
                roothash in stripes
                and stripes[roothash][sender] is not None
                or sender in echoSenders
            ):
                logger.warning("Redundant ECHO", extra={"node": pid})
                continue
            try:
                # Verify using Rust merkle_verify
                is_valid = honey_native.merkle_verify(stripe, proof, roothash)
                assert is_valid, "Merkle proof verification failed"
            except Exception as e:
                logger.warning(f"Failed to validate ECHO message: {e}", extra={"node": pid})
                continue

            # Update
            stripes[roothash][sender] = stripe
            merkle_proofs[roothash][sender] = proof
            echoSenders.add(sender)
            echoCounter[roothash] += 1

            if echoCounter[roothash] >= EchoThreshold and not readySent:
                readySent = True
                await broadcast(("READY", roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                return await store_and_return(roothash)

        elif msg[0] == "READY":
            (_, roothash) = msg
            # Validation
            if sender in ready[roothash] or sender in readySenders:
                logger.warning("Redundant READY", extra={"node": pid})
                continue

            # Update
            ready[roothash].add(sender)
            readySenders.add(sender)

            # Amplify ready messages
            if len(ready[roothash]) >= ReadyThreshold and not readySent:
                readySent = True
                await broadcast(("READY", roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                return await store_and_return(roothash)
