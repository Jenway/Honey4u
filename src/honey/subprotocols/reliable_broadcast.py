import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass

import honey_native

from honey.crypto.merkle import decode, encode
from honey.data.broadcast_mempool import BroadcastMempool
from honey.support.messages import RbcEcho, RbcReady, RbcVal
from honey.support.params import CommonParams
from honey.support.telemetry import METRICS, timed_metric


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
    send_queue: asyncio.Queue,
    mempool: BroadcastMempool,
    round_no: int,
) -> str:
    """Reliable broadcast (RBC) protocol."""
    N = params.N
    pid = params.pid
    leader = params.leader
    rbcParams = BroadcastParams(**params.__dict__)
    K = rbcParams.K
    EchoThreshold = rbcParams.EchoThreshold
    ReadyThreshold = rbcParams.ReadyThreshold
    OutputThreshold = rbcParams.OutputThreshold

    logger = logging.LoggerAdapter(logging.getLogger(__name__), extra={"node": pid})

    async def broadcast(o: RbcVal | RbcEcho | RbcReady) -> None:
        for i in range(N):
            await send_queue.put((i, o))

    if pid == leader:
        m = await input_queue.get()
        assert isinstance(m, (str, bytes))
        if isinstance(m, str):
            m = m.encode()
        with timed_metric("rbc.encode.seconds", node=pid, leader=leader):
            roothash, shards, proofs = encode(m, K, N)

        for i in range(N):
            await send_queue.put(
                (
                    i,
                    RbcVal(
                        roothash=roothash,
                        proof=proofs[i].to_bytes(),
                        stripe=shards[i],
                        stripe_index=i,
                    ),
                )
            )

    from_leader: bytes | None = None
    stripes: dict[bytes, dict[int, bytes]] = defaultdict(dict)
    merkle_proofs: dict[bytes, dict[int, honey_native.MerkleProof]] = defaultdict(dict)
    echoCounter = defaultdict(lambda: 0)
    echo_senders: dict[bytes, set[int]] = defaultdict(set)
    ready = defaultdict(set)
    ready_root: bytes | None = None

    def decode_output(roothash: bytes) -> bytes:
        available = []

        for stripe_idx, stripe in stripes[roothash].items():
            proof = merkle_proofs[roothash].get(stripe_idx)
            if proof is not None:
                available.append(honey_native.EncodedShard(stripe_idx, stripe, proof))
        if len(available) < K:
            raise ValueError(f"Not enough verified shards ({len(available)} < {K})")

        return decode(available, roothash, K, N)

    async def store_and_return(roothash: bytes) -> str:
        with timed_metric("rbc.decode.seconds", node=pid, leader=leader):
            payload = decode_output(roothash)

        all_shards = [stripes[roothash].get(i) for i in range(N)]
        all_proofs = [
            None if (proof := merkle_proofs[roothash].get(i)) is None else proof.to_bytes()
            for i in range(N)
        ]

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
            f"Stored RBC output in mempool: payload_id={payload_id[:8]}...",
            extra={"node": pid},
        )
        METRICS.increment("rbc.output.stored", node=pid, leader=leader)
        return payload_id

    while True:
        sender, msg = await receive_queue.get()
        if isinstance(msg, RbcVal) and from_leader is None:
            roothash = msg.roothash
            proof_bytes = msg.proof
            stripe = msg.stripe
            stripe_index = msg.stripe_index
            proof = honey_native.MerkleProof.from_bytes(proof_bytes)
            if sender != leader:
                METRICS.increment("rbc.invalid.val_sender", node=pid, leader=leader)
                logger.warning(
                    "VAL message from other than leader",
                    extra={"node": pid, "sender": sender},
                )
                continue
            if stripe_index != pid or proof.leaf_index != stripe_index:
                METRICS.increment("rbc.invalid.val_index", node=pid, leader=leader)
                logger.warning("Invalid VAL shard index", extra={"node": pid, "sender": sender})
                continue
            try:
                is_valid = honey_native.merkle_verify(stripe, proof, roothash)
                assert is_valid, "Merkle proof verification failed"
            except Exception as e:
                logger.warning(f"Failed to validate VAL message: {e}", extra={"node": pid})
                continue

            from_leader = roothash
            stripes[roothash][stripe_index] = stripe
            merkle_proofs[roothash][stripe_index] = proof
            await broadcast(
                RbcEcho(
                    roothash=roothash,
                    proof=proof_bytes,
                    stripe=stripe,
                    stripe_index=stripe_index,
                )
            )

        elif isinstance(msg, RbcEcho):
            roothash = msg.roothash
            proof_bytes = msg.proof
            stripe = msg.stripe
            stripe_idx = msg.stripe_index
            proof = honey_native.MerkleProof.from_bytes(proof_bytes)
            if sender in echo_senders[roothash]:
                logger.warning("Redundant ECHO", extra={"node": pid})
                continue
            if stripe_idx != sender or proof.leaf_index != stripe_idx:
                METRICS.increment("rbc.invalid.echo_index", node=pid, leader=leader)
                logger.warning("Invalid ECHO shard index", extra={"node": pid, "sender": sender})
                continue
            try:
                is_valid = honey_native.merkle_verify(stripe, proof, roothash)
                assert is_valid, "Merkle proof verification failed"
            except Exception as e:
                logger.warning(f"Failed to validate ECHO message: {e}", extra={"node": pid})
                continue

            stripes[roothash][stripe_idx] = stripe
            merkle_proofs[roothash][stripe_idx] = proof
            echo_senders[roothash].add(sender)
            echoCounter[roothash] += 1

            if echoCounter[roothash] >= EchoThreshold and ready_root is None:
                ready_root = roothash
                await broadcast(RbcReady(roothash=roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                return await store_and_return(roothash)

        elif isinstance(msg, RbcReady):
            roothash = msg.roothash
            if sender in ready[roothash]:
                logger.warning("Redundant READY", extra={"node": pid})
                continue

            ready[roothash].add(sender)

            if len(ready[roothash]) >= ReadyThreshold and ready_root is None:
                ready_root = roothash
                await broadcast(RbcReady(roothash=roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                return await store_and_return(roothash)
