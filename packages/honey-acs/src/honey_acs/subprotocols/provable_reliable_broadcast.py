from __future__ import annotations

import asyncio
import logging
import struct
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from honey_acs.crypto.protocols import MerkleRuntime, PrbcCryptoRuntime
from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.params import CommonParams
from honey_acs.telemetry import METRICS

type SendFn = Callable[[int, object], Awaitable[None]]
type BroadcastFn = Callable[[object], Awaitable[None]]


@dataclass(slots=True)
class PRBCParams(CommonParams):
    crypto: PrbcCryptoRuntime
    merkle: MerkleRuntime

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.crypto.players != self.N:
            raise ValueError(f"expected {self.N} PRBC public keys, got {self.crypto.players}")

    @property
    def K(self) -> int:
        return self.N - 2 * self.f

    @property
    def echo_threshold(self) -> int:
        return self.N - self.f

    @property
    def ready_threshold(self) -> int:
        return self.f + 1

    @property
    def output_threshold(self) -> int:
        return self.N - self.f


@dataclass(frozen=True, slots=True)
class PrbcVal:
    leader: int
    roothash: bytes
    proof: bytes
    stripe: bytes
    stripe_index: int


@dataclass(frozen=True, slots=True)
class PrbcEcho:
    leader: int
    roothash: bytes
    proof: bytes
    stripe: bytes
    stripe_index: int


@dataclass(frozen=True, slots=True)
class PrbcReady:
    leader: int
    roothash: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class PrbcProof:
    roothash: bytes
    sigmas: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True, slots=True)
class PrbcOutcome:
    leader: int
    value: bytes
    proof: PrbcProof


def _coerce_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ProtocolInvariantError(f"PRBC input must be bytes or str, got {type(value).__name__}")


def _prbc_ready_digest(sid: str, roothash: bytes) -> bytes:
    return b"prbc-ready|" + sid.encode("utf-8") + b"|" + roothash


def serialize_prbc_proof(proof: PrbcProof) -> bytes:
    chunks = [
        struct.pack(">H", len(proof.roothash)),
        proof.roothash,
        struct.pack(">H", len(proof.sigmas)),
    ]
    for sender, signature in proof.sigmas:
        chunks.append(struct.pack(">H", sender))
        chunks.append(struct.pack(">I", len(signature)))
        chunks.append(signature)
    return b"".join(chunks)


def deserialize_prbc_proof(raw: bytes) -> PrbcProof:
    try:
        (root_len,) = struct.unpack_from(">H", raw, 0)
        offset = 2
        roothash = raw[offset : offset + root_len]
        offset += root_len
        (count,) = struct.unpack_from(">H", raw, offset)
        offset += 2
        sigmas: list[tuple[int, bytes]] = []
        for _ in range(count):
            sender, sig_len = struct.unpack_from(">HI", raw, offset)
            offset += 6
            signature = raw[offset : offset + sig_len]
            offset += sig_len
            sigmas.append((sender, signature))
        if offset != len(raw):
            raise ProtocolInvariantError("PRBC proof has trailing bytes")
    except (IndexError, struct.error) as exc:
        raise ProtocolInvariantError("invalid PRBC proof encoding") from exc
    return PrbcProof(roothash=roothash, sigmas=tuple(sigmas))


def compute_prbc_roothash(
    payload: bytes,
    num_nodes: int,
    faulty: int,
    merkle: MerkleRuntime,
) -> bytes:
    k = num_nodes - 2 * faulty
    roothash, _, _ = merkle.encode(payload, k, num_nodes)
    return roothash


def validate_prbc_proof(
    sid: str,
    num_nodes: int,
    faulty: int,
    crypto: PrbcCryptoRuntime,
    proof: PrbcProof,
) -> bool:
    if crypto.players != num_nodes:
        return False
    threshold = num_nodes - faulty
    digest = _prbc_ready_digest(sid, proof.roothash)
    return crypto.verify_ready_proof(digest, proof.sigmas, threshold)


async def provable_reliable_broadcast(
    params: PRBCParams,
    input_queue: asyncio.Queue[bytes | str],
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
    broadcast_others: BroadcastFn | None = None,
) -> PrbcOutcome:
    logger = logging.LoggerAdapter(
        logging.getLogger("honey.prbc"),
        extra={"node": params.pid, "leader": params.leader},
    )

    pid = params.pid
    leader = params.leader
    n = params.N
    k = params.K

    leader_root: bytes | None = None
    stripes: dict[bytes, dict[int, bytes]] = defaultdict(dict)
    proofs: dict[bytes, dict[int, bytes]] = defaultdict(dict)
    echo_senders: dict[bytes, set[int]] = defaultdict(set)
    ready_senders: dict[bytes, set[int]] = defaultdict(set)
    ready_signatures: dict[bytes, dict[int, bytes]] = defaultdict(dict)
    ready_sent = False
    local_ready_signatures: dict[bytes, bytes] = {}
    ready_digests: dict[bytes, bytes] = {}

    if pid == leader:
        value = _coerce_bytes(await input_queue.get())
        roothash, shards, merkle_proofs = params.merkle.encode(value, k, n)
        for recipient in range(n):
            await send(
                recipient,
                PrbcVal(
                    leader=leader,
                    roothash=roothash,
                    proof=merkle_proofs[recipient],
                    stripe=shards[recipient],
                    stripe_index=recipient,
                ),
            )

    def decode_output(roothash: bytes) -> bytes:
        return params.merkle.decode(stripes[roothash], proofs[roothash], roothash, k, n)

    def ready_digest(roothash: bytes) -> bytes:
        digest = ready_digests.get(roothash)
        if digest is None:
            digest = _prbc_ready_digest(params.sid, roothash)
            ready_digests[roothash] = digest
        return digest

    async def emit_broadcast_others(message: object) -> None:
        if broadcast_others is not None:
            await broadcast_others(message)
            return
        for recipient in range(n):
            if recipient == pid:
                continue
            await send(recipient, message)

    async def send_ready(roothash: bytes) -> None:
        nonlocal ready_sent
        if ready_sent:
            return
        ready_sent = True
        signature = params.crypto.sign_ready(ready_digest(roothash))
        local_ready_signatures[roothash] = signature
        ready_senders[roothash].add(pid)
        ready_signatures[roothash][pid] = signature
        await emit_broadcast_others(
            PrbcReady(
                leader=leader,
                roothash=roothash,
                signature=signature,
            )
        )

    while True:
        sender, message = await receive_queue.get()

        if isinstance(message, PrbcVal):
            if message.leader != leader or sender != leader or leader_root is not None:
                continue
            if message.stripe_index != pid:
                continue
            try:
                if not params.merkle.verify_indexed(
                    message.stripe,
                    message.proof,
                    message.roothash,
                    message.stripe_index,
                ):
                    continue
            except ValueError:
                continue

            leader_root = message.roothash
            stripes[message.roothash][message.stripe_index] = message.stripe
            proofs[message.roothash][message.stripe_index] = message.proof
            echo_senders[message.roothash].add(pid)
            await emit_broadcast_others(
                PrbcEcho(
                    leader=leader,
                    roothash=message.roothash,
                    proof=message.proof,
                    stripe=message.stripe,
                    stripe_index=message.stripe_index,
                ),
            )

        elif isinstance(message, PrbcEcho):
            if message.leader != leader:
                continue
            if ready_sent and len(stripes[message.roothash]) >= k:
                continue
            if sender in echo_senders[message.roothash]:
                continue
            if message.stripe_index != sender:
                continue
            try:
                if not params.merkle.verify_indexed(
                    message.stripe,
                    message.proof,
                    message.roothash,
                    message.stripe_index,
                ):
                    continue
            except ValueError:
                continue

            echo_senders[message.roothash].add(sender)
            stripes[message.roothash][message.stripe_index] = message.stripe
            proofs[message.roothash][message.stripe_index] = message.proof

            if len(echo_senders[message.roothash]) >= params.echo_threshold:
                await send_ready(message.roothash)

            if (
                len(ready_senders[message.roothash]) >= params.output_threshold
                and len(stripes[message.roothash]) >= k
            ):
                sigmas = tuple(
                    sorted(ready_signatures[message.roothash].items())[: params.output_threshold]
                )
                outcome = PrbcOutcome(
                    leader=leader,
                    value=decode_output(message.roothash),
                    proof=PrbcProof(roothash=message.roothash, sigmas=sigmas),
                )
                METRICS.increment("prbc.output", node=pid, leader=leader)
                logger.info("PRBC delivered", extra={"leader": leader})
                return outcome

        elif isinstance(message, PrbcReady):
            if message.leader != leader:
                continue
            if len(ready_senders[message.roothash]) >= params.output_threshold:
                continue
            if sender in ready_senders[message.roothash]:
                continue
            if sender == pid:
                local_signature = local_ready_signatures.get(message.roothash)
                if local_signature is None or message.signature != local_signature:
                    continue
            elif not params.crypto.verify_ready_signature(
                sender,
                message.signature,
                ready_digest(message.roothash),
            ):
                continue

            ready_senders[message.roothash].add(sender)
            ready_signatures[message.roothash][sender] = message.signature

            if len(ready_senders[message.roothash]) >= params.ready_threshold:
                await send_ready(message.roothash)

            if (
                len(ready_senders[message.roothash]) >= params.output_threshold
                and len(stripes[message.roothash]) >= k
            ):
                sigmas = tuple(
                    sorted(ready_signatures[message.roothash].items())[: params.output_threshold]
                )
                outcome = PrbcOutcome(
                    leader=leader,
                    value=decode_output(message.roothash),
                    proof=PrbcProof(roothash=message.roothash, sigmas=sigmas),
                )
                METRICS.increment("prbc.output", node=pid, leader=leader)
                logger.info("PRBC delivered", extra={"leader": leader})
                return outcome
