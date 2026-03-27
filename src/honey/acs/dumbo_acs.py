from __future__ import annotations

import asyncio
import logging
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from honey.subprotocols.dumbo_mvba import MVBAParams, dumbo_mvba
from honey.subprotocols.provable_reliable_broadcast import (
    PrbcEcho,
    PrbcOutcome,
    PRBCParams,
    PrbcProof,
    PrbcReady,
    PrbcVal,
    provable_reliable_broadcast,
    validate_prbc_proof,
)
from honey.support.exceptions import ProtocolInvariantError
from honey.support.telemetry import METRICS

type SendFn = Callable[[int, object], Awaitable[None]]
type PrbcProofVector = tuple[PrbcProof | None, ...]
type DumboACSDecision = tuple[bytes | None, ...]


@dataclass(slots=True)
class DumboACSParams(MVBAParams):
    ecdsa_pks: list[bytes]
    ecdsa_sk: bytes
    carryover_grace_ms: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        if len(self.ecdsa_pks) != self.N:
            raise ValueError(f"expected {self.N} ECDSA public keys, got {len(self.ecdsa_pks)}")
        if not self.ecdsa_sk:
            raise ValueError("ecdsa_sk must not be empty")


@dataclass(frozen=True, slots=True)
class DumboProofDiffuse:
    leader: int
    proof: PrbcProof


def _coerce_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ProtocolInvariantError(f"DumboACS input must be bytes or str, got {type(value).__name__}")


def _prbc_sid(sid: str, leader: int) -> str:
    return f"{sid}:prbc:{leader}"


def _prbc_params(params: DumboACSParams, leader: int) -> PRBCParams:
    return PRBCParams(
        sid=_prbc_sid(params.sid, leader),
        pid=params.pid,
        N=params.N,
        f=params.f,
        leader=leader,
        ecdsa_pks=params.ecdsa_pks,
        ecdsa_sk=params.ecdsa_sk,
    )


def _serialize_prbc_vector(entries: PrbcProofVector) -> bytes:
    chunks = [struct.pack(">H", len(entries))]
    for proof in entries:
        if proof is None:
            chunks.append(b"\x00")
            continue
        chunks.append(b"\x01")
        chunks.append(struct.pack(">H", len(proof.roothash)))
        chunks.append(proof.roothash)
        chunks.append(struct.pack(">H", len(proof.sigmas)))
        for sender, signature in proof.sigmas:
            chunks.append(struct.pack(">H", sender))
            chunks.append(struct.pack(">I", len(signature)))
            chunks.append(signature)
    return b"".join(chunks)


def _deserialize_prbc_vector(raw: bytes, n: int) -> PrbcProofVector:
    try:
        (size,) = struct.unpack_from(">H", raw, 0)
    except struct.error as exc:
        raise ProtocolInvariantError("invalid DumboACS proof vector header") from exc
    if size != n:
        raise ProtocolInvariantError(f"DumboACS proof vector has size {size}, expected {n}")

    offset = 2
    results: list[PrbcProof | None] = []
    try:
        for _ in range(size):
            present = raw[offset]
            offset += 1
            if present == 0:
                results.append(None)
                continue
            if present != 1:
                raise ProtocolInvariantError("invalid DumboACS proof vector presence flag")

            (root_len,) = struct.unpack_from(">H", raw, offset)
            offset += 2
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
            results.append(PrbcProof(roothash=roothash, sigmas=tuple(sigmas)))
    except (IndexError, struct.error) as exc:
        raise ProtocolInvariantError("truncated DumboACS proof vector") from exc

    if offset != len(raw):
        raise ProtocolInvariantError("DumboACS proof vector has trailing bytes")
    return tuple(results)


def _build_mvba_predicate(params: DumboACSParams) -> Callable[[bytes], bool]:
    def _predicate(raw: bytes) -> bool:
        try:
            entries = _deserialize_prbc_vector(raw, params.N)
        except Exception:
            return False

        valid = 0
        for leader, proof in enumerate(entries):
            if proof is None:
                continue
            if not validate_prbc_proof(
                _prbc_sid(params.sid, leader),
                params.N,
                params.f,
                params.ecdsa_pks,
                proof,
            ):
                continue
            valid += 1
        return valid >= params.N - params.f

    return _predicate


async def dumbo_acs(
    params: DumboACSParams,
    input_queue: asyncio.Queue[bytes | str],
    decide_queue: asyncio.Queue[DumboACSDecision],
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
    carryover_queue: asyncio.Queue[tuple[PrbcOutcome, ...]] | None = None,
) -> None:
    logger = logging.LoggerAdapter(logging.getLogger("honey.dumbo_acs"), extra={"node": params.pid})

    local_input = _coerce_bytes(await input_queue.get())
    prbc_recvs = [asyncio.Queue() for _ in range(params.N)]
    diffuse_recv: asyncio.Queue[tuple[int, DumboProofDiffuse]] = asyncio.Queue()
    mvba_recv: asyncio.Queue[tuple[int, object]] = asyncio.Queue()
    mvba_input: asyncio.Queue[bytes] = asyncio.Queue(1)
    mvba_output: asyncio.Queue[bytes] = asyncio.Queue(1)

    async def recv_dispatcher() -> None:
        try:
            while True:
                sender, message = await receive_queue.get()
                if isinstance(message, (PrbcVal, PrbcEcho, PrbcReady)):
                    if 0 <= message.leader < params.N:
                        prbc_recvs[message.leader].put_nowait((sender, message))
                elif isinstance(message, DumboProofDiffuse):
                    diffuse_recv.put_nowait((sender, message))
                else:
                    mvba_recv.put_nowait((sender, message))
        except asyncio.CancelledError:
            pass

    dispatcher_task = asyncio.create_task(recv_dispatcher())

    prbc_tasks: list[asyncio.Task[PrbcOutcome]] = []
    for leader in range(params.N):
        leader_input: asyncio.Queue[bytes | str] = asyncio.Queue(1)
        if leader == params.pid:
            leader_input.put_nowait(local_input)
        prbc_tasks.append(
            asyncio.create_task(
                provable_reliable_broadcast(
                    _prbc_params(params, leader),
                    leader_input,
                    prbc_recvs[leader],
                    send,
                )
            )
        )

    async def diffuse_local_proof() -> None:
        outcome = await prbc_tasks[params.pid]
        message = DumboProofDiffuse(leader=params.pid, proof=outcome.proof)
        diffuse_recv.put_nowait((params.pid, message))
        for recipient in range(params.N):
            if recipient == params.pid:
                continue
            await send(recipient, message)

    local_diffuse_task = asyncio.create_task(diffuse_local_proof())
    mvba_task = asyncio.create_task(
        dumbo_mvba(
            params,
            mvba_input,
            mvba_output,
            mvba_recv,
            send,
            predicate=_build_mvba_predicate(params),
        )
    )

    selected_leaders: set[int] = set()
    try:
        proofs: list[PrbcProof | None] = [None] * params.N
        valid_senders: set[int] = set()

        while len(valid_senders) < params.N - params.f:
            sender, message = await diffuse_recv.get()
            if sender in valid_senders:
                continue
            if sender != message.leader:
                continue
            if not validate_prbc_proof(
                _prbc_sid(params.sid, sender),
                params.N,
                params.f,
                params.ecdsa_pks,
                message.proof,
            ):
                continue
            valid_senders.add(sender)
            proofs[sender] = message.proof

        await mvba_input.put(_serialize_prbc_vector(tuple(proofs)))
        selected = _deserialize_prbc_vector(await mvba_output.get(), params.N)
        if sum(proof is not None for proof in selected) < params.N - params.f:
            raise ProtocolInvariantError("DumboACS selected fewer than N-f PRBC proofs")

        values: list[bytes | None] = [None] * params.N
        for leader, selected_proof in enumerate(selected):
            if selected_proof is None:
                continue
            selected_leaders.add(leader)
            outcome = await prbc_tasks[leader]
            if outcome.proof.roothash != selected_proof.roothash:
                raise ProtocolInvariantError(
                    f"selected PRBC proof for leader {leader} does not match local PRBC output"
                )
            values[leader] = outcome.value

        decision = tuple(values)
        await decide_queue.put(decision)
        METRICS.increment("dumbo_acs.decision", node=params.pid)
        logger.info(
            "DumboACS decided",
            extra={"selected": sum(value is not None for value in decision)},
        )

        await mvba_task

        if carryover_queue is not None:
            if params.carryover_grace_ms > 0:
                await asyncio.sleep(params.carryover_grace_ms / 1000.0)
            carryovers: list[PrbcOutcome] = []
            for task in prbc_tasks:
                if not task.done() or task.cancelled():
                    continue
                try:
                    outcome = task.result()
                except Exception:
                    continue
                if outcome.leader in selected_leaders:
                    continue
                carryovers.append(outcome)
            await carryover_queue.put(tuple(carryovers))
    finally:
        dispatcher_task.cancel()
        local_diffuse_task.cancel()
        for task in prbc_tasks:
            if not task.done():
                task.cancel()
        if not mvba_task.done():
            mvba_task.cancel()

        for task in [dispatcher_task, local_diffuse_task, mvba_task, *prbc_tasks]:
            try:
                await task
            except asyncio.CancelledError:
                pass
