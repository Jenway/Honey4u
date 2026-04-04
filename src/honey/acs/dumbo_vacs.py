from __future__ import annotations

import asyncio
import logging
import pickle
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from honey.crypto import sig
from honey.subprotocols.dumbo_mvba import MVBAParams, dumbo_mvba
from honey.support.exceptions import ProtocolInvariantError
from honey.support.telemetry import METRICS


@dataclass(slots=True)
class VACSParams(MVBAParams):
    """Parameters for Dumbo validated common subset."""


@dataclass(frozen=True, slots=True)
class VacsDiffuse:
    value: bytes
    signature: bytes


type VacsEntry = tuple[int, bytes, bytes] | None
type VacsDecision = tuple[bytes | None, ...]
type VacsPredicate = Callable[[int, bytes], bool]
type SendFn = Callable[[int, object], Awaitable[None]]


def _coerce_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    raise ProtocolInvariantError(f"VACS input must be bytes or str, got {type(value).__name__}")


def _diffuse_digest(sid: str, value: bytes) -> bytes:
    return b"vacs-diffuse|" + sid.encode() + b"|" + value


def _serialize_entries(entries: tuple[VacsEntry, ...]) -> bytes:
    return pickle.dumps(entries, protocol=pickle.HIGHEST_PROTOCOL)


def _deserialize_entries(raw: bytes, n: int) -> tuple[VacsEntry, ...]:
    value = pickle.loads(raw)
    if not isinstance(value, tuple) or len(value) != n:
        raise ProtocolInvariantError("VACS decided value must be an N-sized tuple")
    return value


def _build_mvba_predicate(params: VACSParams, predicate: VacsPredicate) -> Callable[[bytes], bool]:
    def _predicate(raw: bytes) -> bool:
        try:
            entries = _deserialize_entries(raw, params.N)
        except Exception:
            return False

        candidates: list[tuple[int, bytes, bytes]] = []
        for index, entry in enumerate(entries):
            if entry is None:
                continue
            sender_id, value, share = entry
            if sender_id != index:
                continue
            if not predicate(index, value):
                continue
            candidates.append((sender_id, share, _diffuse_digest(params.sid, value)))

        valid = sum(sig.verify_shares_for_messages(params.proof_pk, candidates))
        return valid >= params.N - params.f

    return _predicate


async def validated_common_subset(
    params: VACSParams,
    input_queue: asyncio.Queue[bytes | str],
    decide_queue: asyncio.Queue[VacsDecision],
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
    predicate: VacsPredicate,
) -> None:
    logger = logging.LoggerAdapter(logging.getLogger("honey.vacs"), extra={"node": params.pid})

    local_input = _coerce_bytes(await input_queue.get())
    local_valid = predicate(params.pid, local_input)

    diffuse_recv: asyncio.Queue[tuple[int, VacsDiffuse]] = asyncio.Queue()
    mvba_recv: asyncio.Queue[tuple[int, object]] = asyncio.Queue()
    mvba_input: asyncio.Queue[bytes | str] = asyncio.Queue(1)
    mvba_output: asyncio.Queue[bytes] = asyncio.Queue(1)

    async def recv_dispatcher() -> None:
        try:
            while True:
                sender, message = await receive_queue.get()
                if isinstance(message, VacsDiffuse):
                    diffuse_recv.put_nowait((sender, message))
                else:
                    mvba_recv.put_nowait((sender, message))
        except asyncio.CancelledError:
            pass

    dispatcher_task = asyncio.create_task(recv_dispatcher())
    mvba_task = asyncio.create_task(
        dumbo_mvba(
            params,
            mvba_input,
            mvba_output,
            mvba_recv,
            send,
            predicate=_build_mvba_predicate(params, predicate),
        )
    )

    try:
        if local_valid:
            signature = params.proof_sk.sign(_diffuse_digest(params.sid, local_input))
            for recipient in range(params.N):
                await send(recipient, VacsDiffuse(value=local_input, signature=signature))

        entries: list[VacsEntry] = [None] * params.N
        valid_senders: set[int] = set()

        while len(valid_senders) < params.N - params.f:
            sender, message = await diffuse_recv.get()
            if sender in valid_senders:
                continue
            if not predicate(sender, message.value):
                continue
            if not params.proof_pk.verify_share(
                sender,
                message.signature,
                _diffuse_digest(params.sid, message.value),
            ):
                continue
            valid_senders.add(sender)
            entries[sender] = (sender, message.value, message.signature)

        await mvba_input.put(_serialize_entries(tuple(entries)))
        decided_entries = _deserialize_entries(await mvba_output.get(), params.N)
        result = tuple(entry[1] if entry is not None else None for entry in decided_entries)

        if sum(value is not None for value in result) < params.N - params.f:
            raise ProtocolInvariantError("VACS decided vector has fewer than N-f values")

        await decide_queue.put(result)
        METRICS.increment("vacs.decision", node=params.pid)
        logger.info("VACS decided", extra={"selected": sum(value is not None for value in result)})

        await mvba_task
    finally:
        dispatcher_task.cancel()
        try:
            await dispatcher_task
        except asyncio.CancelledError:
            pass
        if not mvba_task.done():
            mvba_task.cancel()
        try:
            await mvba_task
        except asyncio.CancelledError:
            pass
