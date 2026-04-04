from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from honey.crypto import pke
from honey.data.pool_reuse import (
    PoolBundleProposal,
    PoolReference,
    decode_acs_payload,
    encode_bundle_acs_payload,
)
from honey.support.exceptions import ProtocolInvariantError
from honey.support.messages import TpkeShareBundle
from honey.support.telemetry import METRICS, timed_metric

logger = logging.getLogger(__name__)

type PoolResolver = Callable[[PoolReference], Awaitable[bytes]]


@dataclass(frozen=True)
class LocalProposal:
    payload: bytes
    references: tuple[PoolReference, ...] = ()


@dataclass(frozen=True)
class EncryptedProposal:
    acs_payload: bytes


async def honeybadger_block(
    pid: int,
    N: int,
    f: int,
    PK,
    SK,
    propose_queue: asyncio.Queue,
    acs_input_queue: asyncio.Queue,
    acs_output_queue: asyncio.Queue,
    tpke_bcast_queue: asyncio.Queue,
    tpke_recv_queue: asyncio.Queue,
    logger=None,
    *,
    pool_reuse_enabled: bool = False,
    resolve_pool_reference: PoolResolver | None = None,
) -> tuple:
    proposal = await _read_local_proposal(propose_queue)
    encrypted = _prepare_local_acs_payload(
        pid,
        PK,
        proposal,
        logger,
        pool_reuse_enabled=pool_reuse_enabled,
    )
    await acs_input_queue.put(encrypted.acs_payload)

    acs_batches = await acs_output_queue.get()
    if pool_reuse_enabled:
        acs_batches = await _resolve_acs_batches(
            acs_batches,
            resolve_pool_reference=resolve_pool_reference,
        )

    decryptor, my_shares = _build_batch_decryptor(pid, N, f, PK, SK, acs_batches)
    await tpke_bcast_queue.put(TpkeShareBundle(shares=tuple(my_shares)))

    while not decryptor.is_complete():
        sender_id, bundle = await tpke_recv_queue.get()
        _record_share_bundle(pid, decryptor, sender_id, bundle, logger)

    return tuple(plaintext for plaintext in decryptor.plaintexts() if plaintext is not None)


async def _read_local_proposal(propose_queue: asyncio.Queue) -> LocalProposal:
    propose = await propose_queue.get()
    if isinstance(propose, PoolBundleProposal):
        return LocalProposal(payload=propose.payload, references=propose.references)
    if isinstance(propose, str):
        propose = propose.encode()
    return LocalProposal(payload=propose)


def _prepare_local_acs_payload(
    pid: int,
    PK,
    proposal: LocalProposal,
    logger=None,
    *,
    pool_reuse_enabled: bool,
) -> EncryptedProposal:
    if proposal.references and not pool_reuse_enabled:
        raise ProtocolInvariantError("pool references require pool reuse to be enabled")

    encrypted_batch = _encrypt_local_proposal(pid, PK, proposal, logger)
    if not pool_reuse_enabled:
        return EncryptedProposal(acs_payload=encrypted_batch)
    return EncryptedProposal(
        acs_payload=encode_bundle_acs_payload(
            inline_payload=encrypted_batch,
            references=proposal.references,
        )
    )


def _encrypt_local_proposal(pid: int, PK, proposal: LocalProposal, logger=None) -> bytes:
    with timed_metric("tpke.encrypt.seconds", node=pid):
        encrypted_batch = pke.seal_encrypted_batch(PK, proposal.payload)

    if logger is not None:
        logger.info("event=tpke_encrypt_complete", extra={"node": pid})

    return encrypted_batch


async def _resolve_acs_batches(
    acs_batches: tuple[bytes | None, ...],
    *,
    resolve_pool_reference: PoolResolver | None,
) -> tuple[bytes, ...]:
    resolved: list[bytes] = []
    for raw_batch in acs_batches:
        if raw_batch is None:
            continue
        resolved.extend(
            await _expand_acs_payload(
                raw_batch,
                resolve_pool_reference=resolve_pool_reference,
                path=(),
            )
        )
    return tuple(resolved)


async def _expand_acs_payload(
    raw_payload: bytes,
    *,
    resolve_pool_reference: PoolResolver | None,
    path: tuple[str, ...],
) -> list[bytes]:
    decoded = decode_acs_payload(raw_payload)
    resolved: list[bytes] = []

    if decoded.inline_payload is not None:
        resolved.append(decoded.inline_payload)

    for reference in decoded.references:
        ref_key = reference.item_id
        if ref_key in path:
            raise ProtocolInvariantError("detected cyclic pool reference")
        if resolve_pool_reference is None:
            raise ProtocolInvariantError("selected pool reference cannot be resolved")
        resolved_payload = await resolve_pool_reference(reference)
        resolved.extend(
            await _expand_acs_payload(
                resolved_payload,
                resolve_pool_reference=resolve_pool_reference,
                path=(*path, ref_key),
            )
        )

    if not resolved:
        raise ProtocolInvariantError("ACS payload resolved to an empty batch set")
    return resolved


def _build_batch_decryptor(
    pid: int,
    N: int,
    f: int,
    PK,
    SK,
    acs_batches: tuple[bytes | None, ...] | tuple[bytes, ...],
) -> tuple[pke.BatchDecryptor, list[bytes]]:
    selected_batches = [raw_batch for raw_batch in acs_batches if raw_batch is not None]
    if len(selected_batches) < N - f:
        raise ProtocolInvariantError(
            f"expected at least {N - f} ACS batches, got {len(selected_batches)}"
        )

    decryptor = pke.BatchDecryptor(PK, selected_batches)
    with timed_metric("tpke.partial_open.seconds", node=pid):
        my_shares = decryptor.local_shares(SK)
    return decryptor, my_shares


def _record_share_bundle(
    pid: int,
    decryptor: pke.BatchDecryptor,
    sender_id: int,
    bundle: Any,
    logger=None,
) -> None:
    if not isinstance(bundle, TpkeShareBundle):
        if logger is not None:
            logger.warning(
                f"Ignoring unexpected TPKE payload from {sender_id}",
                extra={"node": pid},
            )
        return

    if len(bundle.shares) != decryptor.batch_count():
        if logger is not None:
            logger.warning(
                f"Invalid TPKE share bundle length from {sender_id}",
                extra={"node": pid},
            )
        return

    with timed_metric("tpke.combine.seconds", node=pid):
        decrypted = decryptor.ingest_bundle(sender_id, list(bundle.shares))

    if not decrypted:
        return

    METRICS.increment("tpke.batch.decrypted", len(decrypted), node=pid)
