from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from honey.crypto import pke
from honey.data.pool_reuse import (
    PoolBundleProposal,
    PoolReference,
    decode_acs_payload,
    encode_bundle_acs_payload,
)
from honey.support.exceptions import ProtocolInvariantError
from honey.support.messages import EncryptedBatch, TpkeShareBundle
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


@dataclass
class BatchDecryptionState:
    batch: EncryptedBatch
    shares: dict[int, bytes] = field(default_factory=dict)
    plaintext: bytes | None = None


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

    batch_states, my_shares = _build_batch_states(pid, N, f, SK, acs_batches)
    await tpke_bcast_queue.put(TpkeShareBundle(shares=tuple(my_shares)))

    while not _try_finish_decryptions(pid, f, PK, batch_states, logger):
        sender_id, bundle = await tpke_recv_queue.get()
        _record_share_bundle(pid, PK, sender_id, bundle, batch_states, logger)

    return tuple(state.plaintext for state in batch_states if state.plaintext is not None)


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


def _build_batch_states(
    pid: int,
    N: int,
    f: int,
    SK,
    acs_batches: tuple[bytes | None, ...] | tuple[bytes, ...],
) -> tuple[list[BatchDecryptionState], list[bytes]]:
    selected_batches = [raw_batch for raw_batch in acs_batches if raw_batch is not None]
    if len(selected_batches) < N - f:
        raise ProtocolInvariantError(
            f"expected at least {N - f} ACS batches, got {len(selected_batches)}"
        )

    batch_states: list[BatchDecryptionState] = []
    my_shares: list[bytes] = []
    for raw_batch in selected_batches:
        batch = EncryptedBatch.from_bytes(raw_batch)
        with timed_metric("tpke.partial_open.seconds", node=pid):
            my_share = SK.decrypt_share(batch.encrypted_key)
        batch_states.append(BatchDecryptionState(batch=batch))
        my_shares.append(my_share)

    return batch_states, my_shares


def _try_finish_decryptions(
    pid: int,
    f: int,
    PK,
    batch_states: list[BatchDecryptionState],
    logger=None,
) -> bool:
    for idx, state in enumerate(batch_states):
        if state.plaintext is not None:
            continue

        if len(state.shares) < f + 1:
            return False

        ordered_shares = [share for _, share in sorted(state.shares.items())]
        try:
            with timed_metric("tpke.combine.seconds", node=pid, batch=idx):
                opened_key = PK.combine_shares(state.batch.encrypted_key, ordered_shares)
                state.plaintext = pke.decrypt(opened_key, state.batch.ciphertext)
        except Exception as exc:
            if logger is not None:
                logger.warning(
                    f"Failed to combine TPKE shares for batch {idx}: {exc}",
                    extra={"node": pid},
                )
            METRICS.increment("tpke.combine.retry", node=pid, batch=idx)
            return False

    return all(state.plaintext is not None for state in batch_states)


def _record_share_bundle(
    pid: int,
    PK,
    sender_id: int,
    bundle: Any,
    batch_states: list[BatchDecryptionState],
    logger=None,
) -> None:
    if not isinstance(bundle, TpkeShareBundle):
        if logger is not None:
            logger.warning(
                f"Ignoring unexpected TPKE payload from {sender_id}",
                extra={"node": pid},
            )
        return

    if len(bundle.shares) != len(batch_states):
        if logger is not None:
            logger.warning(
                f"Invalid TPKE share bundle length from {sender_id}",
                extra={"node": pid},
            )
        return

    for idx, state in enumerate(batch_states):
        share = bundle.shares[idx]
        if sender_id in state.shares:
            continue
        if share is None:
            continue
        if not PK.verify_share(sender_id, state.batch.encrypted_key, share):
            continue
        state.shares[sender_id] = share
