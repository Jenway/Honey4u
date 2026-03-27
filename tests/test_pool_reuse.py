from __future__ import annotations

import pytest

from honey.consensus.honeybadger.block import _resolve_acs_batches
from honey.data.broadcast_mempool import BroadcastMempool
from honey.data.pool_reuse import (
    PoolReference,
    decode_acs_payload,
    encode_bundle_acs_payload,
)


def test_pool_acs_payload_round_trip_bundle() -> None:
    reference = PoolReference(
        item_id="deadbeefcafebabe",
        origin_round=3,
        origin_sender=1,
        roothash=b"root-hash",
        proof_payload=b"proof-bytes",
    )

    decoded = decode_acs_payload(
        encode_bundle_acs_payload(
            inline_payload=b"encrypted-batch",
            references=(reference,),
        )
    )

    assert decoded.inline_payload == b"encrypted-batch"
    assert decoded.references == (reference,)


@pytest.mark.asyncio
async def test_resolve_acs_batches_expands_inline_and_reference_payloads() -> None:
    reference = PoolReference(
        item_id="deadbeefcafebabe",
        origin_round=3,
        origin_sender=1,
        roothash=b"root-hash",
        proof_payload=b"proof-bytes",
    )
    bundle = encode_bundle_acs_payload(
        inline_payload=b"encrypted-batch-1",
        references=(reference,),
    )
    referenced_payload = encode_bundle_acs_payload(inline_payload=b"encrypted-batch-2")

    async def resolver(ref: PoolReference) -> bytes:
        assert ref == reference
        return referenced_payload

    resolved = await _resolve_acs_batches(
        (bundle, None),
        resolve_pool_reference=resolver,
    )

    assert resolved == (b"encrypted-batch-1", b"encrypted-batch-2")


def test_broadcast_mempool_tracks_reusable_entries() -> None:
    mempool = BroadcastMempool(max_size=8, expire_rounds=3)
    payload_id = mempool.add_reusable(
        payload=b"bundle-acs-payload",
        roothash=b"root",
        proof_payload=b"proof",
        round_no=1,
        sender_id=2,
        timestamp=1.0,
    )

    reusable = mempool.list_reusable(current_round=3, sender_id=2, limit=1)

    assert reusable[0][0] == payload_id
    assert reusable[0][1].protocol == "prbc"

    mempool.mark_consumed(payload_id, 4)
    consumed = mempool.get_reusable(payload_id)

    assert consumed is not None
    assert consumed.consumed_in_round == 4
    assert consumed.reuse_count == 1
