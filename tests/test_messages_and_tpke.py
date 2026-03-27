import os

import honey_native
import pytest

from honey.acs.dumbo_acs import DumboProofDiffuse
from honey.crypto import merkle, pke
from honey.data.pool_reuse import PoolFetchRequest, PoolFetchResponse
from honey.subprotocols.dumbo_mvba import (
    MvbaAbaMessage,
    MvbaRcPrepare,
    ThresholdShareProof,
)
from honey.subprotocols.provable_reliable_broadcast import PrbcProof, PrbcReady
from honey.support.exceptions import SerializationError
from honey.support.messages import (
    BaConf,
    BaEst,
    Channel,
    EncryptedBatch,
    ProtocolEnvelope,
    RawPayload,
    RbcVal,
    TpkeShareBundle,
    decode_tx,
    decode_tx_batch,
    encode_tx,
    encode_tx_batch,
    tx_dedup_key,
)


def test_protocol_envelope_round_trip() -> None:
    envelope = ProtocolEnvelope(
        round_id=7,
        channel=Channel.ACS_ABA,
        instance_id=2,
        message=BaConf(epoch=5, values=(0, 1)),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=3))

    assert sender == 3
    assert decoded == envelope


def test_protocol_envelope_round_trip_rbc_payload() -> None:
    envelope = ProtocolEnvelope(
        round_id=4,
        channel=Channel.ACS_RBC,
        instance_id=1,
        message=RbcVal(roothash=b"root", proof=b"proof", stripe=b"stripe", stripe_index=9),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=2))

    assert sender == 2
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_raw_payload() -> None:
    envelope = ProtocolEnvelope(
        round_id=5,
        channel=Channel.DUMBO_MVBA,
        instance_id=None,
        message=RawPayload(data=b"opaque-dumbo-payload"),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=1))

    assert sender == 1
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_prbc_payload() -> None:
    envelope = ProtocolEnvelope(
        round_id=6,
        channel=Channel.DUMBO_PRBC,
        instance_id=2,
        message=PrbcReady(leader=2, roothash=b"root", signature=b"sig"),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=2))

    assert sender == 2
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_mvba_payload() -> None:
    proof = ThresholdShareProof(roothash=b"root", signature=b"combined-sig")
    envelope = ProtocolEnvelope(
        round_id=8,
        channel=Channel.DUMBO_MVBA,
        instance_id=None,
        message=MvbaRcPrepare(mvba_round=3, leader=1, proof=proof),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=4))

    assert sender == 4
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_aba_wrapped_payload() -> None:
    envelope = ProtocolEnvelope(
        round_id=9,
        channel=Channel.DUMBO_MVBA,
        instance_id=None,
        message=MvbaAbaMessage(mvba_round=5, payload=BaEst(epoch=2, value=1)),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=3))

    assert sender == 3
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_proof_payload() -> None:
    proof = PrbcProof(roothash=b"root", sigmas=((0, b"a"), (1, b"b"), (2, b"c")))
    envelope = ProtocolEnvelope(
        round_id=10,
        channel=Channel.DUMBO_PROOF,
        instance_id=None,
        message=DumboProofDiffuse(leader=1, proof=proof),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=1))

    assert sender == 1
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_pool_payload() -> None:
    envelope = ProtocolEnvelope(
        round_id=11,
        channel=Channel.DUMBO_POOL,
        instance_id=None,
        message=PoolFetchRequest(item_id="item-1", origin_round=7, origin_sender=2, roothash=b"x"),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=5))

    assert sender == 5
    assert decoded == envelope


def test_protocol_envelope_round_trip_dumbo_pool_response_payload() -> None:
    envelope = ProtocolEnvelope(
        round_id=12,
        channel=Channel.DUMBO_POOL,
        instance_id=None,
        message=PoolFetchResponse(item_id="item-2", payload=b"payload"),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=6))

    assert sender == 6
    assert decoded == envelope


def test_encrypted_batch_round_trip() -> None:
    batch = EncryptedBatch(encrypted_key=b"key-bytes", ciphertext=b"cipher-bytes")

    assert EncryptedBatch.from_bytes(batch.to_bytes()) == batch


def test_tx_batch_round_trip() -> None:
    payload = encode_tx_batch([b'{"tx":1}', b'["x","y"]'])

    assert decode_tx_batch(payload) == [b'{"tx":1}', b'["x","y"]']


def test_string_tx_uses_native_json_encoding() -> None:
    raw = encode_tx('hello "rust"')

    assert raw == honey_native.encode_json_string('hello "rust"')
    assert decode_tx(raw) == 'hello "rust"'


def test_string_tx_dedup_key_uses_lightweight_tagged_key() -> None:
    assert tx_dedup_key("dummy-tx") == "s:dummy-tx"


def test_tpke_share_bundle_round_trip() -> None:
    envelope = ProtocolEnvelope(
        round_id=1,
        channel=Channel.TPKE,
        instance_id=None,
        message=TpkeShareBundle(shares=(b"a", None, b"c")),
    )

    sender, decoded = ProtocolEnvelope.from_bytes(envelope.to_bytes(sender=1))

    assert sender == 1
    assert decoded == envelope


def test_protocol_envelope_rejects_invalid_payload() -> None:
    with pytest.raises(SerializationError):
        ProtocolEnvelope.from_bytes(os.urandom(32))


def test_encrypted_batch_rejects_invalid_payload() -> None:
    with pytest.raises(SerializationError):
        EncryptedBatch.from_bytes(os.urandom(24))


def test_tx_batch_rejects_invalid_payload() -> None:
    with pytest.raises(SerializationError):
        decode_tx_batch(os.urandom(24))


def test_tpke_share_verification(encryption_keys) -> None:
    pk, sks = encryption_keys
    message = b"x" * 32
    ciphertext = pk.encrypt(message)
    share = sks[0].decrypt_share(ciphertext)

    assert pk.verify_ciphertext(ciphertext) is True
    assert pk.verify_share(0, ciphertext, share) is True
    assert pk.verify_share(0, ciphertext, share[:-1] + bytes([share[-1] ^ 1])) is False


def test_seal_encrypted_batch_round_trip(encryption_keys) -> None:
    pk, sks = encryption_keys
    payload = b"batch-payload"

    encoded = pke.seal_encrypted_batch(pk, payload)
    batch = EncryptedBatch.from_bytes(encoded)
    shares = [sks[0].decrypt_share(batch.encrypted_key), sks[1].decrypt_share(batch.encrypted_key)]
    opened_key = pk.combine_shares(batch.encrypted_key, shares)

    assert pke.decrypt(opened_key, batch.ciphertext) == payload


def test_merkle_decode_from_dicts_matches_object_path() -> None:
    num_nodes = 10
    faulty = 3
    k = num_nodes - 2 * faulty
    payload = encode_tx_batch([encode_tx(f"tx-{i}") for i in range(6)])

    root, shards, proofs = merkle.encode(payload, k, num_nodes)
    available = [honey_native.EncodedShard(i, shards[i], proofs[i]) for i in range(k)]
    stripe_map = {i: shards[i] for i in range(k)}
    proof_map = {i: proofs[i].to_bytes() for i in range(k)}

    assert merkle.decode(available, root, k, num_nodes) == payload
    assert merkle.decode_from_dicts(stripe_map, proof_map, root, k, num_nodes) == payload


def test_merkle_round_trip_preserves_encrypted_batch_when_len_divisible_by_k() -> None:
    num_nodes = 10
    faulty = 3
    k = num_nodes - 2 * faulty
    pk, _ = pke.generate(num_nodes, faulty + 1)
    payload = encode_tx_batch([encode_tx(f"tx-{i}") for i in range(4)])

    for _ in range(50):
        encrypted_batch = pke.seal_encrypted_batch(pk, payload)
        assert len(encrypted_batch) % k == 0
        root, shards, proofs = merkle.encode(encrypted_batch, k, num_nodes)
        available = [honey_native.EncodedShard(i, shards[i], proofs[i]) for i in range(k)]

        assert merkle.decode(available, root, k, num_nodes) == encrypted_batch
