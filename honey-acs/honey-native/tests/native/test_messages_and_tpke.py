import honey_native


def test_merkle_decode_from_dicts_matches_object_path() -> None:
    num_nodes = 10
    faulty = 3
    k = num_nodes - 2 * faulty
    # Use a plain bytes payload; no codec dependency needed for Merkle tests.
    payload = b"|".join(f"tx-{i}".encode() for i in range(6))

    encoded = honey_native.merkle_encode(payload, k, num_nodes)
    available = [
        honey_native.EncodedShard(i, encoded.shards[i], encoded.proofs[i]) for i in range(k)
    ]
    stripe_map = {i: encoded.shards[i] for i in range(k)}
    proof_map = {i: encoded.proofs[i].to_bytes() for i in range(k)}

    assert honey_native.merkle_decode(available, encoded.root, k, num_nodes) == payload
    assert (
        honey_native.merkle_decode_dicts(stripe_map, proof_map, encoded.root, k, num_nodes)
        == payload
    )
