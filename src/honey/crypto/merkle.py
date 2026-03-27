import honey_native


def encode(m: bytes, K: int, N: int) -> tuple[bytes, list[bytes], list[honey_native.MerkleProof]]:
    if isinstance(m, str):
        m = m.encode()

    res = honey_native.merkle_encode(m, K, N)
    return res.root, res.shards, [p for p in res.proofs]


def verify(shard: bytes, proof_bytes: bytes, root: bytes) -> bool:
    return honey_native.merkle_verify(shard, honey_native.MerkleProof.from_bytes(proof_bytes), root)


def decode(
    available: list[honey_native.EncodedShard],
    root: bytes,
    k: int,
    n: int,
) -> bytes:
    return honey_native.merkle_decode(available, root, k, n)


def decode_from_dicts(
    stripes: dict[int, bytes],
    proofs: dict[int, bytes],
    root: bytes,
    k: int,
    n: int,
) -> bytes:
    return honey_native.merkle_decode_dicts(stripes, proofs, root, k, n)
