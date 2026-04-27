from __future__ import annotations

import honey_native

from honey_acs.crypto.protocols import AcsRuntimeCrypto


class NativeMerkleRuntime:
    def encode(self, payload: bytes, k: int, n: int) -> tuple[bytes, list[bytes], list[bytes]]:
        result = honey_native.merkle_encode(payload, k, n)
        return result.root, result.shards, [proof.to_bytes() for proof in result.proofs]

    def proof_leaf_index(self, proof: bytes) -> int:
        return int(honey_native.MerkleProof.from_bytes(proof).leaf_index)

    def verify(self, stripe: bytes, proof: bytes, root: bytes) -> bool:
        return bool(
            honey_native.merkle_verify(stripe, honey_native.MerkleProof.from_bytes(proof), root)
        )

    def verify_indexed(self, stripe: bytes, proof: bytes, root: bytes, stripe_index: int) -> bool:
        decoded = honey_native.MerkleProof.from_bytes(proof)
        return int(decoded.leaf_index) == stripe_index and bool(
            honey_native.merkle_verify(stripe, decoded, root)
        )

    def decode(
        self,
        stripes: dict[int, bytes],
        proofs: dict[int, bytes],
        root: bytes,
        k: int,
        n: int,
    ) -> bytes:
        return honey_native.merkle_decode_dicts(stripes, proofs, root, k, n)

    def decode_from_dicts(
        self,
        stripes: dict[int, bytes],
        proofs: dict[int, bytes],
        root: bytes,
        k: int,
        n: int,
    ) -> bytes:
        return self.decode(stripes, proofs, root, k, n)


def build_runtime_crypto(
    protocol: str,
    *,
    sig_pk: bytes,
    sig_sk: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk: bytes,
    proof_sig_pk: bytes | None = None,
    proof_sig_sk: bytes | None = None,
) -> AcsRuntimeCrypto:
    proof = None
    if protocol == "dumbo":
        if proof_sig_pk is None or proof_sig_sk is None:
            raise ValueError("Dumbo crypto material requires proof signature keys")
        proof = honey_native.ThresholdSignatureRuntime.from_bytes(proof_sig_pk, proof_sig_sk)
    return AcsRuntimeCrypto(
        coin=honey_native.ThresholdSignatureRuntime.from_bytes(sig_pk, sig_sk),  # ty: ignore[invalid-argument-type]
        prbc=honey_native.PrbcCryptoRuntime(ecdsa_pks, ecdsa_sk),
        merkle=NativeMerkleRuntime(),
        proof=proof,  # ty: ignore[invalid-argument-type]
    )
