from __future__ import annotations

from typing import Any

import honey_native

from honey_acs.runtime.crypto import AcsRuntimeCrypto


class NativeThresholdSignatureRuntime:
    def __init__(self, public_key: Any, private_share: Any | None = None) -> None:
        self._public_key = public_key
        self._private_share = private_share

    @classmethod
    def from_bytes(
        cls, public_key: bytes, private_share: bytes | None = None
    ) -> NativeThresholdSignatureRuntime:
        return cls(
            honey_native.SigPublicKey.from_bytes(public_key),
            None
            if private_share is None
            else honey_native.SigPrivateShare.from_bytes(private_share),
        )

    @property
    def players(self) -> int:
        return int(self._public_key.players)

    @property
    def threshold(self) -> int:
        return int(self._public_key.threshold)

    def sign_share(self, msg: bytes) -> bytes:
        private_share = self._private_share
        if private_share is None:
            raise ValueError("threshold signature private share is not configured")
        return private_share.sign(msg)

    def verify_share(self, player_id: int, share: bytes, msg: bytes) -> bool:
        return bool(self._public_key.verify_share(player_id, share, msg))

    def combine_trusted_shares(self, shares: dict[int, bytes], msg: bytes) -> bytes:
        combiner = getattr(self._public_key, "combine_trusted_shares", None)
        if combiner is not None:
            return combiner(list(shares.items()), msg)
        return self._public_key.combine_shares(list(shares.items()), msg)

    def verify_combined(self, signature: bytes, msg: bytes) -> bool:
        return bool(self._public_key.verify_combined(signature, msg))


class NativePrbcCryptoRuntime:
    def __init__(self, public_keys: list[bytes], private_key: bytes | None = None) -> None:
        self._public_keys = public_keys
        self._private_key = private_key

    @property
    def players(self) -> int:
        return len(self._public_keys)

    def sign_ready(self, digest: bytes) -> bytes:
        if self._private_key is None:
            raise ValueError("PRBC ECDSA private key is not configured")
        return honey_native.ecdsa_sign(self._private_key, digest)

    def verify_ready_signature(self, player_id: int, signature: bytes, digest: bytes) -> bool:
        if player_id < 0 or player_id >= len(self._public_keys):
            return False
        return bool(honey_native.ecdsa_verify(self._public_keys[player_id], digest, signature))

    def verify_ready_proof(
        self,
        digest: bytes,
        sigmas: tuple[tuple[int, bytes], ...],
        threshold: int,
    ) -> bool:
        if len(sigmas) < threshold:
            return False
        seen: set[int] = set()
        selected: list[tuple[int, bytes]] = []
        for player_id, signature in sigmas:
            if player_id < 0 or player_id >= len(self._public_keys) or player_id in seen:
                return False
            seen.add(player_id)
            selected.append((player_id, signature))
        return bool(
            honey_native.ecdsa_verify_threshold_sigs(self._public_keys, digest, selected, threshold)
        )


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
        proof = NativeThresholdSignatureRuntime.from_bytes(proof_sig_pk, proof_sig_sk)
    return AcsRuntimeCrypto(
        coin=NativeThresholdSignatureRuntime.from_bytes(sig_pk, sig_sk),
        prbc=NativePrbcCryptoRuntime(ecdsa_pks, ecdsa_sk),
        merkle=NativeMerkleRuntime(),
        proof=proof,
    )
