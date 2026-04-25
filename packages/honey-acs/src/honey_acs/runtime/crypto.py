from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ThresholdSignatureRuntime(Protocol):
    @property
    def players(self) -> int: ...

    @property
    def threshold(self) -> int: ...

    def sign_share(self, msg: bytes) -> bytes: ...

    def verify_share(self, player_id: int, share: bytes, msg: bytes) -> bool: ...

    def combine_trusted_shares(self, shares: dict[int, bytes], msg: bytes) -> bytes: ...

    def verify_combined(self, signature: bytes, msg: bytes) -> bool: ...


class PrbcCryptoRuntime(Protocol):
    @property
    def players(self) -> int: ...

    def sign_ready(self, digest: bytes) -> bytes: ...

    def verify_ready_signature(self, player_id: int, signature: bytes, digest: bytes) -> bool: ...

    def verify_ready_proof(
        self,
        digest: bytes,
        sigmas: tuple[tuple[int, bytes], ...],
        threshold: int,
    ) -> bool: ...


class MerkleRuntime(Protocol):
    def encode(self, payload: bytes, k: int, n: int) -> tuple[bytes, list[bytes], list[bytes]]: ...

    def proof_leaf_index(self, proof: bytes) -> int: ...

    def verify(self, stripe: bytes, proof: bytes, root: bytes) -> bool: ...

    def verify_indexed(
        self, stripe: bytes, proof: bytes, root: bytes, stripe_index: int
    ) -> bool: ...

    def decode(
        self, stripes: dict[int, bytes], proofs: dict[int, bytes], root: bytes, k: int, n: int
    ) -> bytes: ...

    def decode_from_dicts(
        self,
        stripes: dict[int, bytes],
        proofs: dict[int, bytes],
        root: bytes,
        k: int,
        n: int,
    ) -> bytes: ...


@dataclass(slots=True)
class AcsRuntimeCrypto:
    coin: ThresholdSignatureRuntime
    prbc: PrbcCryptoRuntime
    merkle: MerkleRuntime
    proof: ThresholdSignatureRuntime | None = None
