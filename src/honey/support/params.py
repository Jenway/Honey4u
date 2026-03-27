"""Parameter classes for HoneyBadgerBFT protocols"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommonParams:
    """Base BFT parameters"""

    sid: Any
    pid: int
    N: int
    f: int
    leader: int

    def __post_init__(self) -> None:
        """Validate common parameters after initialization"""
        assert self.N >= 3 * self.f + 1, f"N={self.N} must be >= 3f+1 where f={self.f}"
        assert self.f >= 0, f"f={self.f} must be >= 0"
        assert 0 <= self.pid < self.N, f"pid={self.pid} must be in range [0, {self.N})"
        assert 0 <= self.leader < self.N, f"leader={self.leader} must be in range [0, {self.N})"


@dataclass
class CryptoParams:
    """Cryptographic key material for HoneyBadgerBFT"""

    sig_pk: Any
    sig_sk: Any
    enc_pk: Any
    enc_sk: Any
    ecdsa_pks: list[bytes] = field(default_factory=list)
    ecdsa_sk: bytes | None = None
    proof_sig_pk: Any | None = None
    proof_sig_sk: Any | None = None

    def __post_init__(self) -> None:
        """Validate crypto parameters"""
        assert self.sig_pk is not None and self.sig_sk is not None, (
            "Signature keys (sig_pk, sig_sk) must not be None"
        )
        assert self.enc_pk is not None and self.enc_sk is not None, (
            "Encryption keys (enc_pk, enc_sk) must not be None"
        )
        if self.ecdsa_pks or self.ecdsa_sk is not None:
            assert self.ecdsa_pks, "ECDSA public keys must not be empty when ECDSA is configured"
            assert self.ecdsa_sk is not None, (
                "ECDSA private key must not be None when ECDSA is configured"
            )
        if self.proof_sig_pk is not None or self.proof_sig_sk is not None:
            assert self.proof_sig_pk is not None, (
                "proof_sig_pk must not be None when proof signatures are configured"
            )
            assert self.proof_sig_sk is not None, (
                "proof_sig_sk must not be None when proof signatures are configured"
            )


@dataclass
class HBConfig:
    """Runtime configuration parameters for HoneyBadgerBFT"""

    batch_size: int = 1
    use_rust_tx_pool: bool = False
    rust_tx_pool_max_bytes: int = 0
    max_rounds: int = 3
    round_timeout: float = 10.0
    enable_profiling: bool = False
    log_level: str = "INFO"
    enable_broadcast_pool_reuse: bool = False
    enable_pool_reference_proposals: bool = False
    enable_pool_fetch_fallback: bool = False
    pool_grace_ms: int = 200
    pool_expire_rounds: int = 5
    pool_reuse_limit_per_round: int = 1
