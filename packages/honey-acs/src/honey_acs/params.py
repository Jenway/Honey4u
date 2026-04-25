"""Parameter classes for HoneyBadgerBFT protocols"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from honey_acs.runtime.crypto import AcsRuntimeCrypto


@dataclass
class CommonParams:
    """Base BFT parameters"""

    sid: Any
    pid: int
    N: int
    f: int
    leader: int

    def __post_init__(self) -> None:
        """Validate common parameters after initialization."""
        if self.f < 0:
            raise ValueError(f"f={self.f} must be >= 0")
        if self.N < 3 * self.f + 1:
            raise ValueError(f"N={self.N} must be >= 3f+1 where f={self.f}")
        if not 0 <= self.pid < self.N:
            raise ValueError(f"pid={self.pid} must be in range [0, {self.N})")
        if not 0 <= self.leader < self.N:
            raise ValueError(f"leader={self.leader} must be in range [0, {self.N})")


@dataclass
class CryptoParams:
    """Runtime cryptographic capabilities for ACS protocols."""

    runtime: AcsRuntimeCrypto

    def __post_init__(self) -> None:
        if self.runtime is None:
            raise ValueError("runtime crypto must not be None")


@dataclass
class HBConfig:
    """Runtime configuration parameters for HoneyBadgerBFT."""

    batch_size: int = 1
    rust_tx_pool_max_bytes: int = 0
    max_rounds: int = 3
    round_timeout: float = 10.0
    enable_profiling: bool = False
    log_level: str = "INFO"
    hb_broadcast_protocol: str = "rbc"
    enable_broadcast_pool_reuse: bool = False
    broadcast_mempool_backend: str = "rust"
    enable_pool_reference_proposals: bool = False
    enable_pool_fetch_fallback: bool = False
    pool_mempool_max: int = 1000
    pool_grace_ms: int = 200
    pool_expire_rounds: int = 5
    pool_reuse_limit_per_round: int = 1
    enable_ledger_persistence: bool = False
    ledger_dir: str | None = None

    def __post_init__(self) -> None:
        if self.batch_size <= 0:
            raise ValueError(f"batch_size={self.batch_size} must be > 0")
        if self.max_rounds <= 0:
            raise ValueError(f"max_rounds={self.max_rounds} must be > 0")
        if self.round_timeout <= 0:
            raise ValueError(f"round_timeout={self.round_timeout} must be > 0")
        if self.hb_broadcast_protocol not in {"rbc", "prbc"}:
            raise ValueError("hb_broadcast_protocol must be one of: rbc, prbc")
        if self.broadcast_mempool_backend not in {"none", "rust"}:
            raise ValueError("broadcast_mempool_backend must be one of: none, rust")
        if self.pool_mempool_max < 0:
            raise ValueError(f"pool_mempool_max={self.pool_mempool_max} must be >= 0")
        if self.pool_grace_ms < 0:
            raise ValueError(f"pool_grace_ms={self.pool_grace_ms} must be >= 0")
        if self.pool_expire_rounds < 0:
            raise ValueError(f"pool_expire_rounds={self.pool_expire_rounds} must be >= 0")
        if self.pool_reuse_limit_per_round < 0:
            raise ValueError(
                f"pool_reuse_limit_per_round={self.pool_reuse_limit_per_round} must be >= 0"
            )
        if self.rust_tx_pool_max_bytes < 0:
            raise ValueError(f"rust_tx_pool_max_bytes={self.rust_tx_pool_max_bytes} must be >= 0")
        if self.enable_ledger_persistence and not self.ledger_dir:
            raise ValueError("ledger_dir must be set when ledger persistence is enabled")
