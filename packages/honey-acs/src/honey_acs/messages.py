from dataclasses import dataclass
from enum import StrEnum


class Channel(StrEnum):
    ACS_COIN = "ACS_COIN"
    ACS_RBC = "ACS_RBC"
    ACS_ABA = "ACS_ABA"
    DUMBO_PRBC = "DUMBO_PRBC"
    DUMBO_PROOF = "DUMBO_PROOF"
    DUMBO_MVBA = "DUMBO_MVBA"
    DUMBO_POOL = "DUMBO_POOL"


@dataclass(frozen=True, slots=True)
class RbcVal:
    roothash: bytes
    proof: bytes
    stripe: bytes
    stripe_index: int


@dataclass(frozen=True, slots=True)
class RbcEcho:
    roothash: bytes
    proof: bytes
    stripe: bytes
    stripe_index: int


@dataclass(frozen=True, slots=True)
class RbcReady:
    roothash: bytes


@dataclass(frozen=True, slots=True)
class BaEst:
    epoch: int
    value: int


@dataclass(frozen=True, slots=True)
class BaAux:
    epoch: int
    value: int


@dataclass(frozen=True, slots=True)
class BaConf:
    epoch: int
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CoinShareMessage:
    round_id: int
    signature: bytes


@dataclass(frozen=True, slots=True)
class RawPayload:
    data: bytes


@dataclass(frozen=True, slots=True)
class EncryptedBatch:
    encrypted_key: bytes
    ciphertext: bytes


ProtocolMessage = (
    RbcVal | RbcEcho | RbcReady | BaEst | BaAux | BaConf | CoinShareMessage | RawPayload
)
