from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import honey_native

from honey.support.exceptions import SerializationError

_MERGE_TX_BATCHES_BYTES = cast(
    Callable[..., bytes], honey_native.__dict__["merge_tx_batches_bytes"]
)


def _native_call[T](func: Callable[..., T], message: str, *args: object) -> T:
    try:
        return func(*args)
    except ValueError as exc:
        raise SerializationError(message) from exc


class Channel(StrEnum):
    ACS_COIN = "ACS_COIN"
    ACS_RBC = "ACS_RBC"
    ACS_ABA = "ACS_ABA"
    DUMBO_PRBC = "DUMBO_PRBC"
    DUMBO_PROOF = "DUMBO_PROOF"
    DUMBO_MVBA = "DUMBO_MVBA"
    DUMBO_POOL = "DUMBO_POOL"
    TPKE = "TPKE"


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
class TpkeShareBundle:
    shares: tuple[bytes | None, ...]


@dataclass(frozen=True, slots=True)
class RawPayload:
    data: bytes


@dataclass(frozen=True, slots=True)
class EncryptedBatch:
    encrypted_key: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return _native_call(
            honey_native.encode_encrypted_batch_py,
            "Invalid encrypted batch payload",
            self,
        )

    @staticmethod
    def from_bytes(raw: bytes) -> EncryptedBatch:
        return cast(
            EncryptedBatch,
            _native_call(
                honey_native.decode_encrypted_batch_py, "Invalid encrypted batch payload", raw
            ),
        )


def encode_tx(tx: object) -> bytes:
    if isinstance(tx, str):
        return _native_call(
            honey_native.encode_json_string, "Transaction must be JSON serializable", tx
        )
    try:
        return json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise SerializationError("Transaction must be JSON serializable") from exc


def decode_tx(raw: bytes) -> object:
    return _native_call(honey_native.decode_tx_py, "Invalid transaction payload", raw)


def tx_dedup_key(tx: object) -> str:
    if isinstance(tx, str):
        return f"s:{tx}"
    return encode_tx(tx).decode("utf-8")


def encode_tx_batch(items: list[bytes]) -> bytes:
    return _native_call(honey_native.encode_tx_batch, "Invalid transaction batch payload", items)


def decode_tx_batch(raw: bytes) -> list[bytes]:
    return _native_call(honey_native.decode_tx_batch, "Invalid transaction batch payload", raw)


def decode_block(raw: bytes) -> list[object]:
    return [decode_tx(item) for item in decode_tx_batch(raw)]


def merge_tx_batches_bytes(blocks: tuple[bytes, ...] | list[bytes]) -> bytes:
    return _native_call(
        _MERGE_TX_BATCHES_BYTES,
        "Invalid transaction batch payload",
        list(blocks),
    )


def merge_tx_batches(blocks: tuple[bytes, ...] | list[bytes]) -> list[object]:
    return decode_block(merge_tx_batches_bytes(blocks))


ProtocolMessage = (
    RbcVal
    | RbcEcho
    | RbcReady
    | BaEst
    | BaAux
    | BaConf
    | CoinShareMessage
    | TpkeShareBundle
    | RawPayload
)


@dataclass(frozen=True, slots=True)
class ProtocolEnvelope:
    round_id: int
    channel: Channel
    instance_id: int | None
    message: ProtocolMessage

    def to_bytes(self, sender: int) -> bytes:
        return _native_call(
            honey_native.encode_protocol_envelope_py,
            "Invalid protocol envelope payload",
            sender,
            self,
        )

    @staticmethod
    def from_bytes(payload: bytes) -> tuple[int, ProtocolEnvelope]:
        sender, envelope = _native_call(
            honey_native.decode_protocol_envelope_py,
            "Invalid protocol envelope payload",
            payload,
        )
        return sender, cast(ProtocolEnvelope, envelope)


@dataclass(frozen=True, slots=True)
class OutboundEnvelope:
    recipient: int
    envelope: ProtocolEnvelope


@dataclass(frozen=True, slots=True)
class InboundEnvelope:
    sender: int
    envelope: ProtocolEnvelope
