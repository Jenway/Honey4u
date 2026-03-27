from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import honey_native

from honey.support.exceptions import SerializationError


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
        try:
            return honey_native.encode_encrypted_batch_py(self)
        except ValueError as exc:
            raise SerializationError("Invalid encrypted batch payload") from exc

    @staticmethod
    def from_bytes(raw: bytes) -> EncryptedBatch:
        try:
            return cast(EncryptedBatch, honey_native.decode_encrypted_batch_py(raw))
        except ValueError as exc:
            raise SerializationError("Invalid encrypted batch payload") from exc


def encode_tx(tx: object) -> bytes:
    if isinstance(tx, str):
        try:
            return honey_native.encode_json_string(tx)
        except ValueError as exc:
            raise SerializationError("Transaction must be JSON serializable") from exc
    try:
        return json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise SerializationError("Transaction must be JSON serializable") from exc


def decode_tx(raw: bytes) -> object:
    try:
        return honey_native.decode_tx_py(raw)
    except ValueError as exc:
        raise SerializationError("Invalid transaction payload") from exc


def tx_dedup_key(tx: object) -> str:
    if isinstance(tx, str):
        return f"s:{tx}"
    return encode_tx(tx).decode("utf-8")


def encode_tx_batch(items: list[bytes]) -> bytes:
    try:
        return honey_native.encode_tx_batch(items)
    except ValueError as exc:
        raise SerializationError("Invalid transaction batch payload") from exc


def decode_tx_batch(raw: bytes) -> list[bytes]:
    try:
        return honey_native.decode_tx_batch(raw)
    except ValueError as exc:
        raise SerializationError("Invalid transaction batch payload") from exc


def merge_tx_batches(blocks: tuple[bytes, ...] | list[bytes]) -> list[object]:
    try:
        return cast(list[object], honey_native.merge_tx_batches_py(list(blocks)))
    except ValueError as exc:
        raise SerializationError("Invalid transaction batch payload") from exc


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
        try:
            return honey_native.encode_protocol_envelope_py(sender, self)
        except ValueError as exc:
            raise SerializationError("Invalid protocol envelope payload") from exc

    @staticmethod
    def from_bytes(payload: bytes) -> tuple[int, ProtocolEnvelope]:
        try:
            sender, envelope = honey_native.decode_protocol_envelope_py(payload)
            return sender, cast(ProtocolEnvelope, envelope)
        except ValueError as exc:
            raise SerializationError("Invalid protocol envelope payload") from exc


@dataclass(frozen=True, slots=True)
class OutboundEnvelope:
    recipient: int
    envelope: ProtocolEnvelope


@dataclass(frozen=True, slots=True)
class InboundEnvelope:
    sender: int
    envelope: ProtocolEnvelope
