from __future__ import annotations

from collections.abc import Callable
from typing import cast

import honey_native

from honey_acs.exceptions import SerializationError

_MERGE_TX_BATCHES_BYTES = cast(
    Callable[..., bytes], honey_native.__dict__["merge_tx_batches_bytes"]
)


def native_call[T](func: Callable[..., T], message: str, *args: object) -> T:
    try:
        return func(*args)
    except ValueError as exc:
        raise SerializationError(message) from exc


def encode_encrypted_batch(value: object) -> bytes:
    return native_call(
        honey_native.encode_encrypted_batch_py, "Invalid encrypted batch payload", value
    )


def decode_encrypted_batch(raw: bytes) -> object:
    return native_call(
        honey_native.decode_encrypted_batch_py, "Invalid encrypted batch payload", raw
    )


def encode_json_string(value: str) -> bytes:
    return native_call(
        honey_native.encode_json_string, "Transaction must be JSON serializable", value
    )


def decode_tx(raw: bytes) -> object:
    return native_call(honey_native.decode_tx_py, "Invalid transaction payload", raw)


def encode_tx_batch(items: list[bytes]) -> bytes:
    return native_call(honey_native.encode_tx_batch, "Invalid transaction batch payload", items)


def decode_tx_batch(raw: bytes) -> list[bytes]:
    return native_call(honey_native.decode_tx_batch, "Invalid transaction batch payload", raw)


def merge_tx_batches_bytes(blocks: tuple[bytes, ...] | list[bytes]) -> bytes:
    return native_call(_MERGE_TX_BATCHES_BYTES, "Invalid transaction batch payload", list(blocks))


def encode_protocol_envelope(sender: int, envelope: object) -> bytes:
    return native_call(
        honey_native.encode_protocol_envelope_py,
        "Invalid protocol envelope payload",
        sender,
        envelope,
    )


def decode_protocol_envelope(payload: bytes) -> tuple[int, object]:
    return native_call(
        honey_native.decode_protocol_envelope_py,
        "Invalid protocol envelope payload",
        payload,
    )
