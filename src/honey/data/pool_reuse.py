from __future__ import annotations

import struct
from dataclasses import dataclass

from honey.support.exceptions import ProtocolInvariantError

_INLINE_TAG = 1
_REFERENCE_TAG = 2
_BUNDLE_TAG = 3


@dataclass(frozen=True, slots=True)
class PoolReference:
    item_id: str
    origin_round: int
    origin_sender: int
    roothash: bytes
    proof_payload: bytes


@dataclass(frozen=True, slots=True)
class PoolBundleProposal:
    payload: bytes
    references: tuple[PoolReference, ...] = ()


@dataclass(frozen=True, slots=True)
class PoolFetchRequest:
    item_id: str
    origin_round: int
    origin_sender: int
    roothash: bytes


@dataclass(frozen=True, slots=True)
class PoolFetchResponse:
    item_id: str
    payload: bytes


@dataclass(frozen=True, slots=True)
class DecodedAcsPayload:
    inline_payload: bytes | None = None
    references: tuple[PoolReference, ...] = ()


def encode_inline_acs_payload(payload: bytes) -> bytes:
    return encode_bundle_acs_payload(inline_payload=payload)


def encode_reference_acs_payload(reference: PoolReference) -> bytes:
    return encode_bundle_acs_payload(references=(reference,))


def encode_bundle_acs_payload(
    *,
    inline_payload: bytes | None = None,
    references: tuple[PoolReference, ...] = (),
) -> bytes:
    chunks = [
        bytes([_BUNDLE_TAG]),
        struct.pack(">I", len(inline_payload) if inline_payload is not None else 0),
    ]
    if inline_payload is not None:
        chunks.append(inline_payload)
    chunks.append(struct.pack(">H", len(references)))
    for reference in references:
        chunks.extend(_encode_reference_chunks(reference))
    return b"".join(chunks)


def decode_acs_payload(raw: bytes) -> DecodedAcsPayload:
    if not raw:
        raise ProtocolInvariantError("empty ACS payload")

    tag = raw[0]
    offset = 1
    try:
        if tag == _INLINE_TAG:
            (size,) = struct.unpack_from(">I", raw, offset)
            offset += 4
            payload = raw[offset : offset + size]
            offset += size
            if offset != len(raw):
                raise ProtocolInvariantError("inline ACS payload has trailing bytes")
            return DecodedAcsPayload(inline_payload=payload)

        if tag == _REFERENCE_TAG:
            reference, offset = _decode_reference(raw, offset)
            if offset != len(raw):
                raise ProtocolInvariantError("reference ACS payload has trailing bytes")
            return DecodedAcsPayload(references=(reference,))

        if tag != _BUNDLE_TAG:
            raise ProtocolInvariantError(f"unknown ACS payload tag: {tag}")

        (inline_len,) = struct.unpack_from(">I", raw, offset)
        offset += 4
        inline_payload = None
        if inline_len > 0:
            inline_payload = raw[offset : offset + inline_len]
            offset += inline_len
        (reference_count,) = struct.unpack_from(">H", raw, offset)
        offset += 2
        references: list[PoolReference] = []
        for _ in range(reference_count):
            reference, offset = _decode_reference(raw, offset)
            references.append(reference)
        if offset != len(raw):
            raise ProtocolInvariantError("bundle ACS payload has trailing bytes")
        return DecodedAcsPayload(
            inline_payload=inline_payload,
            references=tuple(references),
        )
    except (IndexError, UnicodeDecodeError, struct.error) as exc:
        raise ProtocolInvariantError("malformed ACS payload") from exc


def _encode_reference_chunks(reference: PoolReference) -> list[bytes]:
    item_id_bytes = reference.item_id.encode("ascii")
    return [
        struct.pack(">H", len(item_id_bytes)),
        item_id_bytes,
        struct.pack(">I", reference.origin_round),
        struct.pack(">H", reference.origin_sender),
        struct.pack(">H", len(reference.roothash)),
        reference.roothash,
        struct.pack(">I", len(reference.proof_payload)),
        reference.proof_payload,
    ]


def _decode_reference(raw: bytes, offset: int) -> tuple[PoolReference, int]:
    (item_id_len,) = struct.unpack_from(">H", raw, offset)
    offset += 2
    item_id = raw[offset : offset + item_id_len].decode("ascii")
    offset += item_id_len
    (origin_round,) = struct.unpack_from(">I", raw, offset)
    offset += 4
    (origin_sender,) = struct.unpack_from(">H", raw, offset)
    offset += 2
    (roothash_len,) = struct.unpack_from(">H", raw, offset)
    offset += 2
    roothash = raw[offset : offset + roothash_len]
    offset += roothash_len
    (proof_len,) = struct.unpack_from(">I", raw, offset)
    offset += 4
    proof_payload = raw[offset : offset + proof_len]
    offset += proof_len
    return (
        PoolReference(
            item_id=item_id,
            origin_round=origin_round,
            origin_sender=origin_sender,
            roothash=roothash,
            proof_payload=proof_payload,
        ),
        offset,
    )
