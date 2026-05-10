from __future__ import annotations

import json
from typing import cast

from honey_acs.crypto.native import build_runtime_crypto
from honey_acs.crypto.protocols import AcsRuntimeCrypto


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value)


def _requires_proof_signing_keys(
    protocol_family: str, config: dict[str, object] | None = None
) -> bool:
    if protocol_family == "dumbo":
        return True
    if protocol_family != "hb":
        raise ValueError(f"unsupported protocol family: {protocol_family}")
    return False


def build_crypto_params(
    protocol_family: str,
    *,
    sig_pk: bytes,
    sig_sk: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk: bytes,
    proof_sig_pk: bytes | None = None,
    proof_sig_sk: bytes | None = None,
) -> AcsRuntimeCrypto:
    return build_runtime_crypto(
        protocol_family,
        sig_pk=sig_pk,
        sig_sk=sig_sk,
        ecdsa_pks=ecdsa_pks,
        ecdsa_sk=ecdsa_sk,
        proof_sig_pk=proof_sig_pk,
        proof_sig_sk=proof_sig_sk,
    )


def build_crypto_params_from_payload(
    protocol_family: str,
    payload: dict[str, object],
    *,
    config: dict[str, object] | None = None,
) -> AcsRuntimeCrypto:
    requires_proof = _requires_proof_signing_keys(protocol_family, config)
    return build_crypto_params(
        protocol_family,
        sig_pk=_decode_hex(str(payload["sig_pk"])),
        sig_sk=_decode_hex(str(payload["sig_sk"])),
        ecdsa_pks=[_decode_hex(str(value)) for value in cast(list[str], payload["ecdsa_pks"])],
        ecdsa_sk=_decode_hex(str(payload["ecdsa_sk"])),
        proof_sig_pk=(_decode_hex(str(payload["proof_sig_pk"])) if requires_proof else None),
        proof_sig_sk=(_decode_hex(str(payload["proof_sig_sk"])) if requires_proof else None),
    )


def build_crypto_params_from_json(
    protocol_family: str,
    payload_json: str,
    *,
    config: dict[str, object] | None = None,
) -> AcsRuntimeCrypto:
    return build_crypto_params_from_payload(
        protocol_family,
        cast(dict[str, object], json.loads(payload_json)),
        config=config,
    )
