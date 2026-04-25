from __future__ import annotations

import json
from typing import cast

from honey_acs.crypto.native import build_runtime_crypto
from honey_acs.crypto.protocols import AcsRuntimeCrypto


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value)


def build_crypto_params(
    protocol: str,
    *,
    sig_pk: bytes,
    sig_sk: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk: bytes,
    proof_sig_pk: bytes | None = None,
    proof_sig_sk: bytes | None = None,
) -> AcsRuntimeCrypto:
    return build_runtime_crypto(
        protocol,
        sig_pk=sig_pk,
        sig_sk=sig_sk,
        ecdsa_pks=ecdsa_pks,
        ecdsa_sk=ecdsa_sk,
        proof_sig_pk=proof_sig_pk,
        proof_sig_sk=proof_sig_sk,
    )


def build_crypto_params_from_payload(protocol: str, payload: dict[str, object]) -> AcsRuntimeCrypto:
    return build_crypto_params(
        protocol,
        sig_pk=_decode_hex(str(payload["sig_pk"])),
        sig_sk=_decode_hex(str(payload["sig_sk"])),
        ecdsa_pks=[_decode_hex(str(value)) for value in cast(list[str], payload["ecdsa_pks"])],
        ecdsa_sk=_decode_hex(str(payload["ecdsa_sk"])),
        proof_sig_pk=(_decode_hex(str(payload["proof_sig_pk"])) if protocol == "dumbo" else None),
        proof_sig_sk=(_decode_hex(str(payload["proof_sig_sk"])) if protocol == "dumbo" else None),
    )


def build_crypto_params_from_json(protocol: str, payload_json: str) -> AcsRuntimeCrypto:
    return build_crypto_params_from_payload(
        protocol, cast(dict[str, object], json.loads(payload_json))
    )
