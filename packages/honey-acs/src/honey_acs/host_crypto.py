from __future__ import annotations

import json
from typing import cast

import honey_native

from honey_acs.params import CryptoParams


def build_crypto_params(
    protocol: str,
    *,
    sig_pk: bytes,
    sig_sk: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk: bytes,
    proof_sig_pk: bytes | None = None,
    proof_sig_sk: bytes | None = None,
) -> CryptoParams:
    crypto = CryptoParams(
        sig_pk=honey_native.SigPublicKey.from_bytes(sig_pk),
        sig_sk=honey_native.SigPrivateShare.from_bytes(sig_sk),
        ecdsa_pks=ecdsa_pks,
        ecdsa_sk=ecdsa_sk,
    )
    if protocol == "dumbo":
        if proof_sig_pk is None or proof_sig_sk is None:
            raise ValueError("Dumbo crypto material requires proof signature keys")
        crypto.proof_sig_pk = honey_native.SigPublicKey.from_bytes(proof_sig_pk)
        crypto.proof_sig_sk = honey_native.SigPrivateShare.from_bytes(proof_sig_sk)
    return crypto


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value)


def build_crypto_params_from_payload(protocol: str, payload: dict[str, object]) -> CryptoParams:
    # TPKE stays in the Rust outer driver; the Python ACS host only consumes
    # signature and ECDSA material from the shared JSON payload.
    return build_crypto_params(
        protocol,
        sig_pk=_decode_hex(str(payload["sig_pk"])),
        sig_sk=_decode_hex(str(payload["sig_sk"])),
        ecdsa_pks=[_decode_hex(str(value)) for value in cast(list[str], payload["ecdsa_pks"])],
        ecdsa_sk=_decode_hex(str(payload["ecdsa_sk"])),
        proof_sig_pk=(_decode_hex(str(payload["proof_sig_pk"])) if protocol == "dumbo" else None),
        proof_sig_sk=(_decode_hex(str(payload["proof_sig_sk"])) if protocol == "dumbo" else None),
    )


def build_crypto_params_from_json(protocol: str, payload_json: str) -> CryptoParams:
    return build_crypto_params_from_payload(
        protocol,
        cast(dict[str, object], json.loads(payload_json)),
    )
