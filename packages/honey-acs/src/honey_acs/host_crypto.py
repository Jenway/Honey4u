from __future__ import annotations

import json
from typing import cast

import honey_native

from honey_acs.params import CryptoParams


def serialize_hb_crypto_payloads_json(num_nodes: int, faulty: int) -> list[str]:
    """Generate per-node HoneyBadger crypto material as JSON strings.

    Delegates entirely to Rust; Python never holds native key objects.
    """
    return honey_native.generate_hb_crypto_payloads_json(num_nodes, faulty)


def serialize_dumbo_crypto_payloads_json(num_nodes: int, faulty: int) -> list[str]:
    """Generate per-node Dumbo crypto material as JSON strings.

    Delegates entirely to Rust; Python never holds native key objects.
    """
    return honey_native.generate_dumbo_crypto_payloads_json(num_nodes, faulty)


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value)


def build_crypto_params_from_payload(protocol: str, payload: dict[str, object]) -> CryptoParams:
    crypto = CryptoParams(
        sig_pk=honey_native.SigPublicKey.from_bytes(_decode_hex(str(payload["sig_pk"]))),
        sig_sk=honey_native.SigPrivateShare.from_bytes(_decode_hex(str(payload["sig_sk"]))),
        ecdsa_pks=[_decode_hex(str(value)) for value in cast(list[str], payload["ecdsa_pks"])],
        ecdsa_sk=_decode_hex(str(payload["ecdsa_sk"])),
    )
    if protocol == "dumbo":
        crypto.proof_sig_pk = honey_native.SigPublicKey.from_bytes(
            _decode_hex(str(payload["proof_sig_pk"]))
        )
        crypto.proof_sig_sk = honey_native.SigPrivateShare.from_bytes(
            _decode_hex(str(payload["proof_sig_sk"]))
        )
    return crypto


def build_crypto_params_from_json(protocol: str, payload_json: str) -> CryptoParams:
    return build_crypto_params_from_payload(
        protocol,
        cast(dict[str, object], json.loads(payload_json)),
    )
