from __future__ import annotations

import json
from typing import cast

import honey_native
from honey_shared.crypto import ecdsa, pke, sig
from honey_shared.params import CryptoParams


def build_materials(num_nodes: int, faulty: int):
    sig_pk, sig_shares = sig.generate(num_nodes, faulty + 1)
    enc_pk, enc_shares = pke.generate(num_nodes, faulty + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(num_nodes)
    return sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks


def build_dumbo_materials(num_nodes: int, faulty: int):
    coin_pk, coin_shares = sig.generate(num_nodes, faulty + 1)
    proof_pk, proof_shares = sig.generate(num_nodes, num_nodes - faulty)
    enc_pk, enc_shares = pke.generate(num_nodes, faulty + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(num_nodes)
    return coin_pk, coin_shares, proof_pk, proof_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks


def serialize_hb_crypto_payloads(num_nodes: int, faulty: int) -> list[dict[str, object]]:
    sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = build_materials(
        num_nodes, faulty
    )
    payloads: list[dict[str, object]] = []
    for pid in range(num_nodes):
        payloads.append(
            {
                "sig_pk": sig_pk.to_bytes().hex(),
                "sig_sk": sig_shares[pid].to_bytes().hex(),
                "enc_pk": enc_pk.to_bytes().hex(),
                "enc_sk": enc_shares[pid].to_bytes().hex(),
                "ecdsa_pks": [pk.hex() for pk in ecdsa_pks],
                "ecdsa_sk": ecdsa_sks[pid].hex(),
            }
        )
    return payloads


def serialize_dumbo_crypto_payloads(num_nodes: int, faulty: int) -> list[dict[str, object]]:
    coin_pk, coin_shares, proof_pk, proof_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = (
        build_dumbo_materials(num_nodes, faulty)
    )
    payloads: list[dict[str, object]] = []
    for pid in range(num_nodes):
        payloads.append(
            {
                "sig_pk": coin_pk.to_bytes().hex(),
                "sig_sk": coin_shares[pid].to_bytes().hex(),
                "enc_pk": enc_pk.to_bytes().hex(),
                "enc_sk": enc_shares[pid].to_bytes().hex(),
                "ecdsa_pks": [pk.hex() for pk in ecdsa_pks],
                "ecdsa_sk": ecdsa_sks[pid].hex(),
                "proof_sig_pk": proof_pk.to_bytes().hex(),
                "proof_sig_sk": proof_shares[pid].to_bytes().hex(),
            }
        )
    return payloads


def serialize_hb_crypto_payloads_json(num_nodes: int, faulty: int) -> list[str]:
    return [
        json.dumps(payload, separators=(",", ":"))
        for payload in serialize_hb_crypto_payloads(num_nodes, faulty)
    ]


def serialize_dumbo_crypto_payloads_json(num_nodes: int, faulty: int) -> list[str]:
    return [
        json.dumps(payload, separators=(",", ":"))
        for payload in serialize_dumbo_crypto_payloads(num_nodes, faulty)
    ]


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value)


def build_crypto_params_from_payload(protocol: str, payload: dict[str, object]) -> CryptoParams:
    crypto = CryptoParams(
        sig_pk=honey_native.SigPublicKey.from_bytes(_decode_hex(str(payload["sig_pk"]))),
        sig_sk=honey_native.SigPrivateShare.from_bytes(_decode_hex(str(payload["sig_sk"]))),
        enc_pk=honey_native.PkePublicKey.from_bytes(_decode_hex(str(payload["enc_pk"]))),
        enc_sk=honey_native.PkePrivateShare.from_bytes(_decode_hex(str(payload["enc_sk"]))),
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
