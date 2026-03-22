"""Threshold Public Key Encryption (TPKE).

Thin wrappers around the Rust native module. This module exposes
plain key-material dataclasses and module-level functions.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

try:
    import honey_native
except Exception as err:
    print(err)
    exit(-1)


@dataclass
class EncPublicMaterial:
    players: int
    threshold: int
    params_bin: bytes
    mpk_bin: bytes


@dataclass
class EncPrivateMaterial:
    player_id: int  # 0-based
    params_bin: bytes
    mpk_bin: bytes
    share_bin: bytes


def dealer(players: int, threshold: int) -> tuple[EncPublicMaterial, list[EncPrivateMaterial]]:
    params_bin, mpk_bin, shares_bin = honey_native.pke_generate_keys(players, threshold)
    pub = EncPublicMaterial(players, threshold, params_bin, mpk_bin)
    priv = [
        EncPrivateMaterial(
            player_id=i,
            params_bin=params_bin,
            mpk_bin=mpk_bin,
            share_bin=shares_bin[i],
        )
        for i in range(players)
    ]
    return pub, priv


def pke_encrypt(pk: EncPublicMaterial, msg32: bytes) -> bytes:
    if len(msg32) != 32:
        raise ValueError("message for TPKE must be 32 bytes")
    return honey_native.pke_encrypt(pk.mpk_bin, msg32)


def pke_verify_ciphertext(pk: EncPublicMaterial, ct_bin: bytes) -> bool:
    return honey_native.pke_verify_ciphertext(pk.params_bin, ct_bin)


def pke_decrypt_share(sk: EncPrivateMaterial, ct_bin: bytes) -> bytes:
    if not pke_verify_ciphertext(EncPublicMaterial(0, 0, sk.params_bin, sk.mpk_bin), ct_bin):
        raise ValueError("invalid ciphertext")
    return honey_native.pke_partial_open(sk.share_bin, ct_bin)


def pke_combine_shares(pk: EncPublicMaterial, ct_bin: bytes, shares: list[bytes]) -> bytes:
    return honey_native.pke_open(pk.params_bin, ct_bin, shares)


def encrypt(key: bytes, raw: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")
    return honey_native.aes_encrypt(key, raw)


def decrypt(key: bytes, enc: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")
    return honey_native.aes_decrypt(key, enc)


# Backward compatibility for callers doing `from crypto.threshenc import tpke`.
tpke = sys.modules[__name__]
