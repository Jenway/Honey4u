from __future__ import annotations

import honey_native


def generate(players: int) -> tuple[list[bytes], list[bytes]]:
    return honey_native.ecdsa_generate_keys(players)


def public_key_from_private(priv_key: bytes) -> bytes:
    return honey_native.ecdsa_public_key_from_private(priv_key)


def sign(priv_key: bytes, msg: bytes) -> bytes:
    return honey_native.ecdsa_sign(priv_key, msg)


def verify(pub_key: bytes, msg: bytes, sig_bytes: bytes) -> bool:
    return bool(honey_native.ecdsa_verify(pub_key, msg, sig_bytes))


def verify_threshold_sigs(
    pub_keys: list[bytes],
    digest: bytes,
    sigmas: list[tuple[int, bytes]],
    threshold: int,
) -> bool:
    return bool(honey_native.ecdsa_verify_threshold_sigs(pub_keys, digest, sigmas, threshold))
