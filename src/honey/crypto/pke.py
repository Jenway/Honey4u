from __future__ import annotations

import honey_native

BatchDecryptor = honey_native.PkeBatchDecryptor
PublicKey = honey_native.PkePublicKey
PrivateShare = honey_native.PkePrivateShare


def generate(players: int, threshold: int) -> tuple[PublicKey, list[PrivateShare]]:
    return honey_native.pke_generate(players, threshold)


def verify_share(pk: PublicKey, ct_bin: bytes, share_bin: bytes, player_id: int) -> bool:
    return bool(pk.verify_share(player_id, ct_bin, share_bin))


def verify_shares(pk: PublicKey, ct_bin: bytes, shares: dict[int, bytes]) -> dict[int, bool]:
    return {
        player_id: verify_share(pk, ct_bin, share_bin, player_id)
        for player_id, share_bin in shares.items()
    }


def decrypt_share_many(sk: PrivateShare, ciphertexts: list[bytes]) -> list[bytes]:
    return [sk.decrypt_share(ct_bin) for ct_bin in ciphertexts]


def combine_share_sets(
    pk: PublicKey, ciphertexts: list[bytes], share_sets: list[list[bytes]]
) -> list[bytes]:
    return [
        pk.combine_shares(ct_bin, shares)
        for ct_bin, shares in zip(ciphertexts, share_sets, strict=True)
    ]


def encrypt(key: bytes, raw: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")
    return honey_native.aes_encrypt(key, raw)


def decrypt(key: bytes, enc: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")
    return honey_native.aes_decrypt(key, enc)


def seal_encrypted_batch(pk: PublicKey, payload: bytes) -> bytes:
    return honey_native.seal_encrypted_batch(pk, payload)
