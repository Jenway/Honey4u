from __future__ import annotations

import honey_native

PublicKey = honey_native.SigPublicKey
PrivateShare = honey_native.SigPrivateShare


def generate(
    players: int, threshold: int, seed: None = None
) -> tuple[PublicKey, list[PrivateShare]]:
    _ = seed
    return honey_native.sig_generate(players, threshold)


def sign(sk: PrivateShare, msg: bytes) -> bytes:
    return sk.sign(msg)


def sign_many(sk: PrivateShare, messages: list[bytes]) -> list[bytes]:
    return [sk.sign(msg) for msg in messages]


def verify_share(pk: PublicKey, sig_bin: bytes, player_id: int, msg: bytes) -> bool:
    return bool(pk.verify_share(player_id, sig_bin, msg))


def verify_combined(pk: PublicKey, sig_bin: bytes, msg: bytes) -> bool:
    return bool(pk.verify_combined(sig_bin, msg))


def verify_shares(pk: PublicKey, sigs: dict[int, bytes], msg: bytes) -> dict[int, bool]:
    return {
        player_id: bool(pk.verify_share(player_id, sig_bin, msg))
        for player_id, sig_bin in sigs.items()
    }


def combine_shares(pk: PublicKey, sigs: dict[int, bytes], msg: bytes) -> bytes:
    return pk.combine_shares(list(sigs.items()), msg)


def combine_share_sets(
    pk: PublicKey, share_sets: list[dict[int, bytes]], msg: bytes
) -> list[bytes]:
    return [combine_shares(pk, share_map, msg) for share_map in share_sets]
