from __future__ import annotations

from honey.crypto import ecdsa
from honey.support.params import CryptoParams
from network.crypto_material import build_materials


def test_ecdsa_api_round_trip_and_threshold_verify() -> None:
    pks, sks = ecdsa.generate(4)
    msg = b"ecdsa-message"

    sig0 = ecdsa.sign(sks[0], msg)
    sig1 = ecdsa.sign(sks[1], msg)

    assert ecdsa.public_key_from_private(sks[0]) == pks[0]
    assert ecdsa.verify(pks[0], msg, sig0) is True
    assert ecdsa.verify(pks[1], msg, sig0) is False
    assert ecdsa.verify_threshold_sigs(pks, msg, [(0, sig0), (1, sig1)], threshold=2) is True
    assert ecdsa.verify_threshold_sigs(pks, msg, [(0, sig0)], threshold=2) is False


def test_build_materials_returns_ecdsa_keys() -> None:
    sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = build_materials(4, 1)

    assert sig_pk is not None
    assert enc_pk is not None
    assert len(sig_shares) == 4
    assert len(enc_shares) == 4
    assert len(ecdsa_pks) == 4
    assert len(ecdsa_sks) == 4
    assert all(len(pub) == 33 for pub in ecdsa_pks)
    assert all(len(sk) == 32 for sk in ecdsa_sks)


def test_crypto_params_accepts_optional_ecdsa_material() -> None:
    pks, sks = ecdsa.generate(4)

    params = CryptoParams(
        sig_pk=b"sig_pk",
        sig_sk=b"sig_sk",
        enc_pk=b"enc_pk",
        enc_sk=b"enc_sk",
        ecdsa_pks=pks,
        ecdsa_sk=sks[0],
    )

    assert params.ecdsa_pks == pks
    assert params.ecdsa_sk == sks[0]
