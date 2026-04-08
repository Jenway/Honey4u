from __future__ import annotations

import json

from honey_acs.crypto import ecdsa
from honey_acs.host_crypto import build_crypto_params_from_json, serialize_hb_crypto_payloads_json
from honey_acs.params import CryptoParams


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
    assert ecdsa.verify_threshold_sigs_strict(pks, msg, [(0, sig0), (1, sig1)], threshold=2) is True
    assert (
        ecdsa.verify_threshold_sigs_strict(pks, msg, [(0, sig0), (0, sig0)], threshold=2) is False
    )


def test_generate_hb_crypto_payloads_json_produces_valid_material() -> None:
    """generate_hb_crypto_payloads_json returns well-formed per-node JSON payloads
    that can be round-tripped through build_crypto_params_from_json."""
    N, f = 4, 1
    payloads = serialize_hb_crypto_payloads_json(N, f)

    assert len(payloads) == N

    for pid, raw in enumerate(payloads):
        payload = json.loads(raw)

        # All expected keys are present
        for key in ("sig_pk", "sig_sk", "enc_pk", "enc_sk", "ecdsa_pks", "ecdsa_sk"):
            assert key in payload, f"pid={pid}: missing key {key!r}"

        # ECDSA key sizes match the k256 compressed point format
        assert len(payload["ecdsa_pks"]) == N
        assert all(len(bytes.fromhex(pk)) == 33 for pk in payload["ecdsa_pks"])
        assert len(bytes.fromhex(payload["ecdsa_sk"])) == 32

        # Round-trip: JSON → CryptoParams succeeds without error
        crypto = build_crypto_params_from_json("hb", raw)
        assert crypto.sig_pk is not None
        assert crypto.sig_sk is not None
        assert len(crypto.ecdsa_pks) == N
        assert crypto.ecdsa_sk is not None


def test_crypto_params_accepts_optional_ecdsa_material() -> None:
    pks, sks = ecdsa.generate(4)

    params = CryptoParams(
        sig_pk=b"sig_pk",
        sig_sk=b"sig_sk",
        ecdsa_pks=pks,
        ecdsa_sk=sks[0],
    )

    assert params.ecdsa_pks == pks
    assert params.ecdsa_sk == sks[0]
