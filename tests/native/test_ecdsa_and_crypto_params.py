from __future__ import annotations

import honey_native


def test_ecdsa_api_round_trip_and_threshold_verify() -> None:
    pks, sks = honey_native.ecdsa_generate_keys(4)
    msg = b"ecdsa-message"

    sig0 = honey_native.ecdsa_sign(sks[0], msg)
    sig1 = honey_native.ecdsa_sign(sks[1], msg)
    runtime = honey_native.PrbcCryptoRuntime(pks)

    assert honey_native.ecdsa_public_key_from_private(sks[0]) == pks[0]
    assert honey_native.ecdsa_verify(pks[0], msg, sig0) is True
    assert honey_native.ecdsa_verify(pks[1], msg, sig0) is False
    assert honey_native.ecdsa_verify_threshold_sigs(pks, msg, [(0, sig0), (1, sig1)], 2) is True
    assert honey_native.ecdsa_verify_threshold_sigs(pks, msg, [(0, sig0)], 2) is False
    assert runtime.verify_ready_proof(msg, ((0, sig0), (1, sig1)), threshold=2) is True
    assert runtime.verify_ready_proof(msg, ((0, sig0), (0, sig0)), threshold=2) is False
