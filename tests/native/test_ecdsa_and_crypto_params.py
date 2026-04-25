from __future__ import annotations

import json

import honey_native
from honey_acs.params import CryptoParams
from honey_acs.runtime.host import build_crypto_params_from_json
from honey_acs.runtime.native import NativePrbcCryptoRuntime


def test_ecdsa_api_round_trip_and_threshold_verify() -> None:
    pks, sks = honey_native.ecdsa_generate_keys(4)
    msg = b"ecdsa-message"

    sig0 = honey_native.ecdsa_sign(sks[0], msg)
    sig1 = honey_native.ecdsa_sign(sks[1], msg)
    runtime = NativePrbcCryptoRuntime(pks)

    assert honey_native.ecdsa_public_key_from_private(sks[0]) == pks[0]
    assert honey_native.ecdsa_verify(pks[0], msg, sig0) is True
    assert honey_native.ecdsa_verify(pks[1], msg, sig0) is False
    assert honey_native.ecdsa_verify_threshold_sigs(pks, msg, [(0, sig0), (1, sig1)], 2) is True
    assert honey_native.ecdsa_verify_threshold_sigs(pks, msg, [(0, sig0)], 2) is False
    assert runtime.verify_ready_proof(msg, ((0, sig0), (1, sig1)), threshold=2) is True
    assert runtime.verify_ready_proof(msg, ((0, sig0), (0, sig0)), threshold=2) is False


def test_native_generate_hb_crypto_payloads_json_produces_valid_material() -> None:
    """honey_native.generate_hb_crypto_payloads_json returns well-formed per-node JSON payloads
    that can be round-tripped through build_crypto_params_from_json."""
    N, f = 4, 1
    payloads = honey_native.generate_hb_crypto_payloads_json(N, f)

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
        assert crypto.runtime.coin.players == N
        assert crypto.runtime.coin.threshold == f + 1
        assert crypto.runtime.prbc.players == N
        assert crypto.runtime.proof is None


def test_crypto_params_requires_runtime() -> None:
    payload = honey_native.generate_hb_crypto_payloads_json(4, 1)[0]
    runtime = build_crypto_params_from_json("hb", payload).runtime
    params = CryptoParams(runtime=runtime)

    assert params.runtime is runtime
