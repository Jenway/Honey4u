from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

import honey_native

from honey.crypto import pke
from honey.protocol.messages import encode_tx, encode_tx_batch
from honey.host.crypto_material import serialize_hb_crypto_payloads_json
from honey.runtime.runners import _build_honey_node_binary


def _send_worker_command(
    process: subprocess.Popen[str],
    payload: dict[str, Any],
) -> dict[str, Any]:
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()
    response = process.stdout.readline()
    assert response, "hb-worker produced no response"
    return json.loads(response)


def test_hb_worker_exposes_stats_and_tpke_local_bundle() -> None:
    payloads = serialize_hb_crypto_payloads_json(4, 1)
    worker_payload = payloads[0]
    binary = _build_honey_node_binary()

    process = subprocess.Popen(
        [
            str(binary),
            "hb-worker",
            "--pid",
            "0",
            "--nodes",
            "4",
            "--faulty",
            "1",
            "--acs-protocol",
            "hb",
            "--acs-crypto-json",
            worker_payload,
            "--hb-crypto-json",
            worker_payload,
            "--config-json",
            "{}",
        ],
        cwd=Path.cwd(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 5.0
        while True:
            stats_response = _send_worker_command(process, {"kind": "stats"})
            if stats_response["stats"]["worker_running"] is True:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        assert stats_response["ok"] is True
        assert stats_response["stats"]["pid"] == 0
        assert stats_response["stats"]["worker_running"] is True

        decoded = json.loads(worker_payload)
        public_key = honey_native.PkePublicKey.from_bytes(bytes.fromhex(decoded["enc_pk"]))
        encrypted_batch = pke.seal_encrypted_batch(
            public_key,
            encode_tx_batch([encode_tx("worker-tx-0")]),
        )

        bundle_response = _send_worker_command(
            process,
            {
                "kind": "tpke_local_bundle",
                "selected_batches_hex": [encrypted_batch.hex()],
            },
        )
        assert bundle_response["ok"] is True
        assert len(bundle_response["bundle_hex"]) == 1
        assert bundle_response["bundle_hex"][0]
        assert bundle_response["elapsed_seconds"] >= 0.0

        shutdown_response = _send_worker_command(process, {"kind": "shutdown"})
        assert shutdown_response["ok"] is True
    finally:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
        if process.returncode not in (0, None):
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise AssertionError(f"hb-worker exited with {process.returncode}: {stderr}")
