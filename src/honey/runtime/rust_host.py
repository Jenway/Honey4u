from __future__ import annotations

import asyncio
import json
import time
from typing import Any, cast

import honey_native

from honey.consensus.dumbo.core import DumboBFT
from honey.consensus.honeybadger.core import HoneyBadgerBFT
from honey.runtime.rust_transport import create_rust_transport
from honey.support.params import CommonParams, CryptoParams, HBConfig


def _decode_hex(value: str) -> bytes:
    return bytes.fromhex(value)


def _build_crypto(protocol: str, payload: dict[str, Any]) -> CryptoParams:
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


def _seed_transactions(
    node: HoneyBadgerBFT | DumboBFT,
    *,
    pid: int,
    transactions_per_node: int,
    tx_input: str,
) -> None:
    for tx_index in range(transactions_per_node):
        tx = f"Rust hosted TX node-{pid}-tx-{tx_index}"
        submitted_at_ns = time.time_ns()
        if tx_input == "bytes":
            node.submit_tx_bytes(
                honey_native.encode_json_string(tx),
                track_latency=True,
                submitted_at_ns=submitted_at_ns,
            )
            continue
        node.submit_tx_json_str(tx, track_latency=True, submitted_at_ns=submitted_at_ns)


async def _run_protocol_node(
    *,
    protocol: str,
    sid: str,
    pid: int,
    nodes: int,
    faulty: int,
    addresses: list[tuple[str, int]],
    crypto_payload: dict[str, Any],
    config_payload: dict[str, Any],
    transactions_per_node: int,
    tx_input: str,
    start_at_ms: int | None,
) -> dict[str, Any]:
    common = CommonParams(sid=sid, pid=pid, N=nodes, f=faulty, leader=0)
    crypto = _build_crypto(protocol, crypto_payload)
    config = HBConfig(**config_payload)
    transport = create_rust_transport(pid=pid, addresses=addresses)
    node_cls = DumboBFT if protocol == "dumbo" else HoneyBadgerBFT
    node = node_cls(common, crypto, transport, config=config)
    if start_at_ms is not None:
        delay = max(0.0, start_at_ms / 1000.0 - time.time())
        if delay > 0.0:
            await asyncio.sleep(delay)
    _seed_transactions(
        node,
        pid=pid,
        transactions_per_node=transactions_per_node,
        tx_input=tx_input,
    )

    try:
        await node.run()
        return {
            "rounds": node.round,
            "delivered": node.txcnt,
            "round_build_latencies": list(node.round_build_latencies),
            "round_latencies": list(node.round_latencies),
            "round_wall_latencies": list(node.round_wall_latencies),
            "round_proposed_counts": list(node.round_proposed_counts),
            "round_delivered_counts": list(node.round_delivered_counts),
            "origin_tx_latencies": list(node.origin_tx_latencies),
            "origin_tx_latencies_by_round": [list(v) for v in node.origin_tx_latencies_by_round],
            "chain_digest": node.chain_digest,
            "ledger_path": node.ledger_path,
            "subprotocol_timings": {
                "hb.round.seconds": {
                    "sample_count": len(node.round_latencies),
                    "total_seconds": float(sum(node.round_latencies)),
                    "max_seconds": float(max(node.round_latencies, default=0.0)),
                }
            },
            "queue_peaks": {
                "raw_inbound_messages": int(transport.pending_inbound()),
                "raw_outbound_messages": int(transport.pending_outbound()),
                "transport_inbound": int(transport.pending_inbound()),
                "transport_outbound": int(transport.pending_outbound()),
                "mailbox_round_inbox": int(node.mailboxes.peak_inbox_size),
            },
            "transport_stats": transport.stats(),
        }
    finally:
        await transport.close()


def run_protocol_node(
    protocol: str,
    sid: str,
    pid: int,
    nodes: int,
    faulty: int,
    addresses_json: str,
    crypto_json: str,
    config_json: str,
    transactions_per_node: int,
    tx_input: str,
    start_at_ms: int | None = None,
) -> dict[str, Any]:
    addresses = [
        (str(host), int(port)) for host, port in cast(list[list[Any]], json.loads(addresses_json))
    ]
    crypto_payload = cast(dict[str, Any], json.loads(crypto_json))
    config_payload = cast(dict[str, Any], json.loads(config_json))
    return asyncio.run(
        _run_protocol_node(
            protocol=protocol,
            sid=sid,
            pid=pid,
            nodes=nodes,
            faulty=faulty,
            addresses=addresses,
            crypto_payload=crypto_payload,
            config_payload=config_payload,
            transactions_per_node=transactions_per_node,
            tx_input=tx_input,
            start_at_ms=start_at_ms,
        )
    )
