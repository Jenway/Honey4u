from __future__ import annotations

import asyncio
import json

import pytest

from honey.consensus.dumbo.core import DumboBFT
from honey.consensus.honeybadger.core import CommittedBlock
from honey.crypto import ecdsa, pke, sig
from honey.network.transport import QueueTransport
from honey.support.messages import decode_block, encode_tx
from honey.support.params import CommonParams, CryptoParams, HBConfig
from honey.support.results import Success


class RecordingDumbo(DumboBFT):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.delivered_blocks: list[list[object]] = []

    def _apply_round_result(self, round_id, batch, round_result):
        super()._apply_round_result(round_id, batch, round_result)
        if isinstance(round_result, Success) and isinstance(round_result.value, CommittedBlock):
            self.delivered_blocks.append(decode_block(round_result.value.payload))


@pytest.mark.asyncio
async def test_dumbo_run_single_round_queue_transport() -> None:
    n = 4
    f = 1
    sid = "test:dumbo:queue"

    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)
    enc_pk, enc_sks = pke.generate(n, f + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)

    transports = [QueueTransport() for _ in range(n)]
    nodes: list[RecordingDumbo] = []

    for pid in range(n):
        common = CommonParams(sid=sid, pid=pid, N=n, f=f, leader=0)
        crypto = CryptoParams(
            sig_pk=coin_pk,
            sig_sk=coin_sks[pid],
            enc_pk=enc_pk,
            enc_sk=enc_sks[pid],
            ecdsa_pks=ecdsa_pks,
            ecdsa_sk=ecdsa_sks[pid],
            proof_sig_pk=proof_pk,
            proof_sig_sk=proof_sks[pid],
        )
        config = HBConfig(batch_size=1, max_rounds=1, round_timeout=20.0, log_level="ERROR")
        node = RecordingDumbo(common, crypto, transports[pid], config=config)
        node.submit_tx_bytes(encode_tx({"node": pid, "tx": 0}))
        nodes.append(node)

    async def router() -> None:
        while True:
            pending = []
            for pid in range(n):
                try:
                    while True:
                        outbound = transports[pid].outbound.get_nowait()
                        pending.append((pid, outbound.recipient, outbound.envelope))
                except asyncio.QueueEmpty:
                    pass
            for sender, recipient, envelope in pending:
                transports[recipient].deliver_nowait(sender, envelope)
            await asyncio.sleep(0.001)

    router_task = asyncio.create_task(router())
    try:
        await asyncio.wait_for(asyncio.gather(*(node.run() for node in nodes)), timeout=30.0)
    finally:
        router_task.cancel()
        try:
            await router_task
        except asyncio.CancelledError:
            pass

    assert all(node.round == 1 for node in nodes)
    assert all(node.delivered_blocks for node in nodes)
    blocks = [json.dumps(node.delivered_blocks[0], sort_keys=True) for node in nodes]
    assert len(set(blocks)) == 1
    decided = json.loads(blocks[0])
    assert n - f <= len(decided) <= n


@pytest.mark.asyncio
async def test_dumbo_pool_reuse_caches_and_consumes_carryover_entries() -> None:
    n = 4
    f = 1
    sid = "test:dumbo:pool:queue"

    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)
    enc_pk, enc_sks = pke.generate(n, f + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)

    transports = [QueueTransport() for _ in range(n)]
    nodes: list[RecordingDumbo] = []

    for pid in range(n):
        common = CommonParams(sid=sid, pid=pid, N=n, f=f, leader=0)
        crypto = CryptoParams(
            sig_pk=coin_pk,
            sig_sk=coin_sks[pid],
            enc_pk=enc_pk,
            enc_sk=enc_sks[pid],
            ecdsa_pks=ecdsa_pks,
            ecdsa_sk=ecdsa_sks[pid],
            proof_sig_pk=proof_pk,
            proof_sig_sk=proof_sks[pid],
        )
        config = HBConfig(
            batch_size=1,
            max_rounds=6,
            round_timeout=20.0,
            log_level="ERROR",
            enable_broadcast_pool_reuse=True,
            enable_pool_reference_proposals=True,
            enable_pool_fetch_fallback=True,
            pool_grace_ms=50,
        )
        node = RecordingDumbo(common, crypto, transports[pid], config=config)
        for tx_index in range(6):
            node.submit_tx_bytes(encode_tx({"node": pid, "tx": tx_index}))
        nodes.append(node)

    async def router() -> None:
        while True:
            pending = []
            for pid in range(n):
                try:
                    while True:
                        outbound = transports[pid].outbound.get_nowait()
                        pending.append((pid, outbound.recipient, outbound.envelope))
                except asyncio.QueueEmpty:
                    pass
            for sender, recipient, envelope in pending:
                transports[recipient].deliver_nowait(sender, envelope)
            await asyncio.sleep(0.001)

    router_task = asyncio.create_task(router())
    try:
        await asyncio.wait_for(asyncio.gather(*(node.run() for node in nodes)), timeout=60.0)
    finally:
        router_task.cancel()
        try:
            await router_task
        except asyncio.CancelledError:
            pass

    assert all(node.round == 6 for node in nodes)
    assert all(node.delivered_blocks for node in nodes)
    assert any(node.mempool.stats().get("reusable", 0) > 0 for node in nodes)
    assert any(node.mempool.stats().get("consumed", 0) > 0 for node in nodes)
