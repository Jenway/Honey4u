from typing import Any, cast

import honey_native
import pytest

from honey.consensus.honeybadger.core import CommittedBlock, HoneyBadgerBFT, PendingRoundBatch
from honey.network.transport import QueueTransport
from honey.support.messages import ProtocolEnvelope, decode_block, encode_tx, encode_tx_batch
from honey.support.params import CommonParams, CryptoParams, HBConfig
from honey.support.results import Result, failure, success


@pytest.mark.asyncio
async def test_honeybadger_run_single_round_success() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(
            self, round_id: int, batch: PendingRoundBatch
        ) -> Result[CommittedBlock]:
            del round_id
            return success(
                CommittedBlock(payload=batch.proposal_payload, tx_count=len(batch.tx_ids))
            )

    common = CommonParams(sid="test:hb", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    transport = QueueTransport()

    hb = TestHoneyBadger(
        common,
        crypto,
        transport,
        config=HBConfig(batch_size=1, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    hb.submit_tx_json_str("tx-1")

    await hb.run()

    assert hb.round == 1
    assert len(hb.round_build_latencies) == 1
    assert len(hb.round_latencies) == 1
    assert len(hb.round_wall_latencies) == 1
    assert hb.round_build_latencies[0] >= 0.0
    assert hb.round_wall_latencies[0] >= hb.round_build_latencies[0]
    assert hb._rust_tx_pool.len() == 0
    assert hb._rust_tx_pool.inflight_len() == 0


@pytest.mark.asyncio
async def test_honeybadger_run_single_round_success_with_rust_tx_pool() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(
            self, round_id: int, batch: PendingRoundBatch
        ) -> Result[CommittedBlock]:
            del round_id
            return success(
                CommittedBlock(payload=batch.proposal_payload, tx_count=len(batch.tx_ids))
            )

    common = CommonParams(sid="test:hb:rust", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    transport = QueueTransport()

    hb = TestHoneyBadger(
        common,
        crypto,
        transport,
        config=HBConfig(
            batch_size=1,
            max_rounds=1,
            round_timeout=1.0,
            log_level="CRITICAL",
        ),
    )

    hb.submit_tx_json_str("tx-1")

    await hb.run()

    assert hb.round == 1
    assert len(hb.round_build_latencies) == 1
    assert len(hb.round_latencies) == 1
    assert len(hb.round_wall_latencies) == 1
    assert hb.round_wall_latencies[0] >= hb.round_build_latencies[0]
    assert hb._rust_tx_pool.len() == 0
    assert hb._rust_tx_pool.inflight_len() == 0


def test_honeybadger_merge_block_batches_is_deterministic() -> None:
    block = (
        encode_tx_batch([b'"tx-2"', b'"tx-1"', b'"tx-1"']),
        encode_tx_batch([b'{"id":2}', b'{"id":1}', b'{"id":2}', b'"tx-3"']),
        encode_tx_batch([b'{"id":1}', b'"tx-2"']),
    )

    merged = HoneyBadgerBFT._merge_block_batches(block)

    assert merged.tx_count == 5
    assert decode_block(merged.payload) == ["tx-2", "tx-1", {"id": 2}, {"id": 1}, "tx-3"]


@pytest.mark.asyncio
async def test_honeybadger_requeues_batch_after_round_failure() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(
            self, round_id: int, batch: PendingRoundBatch
        ) -> Result[CommittedBlock]:
            del round_id, batch
            return failure("TIMEOUT", "synthetic timeout")

    common = CommonParams(sid="test:hb", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    transport = QueueTransport()

    hb = TestHoneyBadger(
        common,
        crypto,
        transport,
        config=HBConfig(batch_size=2, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    hb.submit_tx_json_str("tx-1")
    hb.submit_tx_json_str("tx-2")

    await hb.run()

    assert hb._rust_tx_pool.len() == 2
    assert hb._rust_tx_pool.inflight_len() == 0


@pytest.mark.asyncio
async def test_honeybadger_requeues_batch_after_round_failure_with_rust_tx_pool() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(
            self, round_id: int, batch: PendingRoundBatch
        ) -> Result[CommittedBlock]:
            del round_id, batch
            return failure("TIMEOUT", "synthetic timeout")

    common = CommonParams(sid="test:hb:rust:failure", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    transport = QueueTransport()

    hb = TestHoneyBadger(
        common,
        crypto,
        transport,
        config=HBConfig(
            batch_size=2,
            max_rounds=1,
            round_timeout=1.0,
            log_level="CRITICAL",
        ),
    )

    hb.submit_tx_json_str("tx-1")
    hb.submit_tx_json_str("tx-2")

    await hb.run()

    assert hb._rust_tx_pool.len() == 2
    assert hb._rust_tx_pool.inflight_len() == 0


@pytest.mark.asyncio
async def test_honeybadger_fails_fast_when_mailbox_task_crashes() -> None:
    class FailingTransport:
        async def send(self, recipient: int, envelope: ProtocolEnvelope) -> None:
            del recipient, envelope

        async def recv(self):
            raise RuntimeError("mailbox transport failed")

    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(
            self, round_id: int, batch: PendingRoundBatch
        ) -> Result[CommittedBlock]:
            del round_id
            return success(
                CommittedBlock(payload=batch.proposal_payload, tx_count=len(batch.tx_ids))
            )

    common = CommonParams(sid="test:hb", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    hb = TestHoneyBadger(
        common,
        crypto,
        FailingTransport(),
        config=HBConfig(batch_size=1, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    hb.submit_tx_json_str("tx-1")

    with pytest.raises(RuntimeError, match="mailbox transport failed"):
        await hb.run()


def test_honeybadger_build_round_context_pre_registers_acs_channels() -> None:
    common = CommonParams(sid="test:hb", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    hb = HoneyBadgerBFT(
        common,
        crypto,
        QueueTransport(),
        config=HBConfig(batch_size=1, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    ctx = hb._build_round_context(0)

    assert len(ctx.coin_recvs) == common.N
    assert len(ctx.aba_recvs) == common.N
    assert len(ctx.rbc_recvs) == common.N
    assert ctx.router.coin_recvs is ctx.coin_recvs
    assert ctx.router.aba_recvs is ctx.aba_recvs
    assert ctx.router.rbc_recvs is ctx.rbc_recvs


def test_native_tx_pool_requeue_preserves_order() -> None:
    pool = honey_native.TxPool()
    pool.push("a", b'"a"')
    pool.push("b", b'"b"')
    pool.push("c", b'"c"')

    tx_ids, _ = pool.pop_batch(3, 0)
    assert tx_ids == ["a", "b", "c"]

    pool.drop_inflight(["a"])
    pool.requeue(["b", "c"])

    next_ids, _ = pool.pop_batch(2, 0)
    assert next_ids == ["b", "c"]


def test_native_tx_pool_resolve_delivery_requeues_undelivered_items() -> None:
    pool = honey_native.TxPool()
    pool.push("a", b'"a"')
    pool.push("b", b'"b"')
    pool.push("c", b'"c"')

    tx_ids, _ = pool.pop_batch(3, 0)
    retry_ids, delivered_ids = cast(Any, pool).resolve_delivery(
        tx_ids, encode_tx_batch([b'"a"', b'"c"'])
    )

    assert delivered_ids == ["a", "c"]
    assert retry_ids == ["b"]
    assert pool.inflight_len() == 0
    assert pool.len() == 1

    next_ids, payload = pool.pop_batch(1, 0)
    assert next_ids == ["b"]
    assert decode_block(payload) == ["b"]


def test_native_tx_pool_rejects_duplicate_ids_in_queue_and_inflight() -> None:
    pool = honey_native.TxPool()
    pool.push("a", b'"a"')

    with pytest.raises(ValueError, match="duplicate tx_id"):
        pool.push("a", b'"duplicate"')

    tx_ids, _ = pool.pop_batch(1, 0)
    assert tx_ids == ["a"]

    with pytest.raises(ValueError, match="duplicate tx_id"):
        pool.push("a", b'"duplicate"')


def test_submit_tx_bytes_accepts_canonical_payload_without_sidecar() -> None:
    common = CommonParams(sid="test:hb:bytes", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    hb = HoneyBadgerBFT(
        common,
        crypto,
        QueueTransport(),
        config=HBConfig(batch_size=1, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    hb.submit_tx_bytes(encode_tx({"id": 1}))

    tx_ids, payload = hb._rust_tx_pool.pop_batch(1, 0)
    assert tx_ids == ["0:0"]
    assert decode_block(payload) == [{"id": 1}]
