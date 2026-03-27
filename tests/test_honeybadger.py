import honey_native
import pytest

from honey.consensus.honeybadger.core import HoneyBadgerBFT
from honey.support.messages import ProtocolEnvelope, encode_tx_batch
from honey.support.params import CommonParams, CryptoParams, HBConfig
from honey.support.results import Result, failure, success
from network.transport import QueueTransport


@pytest.mark.asyncio
async def test_honeybadger_run_single_round_success() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(self, _r: int, tx_to_send: list[object]) -> Result[list[object]]:
            return success(list(tx_to_send))

    common = CommonParams(sid="test:hb", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    transport = QueueTransport()

    hb = TestHoneyBadger(
        common,
        crypto,
        transport,
        config=HBConfig(batch_size=1, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    hb.submit_tx("tx-1")

    await hb.run()

    assert hb.round == 1
    assert len(hb.round_build_latencies) == 1
    assert len(hb.round_latencies) == 1
    assert len(hb.round_wall_latencies) == 1
    assert hb.round_build_latencies[0] >= 0.0
    assert hb.round_wall_latencies[0] >= hb.round_build_latencies[0]
    assert list(hb.transaction_buffer) == []


@pytest.mark.asyncio
async def test_honeybadger_run_single_round_success_with_rust_tx_pool() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(self, _r: int, tx_to_send: list[object]) -> Result[list[object]]:
            return success(list(tx_to_send))

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
            use_rust_tx_pool=True,
        ),
    )

    hb.submit_tx("tx-1")

    await hb.run()

    assert hb.round == 1
    assert len(hb.round_build_latencies) == 1
    assert len(hb.round_latencies) == 1
    assert len(hb.round_wall_latencies) == 1
    assert hb.round_wall_latencies[0] >= hb.round_build_latencies[0]
    assert hb._rust_tx_pool is not None
    assert hb._rust_tx_pool.len() == 0
    assert hb._rust_tx_pool.inflight_len() == 0
    assert hb._tx_objects_by_id == {}


def test_honeybadger_merge_block_batches_is_deterministic() -> None:
    block = (
        encode_tx_batch([b'"tx-2"', b'"tx-1"', b'"tx-1"']),
        encode_tx_batch([b'{"id":2}', b'{"id":1}', b'{"id":2}', b'"tx-3"']),
        encode_tx_batch([b'{"id":1}', b'"tx-2"']),
    )

    merged = HoneyBadgerBFT._merge_block_batches(block)

    assert merged == ["tx-2", "tx-1", {"id": 2}, {"id": 1}, "tx-3"]


@pytest.mark.asyncio
async def test_honeybadger_requeues_batch_after_round_failure() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(self, _r: int, _tx_to_send: list[object]) -> Result[list[object]]:
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

    hb.submit_tx("tx-1")
    hb.submit_tx("tx-2")

    await hb.run()

    assert list(hb.transaction_buffer) == ["tx-1", "tx-2"]


@pytest.mark.asyncio
async def test_honeybadger_requeues_batch_after_round_failure_with_rust_tx_pool() -> None:
    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(self, _r: int, _tx_to_send: list[object]) -> Result[list[object]]:
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
            use_rust_tx_pool=True,
        ),
    )

    hb.submit_tx("tx-1")
    hb.submit_tx("tx-2")

    await hb.run()

    assert hb._rust_tx_pool is not None
    assert hb._rust_tx_pool.len() == 2
    assert hb._rust_tx_pool.inflight_len() == 0
    assert set(hb._tx_objects_by_id.values()) == {"tx-1", "tx-2"}


@pytest.mark.asyncio
async def test_honeybadger_fails_fast_when_mailbox_task_crashes() -> None:
    class FailingTransport:
        async def send(self, recipient: int, envelope: ProtocolEnvelope) -> None:
            del recipient, envelope

        async def recv(self):
            raise RuntimeError("mailbox transport failed")

    class TestHoneyBadger(HoneyBadgerBFT):
        async def _run_round(self, _r: int, tx_to_send: list[object]) -> Result[list[object]]:
            return success(list(tx_to_send))

    common = CommonParams(sid="test:hb", pid=0, N=4, f=1, leader=0)
    crypto = CryptoParams(sig_pk=b"sig_pk", sig_sk=b"sig_sk", enc_pk=b"enc_pk", enc_sk=b"enc_sk")
    hb = TestHoneyBadger(
        common,
        crypto,
        FailingTransport(),
        config=HBConfig(batch_size=1, max_rounds=1, round_timeout=1.0, log_level="CRITICAL"),
    )

    hb.submit_tx("tx-1")

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


def test_native_tx_pool_rejects_duplicate_ids_in_queue_and_inflight() -> None:
    pool = honey_native.TxPool()
    pool.push("a", b'"a"')

    with pytest.raises(ValueError, match="duplicate tx_id"):
        pool.push("a", b'"duplicate"')

    tx_ids, _ = pool.pop_batch(1, 0)
    assert tx_ids == ["a"]

    with pytest.raises(ValueError, match="duplicate tx_id"):
        pool.push("a", b'"duplicate"')
