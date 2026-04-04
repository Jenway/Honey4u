from __future__ import annotations

import importlib
import importlib.util
import logging
from dataclasses import dataclass
from typing import Any, cast

import honey_native
import pytest

from honey.consensus.dumbo.core import DumboBFT
from honey.network.transport import QueueTransport
from honey.runtime.node_mailbox import NodeMailboxRouter
from honey.support.params import CommonParams, CryptoParams, HBConfig

node_embed = importlib.import_module("honey.node_embed")


def test_runtime_modules_live_under_honey_namespace() -> None:
    assert importlib.util.find_spec("honey.network.transport") is not None
    assert importlib.util.find_spec("honey.network.hbbft_runner") is not None
    assert importlib.util.find_spec("network") is None


def test_common_params_raise_value_error_for_invalid_topology() -> None:
    with pytest.raises(ValueError, match=r"3f\+1"):
        CommonParams(sid="invalid:n", pid=0, N=3, f=1, leader=0)

    with pytest.raises(ValueError, match=r"pid=4"):
        CommonParams(sid="invalid:pid", pid=4, N=4, f=1, leader=0)

    with pytest.raises(ValueError, match=r"leader=4"):
        CommonParams(sid="invalid:leader", pid=0, N=4, f=1, leader=4)


def test_crypto_params_raise_value_error_for_incomplete_optional_material() -> None:
    with pytest.raises(ValueError, match="ECDSA public keys"):
        CryptoParams(
            sig_pk=b"sig_pk",
            sig_sk=b"sig_sk",
            enc_pk=b"enc_pk",
            enc_sk=b"enc_sk",
            ecdsa_sk=b"ecdsa_sk",
        )

    with pytest.raises(ValueError, match="proof_sig_sk"):
        CryptoParams(
            sig_pk=b"sig_pk",
            sig_sk=b"sig_sk",
            enc_pk=b"enc_pk",
            enc_sk=b"enc_sk",
            proof_sig_pk=b"proof_pk",
        )


def test_dumbo_mailbox_uses_dedicated_logger() -> None:
    dumbo = DumboBFT(
        CommonParams(sid="test:dumbo:logger", pid=0, N=4, f=1, leader=0),
        CryptoParams(
            sig_pk=b"sig_pk",
            sig_sk=b"sig_sk",
            enc_pk=b"enc_pk",
            enc_sk=b"enc_sk",
            ecdsa_pks=[b"pk-0", b"pk-1", b"pk-2", b"pk-3"],
            ecdsa_sk=b"sk-0",
            proof_sig_pk=b"proof_pk",
            proof_sig_sk=b"proof_sk",
        ),
        QueueTransport(),
        config=HBConfig(max_rounds=1, log_level="CRITICAL"),
    )

    assert dumbo.logger.logger.name == "honey.dumbo"
    assert dumbo.mailboxes._logger.logger.name == "honey.dumbo"


def test_node_mailbox_router_bounds_closed_round_state() -> None:
    router = NodeMailboxRouter(
        QueueTransport(),
        logging.LoggerAdapter(logging.getLogger("test.mailbox"), extra={"node": 0}),
    )
    router.inbox(0)
    router.inbox(1)
    router.peak_round_inbox_sizes[0] = 3
    router.peak_round_inbox_sizes[1] = 5

    router.close_round(0)

    stats = router.stats()
    assert stats["closed_through"] == 0
    assert stats["active_rounds"] == 1
    assert 0 not in router.peak_round_inbox_sizes
    assert 1 in router.peak_round_inbox_sizes

    with pytest.raises(ValueError, match="already closed"):
        router.inbox(0)

    router.close_round(1)
    assert router.stats()["active_rounds"] == 0
    assert router.peak_round_inbox_sizes == {}


@dataclass
class _DummyTransport:
    async def send(self, recipient: int, envelope: object) -> None:
        del recipient, envelope

    async def recv(self) -> tuple[int, object]:
        return (0, object())


def test_plan_hb_node_rejects_transport_without_recv() -> None:
    class SendOnlyTransport:
        async def send(self, recipient: int, envelope: object) -> None:
            del recipient, envelope

    with pytest.raises(ValueError, match="transport_handle must define callable recv"):
        node_embed.plan_hb_node(
            common={"sid": "s", "pid": 0, "N": 4, "f": 1, "leader": 0},
            crypto=None,
            transport_handle=SendOnlyTransport(),
            commit_sink=object(),
            config={"max_rounds": 1},
        )


def test_plan_dumbo_node_builds_protocol_specific_plan() -> None:
    plan = node_embed.plan_dumbo_node(
        common={"sid": "s", "pid": 0, "N": 4, "f": 1, "leader": 0},
        crypto=None,
        transport_handle=_DummyTransport(),
        commit_sink=object(),
        config={"max_rounds": 2},
    )

    assert plan.protocol == "dumbo"
    assert plan.max_rounds == 2
    assert plan.transport_handle_type == "_DummyTransport"


@pytest.mark.asyncio
async def test_run_hb_node_emits_commits_via_commit_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeLedger:
        def append_block(
            self,
            *,
            round_id: int,
            block_payload: bytes,
            tx_count: int,
            delivered_at_ns: int,
        ) -> object:
            del delivered_at_ns
            return {
                "round_id": round_id,
                "block_payload": block_payload,
                "tx_count": tx_count,
            }

    class FakeHBNode:
        def __init__(
            self,
            common_params: CommonParams,
            crypto_params: Any,
            transport: _DummyTransport,
            config: HBConfig | None = None,
        ) -> None:
            del common_params, crypto_params, transport, config
            self._ledger = FakeLedger()

        async def run(self) -> None:
            self._ledger.append_block(
                round_id=0,
                block_payload=b"block-0",
                tx_count=2,
                delivered_at_ns=123,
            )

    class FakeSink:
        def __init__(self) -> None:
            self.records: list[tuple[int, bytes, int]] = []

        def commit(self, *, round_id: int, payload: bytes, tx_count: int) -> None:
            self.records.append((round_id, payload, tx_count))

    monkeypatch.setattr(node_embed, "HoneyBadgerBFT", FakeHBNode)
    sink = FakeSink()
    await node_embed.run_hb_node(
        common={"sid": "s", "pid": 0, "N": 4, "f": 1, "leader": 0},
        crypto=cast(Any, object()),
        transport_handle=_DummyTransport(),
        commit_sink=sink,
        config={"max_rounds": 1},
    )

    assert sink.records == [(0, b"block-0", 2)]


def test_embedded_transport_handle_exposes_wakeup_seq() -> None:
    if "EmbeddedTransportHandle" not in honey_native.__dict__:
        pytest.skip("EmbeddedTransportHandle export not available in current built extension")
    transport_cls = cast(Any, honey_native.__dict__["EmbeddedTransportHandle"])
    transport = transport_cls(0, [("127.0.0.1", 35301)])
    try:
        assert isinstance(transport.wakeup_seq(), int)
    finally:
        transport.close()
