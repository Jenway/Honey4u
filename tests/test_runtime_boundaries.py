from __future__ import annotations

import importlib.util
import logging

import pytest

from honey.consensus.dumbo.core import DumboBFT
from honey.network.transport import QueueTransport
from honey.runtime.node_mailbox import NodeMailboxRouter
from honey.support.params import CommonParams, CryptoParams, HBConfig


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
