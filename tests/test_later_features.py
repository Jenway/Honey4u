import asyncio

import pytest

from honey.crypto import pke, sig
from honey.support.messages import BaEst, Channel, ProtocolEnvelope
from honey.support.telemetry import METRICS
from network.deterministic_simulator import DeterministicNetworkSimulator
from network.hbbft_runner import run_local_honeybadger_nodes_deterministic


def test_sig_api_supports_batch_helpers(signing_keys) -> None:
    pk, sks = signing_keys
    msg = b"batch-sign-msg"

    sig_a = sks[0].sign(msg)
    sig_b = sks[1].sign(msg)
    repeated = sig.sign_many(sks[0], [msg, msg])[0]

    assert sig_a == repeated
    assert sig.verify_shares(pk, {0: sig_a}, msg) == {0: True}
    combined = sig.combine_shares(pk, {0: sig_a, 1: sig_b}, msg)
    assert sig.verify_combined(pk, combined, msg) is True
    assert sig.verify_combined(pk, combined, b"wrong-msg") is False
    assert sig.combine_share_sets(pk, [{0: sig_a, 1: sig_b}], msg) == [combined]


def test_pke_api_supports_batch_helpers(encryption_keys) -> None:
    pk, sks = encryption_keys
    messages = [b"a" * 32, b"b" * 32]
    ciphertexts = [pk.encrypt(msg) for msg in messages]

    shares0 = pke.decrypt_share_many(sks[0], ciphertexts)
    shares1 = pke.decrypt_share_many(sks[1], ciphertexts)

    assert pke.verify_shares(pk, ciphertexts[0], {0: shares0[0], 1: shares1[0]}) == {
        0: True,
        1: True,
    }
    assert (
        pke.combine_share_sets(
            pk,
            ciphertexts,
            [[shares0[0], shares1[0]], [shares0[1], shares1[1]]],
        )
        == messages
    )


def test_deterministic_simulator_is_reproducible() -> None:
    def make_trace() -> list[tuple[int, int, int, str]]:
        async def _run() -> list[tuple[int, int, int, str]]:
            simulator = DeterministicNetworkSimulator(
                2,
                seed=11,
                min_delay_steps=0,
                max_delay_steps=2,
                duplicate_predicate=lambda step, sender, recipient, envelope: (
                    recipient == 1 and step == 0
                ),
            )
            envelope = ProtocolEnvelope(
                round_id=0,
                channel=Channel.ACS_ABA,
                instance_id=0,
                message=BaEst(epoch=0, value=1),
            )
            await simulator.transports[0].send(1, envelope)
            await simulator.transports[1].send(0, envelope)
            await simulator.flush()
            return simulator.delivery_trace

        return asyncio.run(_run())

    trace_a = make_trace()
    trace_b = make_trace()

    assert trace_a == trace_b


@pytest.mark.asyncio
async def test_deterministic_simulator_drop_fault() -> None:
    simulator = DeterministicNetworkSimulator(
        2,
        seed=3,
        drop_predicate=lambda _step, sender, recipient, _envelope: sender == 0 and recipient == 1,
    )
    envelope = ProtocolEnvelope(
        round_id=0,
        channel=Channel.ACS_ABA,
        instance_id=0,
        message=BaEst(epoch=0, value=1),
    )

    await simulator.transports[0].send(1, envelope)
    await simulator.flush()

    assert simulator.delivery_trace == []
    with pytest.raises(asyncio.QueueEmpty):
        simulator.transports[1].inbound.get_nowait()


@pytest.mark.asyncio
async def test_deterministic_runner_populates_metrics() -> None:
    METRICS.reset()
    nodes = await run_local_honeybadger_nodes_deterministic(
        sid="test:deterministic",
        num_nodes=4,
        faulty=1,
        seed=7,
        max_rounds=1,
        round_timeout=5.0,
        min_delay_steps=0,
        max_delay_steps=2,
    )

    assert all(node.round == 1 for node in nodes)
    snapshot = METRICS.snapshot()
    assert any(key.startswith("hb.round.started") for key in snapshot["counters"])
    assert any(key.startswith("hb.round.seconds") for key in snapshot["timings"])
