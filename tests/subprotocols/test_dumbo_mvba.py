from __future__ import annotations

import asyncio
import importlib

import pytest
from honey_acs.crypto import merkle, sig
from honey_acs.subprotocols.dumbo_mvba import (
    MVBAParams,
    PdDone,
    PdLocked,
    PdStored,
    _locked_digest,
    _pd_sid,
    _provable_dispersal,
    _stored_digest,
    dumbo_mvba,
)

dumbo_mvba_module = importlib.import_module("honey_acs.subprotocols.dumbo_mvba")


def _network_sender(
    sender: int,
    queues: list[asyncio.Queue[tuple[int, object]]],
):
    async def _send(recipient: int, message: object) -> None:
        await queues[recipient].put((sender, message))

    return _send


@pytest.mark.asyncio
async def test_dumbo_mvba_agrees_on_valid_inputs() -> None:
    n = 4
    f = 1
    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)

    recv_queues = [asyncio.Queue() for _ in range(n)]
    input_queues = [asyncio.Queue(1) for _ in range(n)]
    decide_queues = [asyncio.Queue(1) for _ in range(n)]
    values = [f"payload-{i}".encode() for i in range(n)]

    for queue, value in zip(input_queues, values, strict=True):
        queue.put_nowait(value)

    tasks: list[asyncio.Task[None]] = []
    async with asyncio.TaskGroup() as tg:
        for pid in range(n):
            params = MVBAParams(
                sid="test:mvba:all-valid",
                pid=pid,
                N=n,
                f=f,
                leader=0,
                coin_pk=coin_pk,
                coin_sk=coin_sks[pid],
                proof_pk=proof_pk,
                proof_sk=proof_sks[pid],
            )
            tasks.append(
                tg.create_task(
                    dumbo_mvba(
                        params,
                        input_queues[pid],
                        decide_queues[pid],
                        recv_queues[pid],
                        _network_sender(pid, recv_queues),
                    )
                )
            )

        results = await asyncio.wait_for(
            asyncio.gather(*(queue.get() for queue in decide_queues)),
            timeout=20.0,
        )
        assert len(set(results)) == 1
        assert results[0] in values

        await asyncio.wait_for(asyncio.gather(*tasks), timeout=20.0)


@pytest.mark.asyncio
async def test_dumbo_mvba_skips_invalid_local_value() -> None:
    n = 4
    f = 1
    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)

    recv_queues = [asyncio.Queue() for _ in range(n)]
    input_queues = [asyncio.Queue(1) for _ in range(n)]
    decide_queues = [asyncio.Queue(1) for _ in range(n)]
    values = [b"good-0", b"good-1", b"bad-2", b"good-3"]

    for queue, value in zip(input_queues, values, strict=True):
        queue.put_nowait(value)

    def predicate(payload):
        return payload.startswith(b"good-")

    tasks: list[asyncio.Task[None]] = []
    async with asyncio.TaskGroup() as tg:
        for pid in range(n):
            params = MVBAParams(
                sid="test:mvba:one-invalid",
                pid=pid,
                N=n,
                f=f,
                leader=0,
                coin_pk=coin_pk,
                coin_sk=coin_sks[pid],
                proof_pk=proof_pk,
                proof_sk=proof_sks[pid],
            )
            tasks.append(
                tg.create_task(
                    dumbo_mvba(
                        params,
                        input_queues[pid],
                        decide_queues[pid],
                        recv_queues[pid],
                        _network_sender(pid, recv_queues),
                        predicate=predicate,
                    )
                )
            )

        results = await asyncio.wait_for(
            asyncio.gather(*(queue.get() for queue in decide_queues)),
            timeout=20.0,
        )
        assert len(set(results)) == 1
        assert predicate(results[0]) is True

        await asyncio.wait_for(asyncio.gather(*tasks), timeout=20.0)


@pytest.mark.asyncio
async def test_provable_dispersal_skips_self_and_surplus_share_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    n = 7
    f = 2
    pid = 0
    leader = 0
    sid = "test:mvba:pd-share-prune"
    value = b"pd-share-prune"
    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)
    roothash, _stripes, _proofs = merkle.encode(value, n - 2 * f, n)
    pd_sid = _pd_sid(sid, leader)
    stored_digest = _stored_digest(pd_sid, roothash)
    locked_digest = _locked_digest(pd_sid, roothash)

    verify_calls = 0
    original_verify_share = dumbo_mvba_module.sig.verify_share

    def counting_verify_share(
        pk: sig.PublicKey,
        signature: bytes,
        sender: int,
        message: bytes,
    ) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify_share(pk, signature, sender, message)

    monkeypatch.setattr(dumbo_mvba_module.sig, "verify_share", counting_verify_share)

    receive_queue: asyncio.Queue[tuple[int, object]] = asyncio.Queue()
    event_queue: asyncio.Queue[object] = asyncio.Queue()
    proof_validity_cache: dict[tuple[bytes, bytes], bool] = {}
    held_done: PdDone | None = None

    async def send(recipient: int, message: object) -> None:
        nonlocal held_done
        if recipient != pid:
            return
        if isinstance(message, PdDone):
            held_done = message
            return
        await receive_queue.put((pid, message))

    task = asyncio.create_task(
        _provable_dispersal(
            MVBAParams(
                sid=sid,
                pid=pid,
                N=n,
                f=f,
                leader=leader,
                coin_pk=coin_pk,
                coin_sk=coin_sks[pid],
                proof_pk=proof_pk,
                proof_sk=proof_sks[pid],
            ),
            sid=sid,
            leader=leader,
            input_value=value,
            receive_queue=receive_queue,
            send=send,
            event_queue=event_queue,
            proof_validity_cache=proof_validity_cache,
        )
    )

    await asyncio.sleep(0)

    for sender in (1, 2, 3, 4):
        await receive_queue.put(
            (
                sender,
                PdStored(
                    leader=leader,
                    roothash=roothash,
                    share=proof_sks[sender].sign(stored_digest),
                ),
            )
        )
    await asyncio.sleep(0)

    for sender in (5, 6):
        await receive_queue.put(
            (
                sender,
                PdStored(
                    leader=leader,
                    roothash=roothash,
                    share=proof_sks[sender].sign(stored_digest),
                ),
            )
        )
    await asyncio.sleep(0)

    for sender in (1, 2, 3, 4):
        await receive_queue.put(
            (
                sender,
                PdLocked(
                    leader=leader,
                    roothash=roothash,
                    share=proof_sks[sender].sign(locked_digest),
                ),
            )
        )
    await asyncio.sleep(0)

    for sender in (5, 6):
        await receive_queue.put(
            (
                sender,
                PdLocked(
                    leader=leader,
                    roothash=roothash,
                    share=proof_sks[sender].sign(locked_digest),
                ),
            )
        )
    await asyncio.sleep(0)

    assert held_done is not None
    await receive_queue.put((pid, held_done))
    await asyncio.wait_for(task, timeout=1.0)

    assert verify_calls == 8
