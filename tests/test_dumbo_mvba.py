from __future__ import annotations

import asyncio

import pytest

from honey.crypto import sig
from honey.subprotocols.dumbo_mvba import MVBAParams, dumbo_mvba


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
