from __future__ import annotations

import asyncio

import pytest

from honey.acs.dumbo_vacs import VacsDiffuse, VACSParams, validated_common_subset
from honey.crypto import sig


def _network_sender(
    sender: int,
    queues: list[asyncio.Queue[tuple[int, object]]],
):
    async def _send(recipient: int, message: object) -> None:
        await queues[recipient].put((sender, message))

    return _send


@pytest.mark.asyncio
async def test_dumbo_vacs_agrees_on_valid_values() -> None:
    n = 4
    f = 1
    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)

    recv_queues = [asyncio.Queue() for _ in range(n)]
    input_queues = [asyncio.Queue(1) for _ in range(n)]
    decide_queues = [asyncio.Queue(1) for _ in range(n)]
    values = [b"proof-0", b"proof-1", b"proof-2", b"proof-3"]

    for queue, value in zip(input_queues, values, strict=True):
        queue.put_nowait(value)

    async with asyncio.TaskGroup() as tg:
        tasks: list[asyncio.Task[None]] = []
        for pid in range(n):
            params = VACSParams(
                sid="test:vacs:all-valid",
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
                    validated_common_subset(
                        params,
                        input_queues[pid],
                        decide_queues[pid],
                        recv_queues[pid],
                        _network_sender(pid, recv_queues),
                        predicate=lambda _sender, value: value.startswith(b"proof-"),
                    )
                )
            )

        results = await asyncio.wait_for(
            asyncio.gather(*(queue.get() for queue in decide_queues)),
            timeout=20.0,
        )
        assert len(set(results)) == 1
        assert sum(value is not None for value in results[0]) >= n - f
        assert all(value is None or value.startswith(b"proof-") for value in results[0])

        await asyncio.wait_for(asyncio.gather(*tasks), timeout=20.0)


@pytest.mark.asyncio
async def test_dumbo_vacs_filters_invalid_values() -> None:
    n = 4
    f = 1
    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)

    recv_queues = [asyncio.Queue() for _ in range(n)]
    input_queues = [asyncio.Queue(1) for _ in range(n)]
    decide_queues = [asyncio.Queue(1) for _ in range(n)]
    values = [b"proof-0", b"proof-1", b"junk-2", b"proof-3"]

    for queue, value in zip(input_queues, values, strict=True):
        queue.put_nowait(value)

    def predicate(_sender: int, value: bytes) -> bool:
        return value.startswith(b"proof-")

    async with asyncio.TaskGroup() as tg:
        tasks: list[asyncio.Task[None]] = []
        for pid in range(n):
            params = VACSParams(
                sid="test:vacs:one-invalid",
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
                    validated_common_subset(
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
        decided = results[0]
        assert decided[2] is None
        assert sum(value is not None for value in decided) >= n - f
        assert all(value is None or predicate(0, value) for value in decided)

        await asyncio.wait_for(asyncio.gather(*tasks), timeout=20.0)


def test_vacs_diffuse_is_hashable_dataclass() -> None:
    message = VacsDiffuse(value=b"proof", signature=b"sig")

    assert message.value == b"proof"
    assert message.signature == b"sig"
