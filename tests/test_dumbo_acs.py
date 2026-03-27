from __future__ import annotations

import asyncio

import pytest

from honey.acs.dumbo_acs import DumboACSParams, dumbo_acs
from honey.crypto import ecdsa, sig


def _network_sender(
    sender: int,
    queues: list[asyncio.Queue[tuple[int, object]]],
):
    async def _send(recipient: int, message: object) -> None:
        await queues[recipient].put((sender, message))

    return _send


@pytest.mark.asyncio
async def test_dumbo_acs_agrees_on_prbc_selected_values() -> None:
    n = 4
    f = 1
    coin_pk, coin_sks = sig.generate(n, f + 1)
    proof_pk, proof_sks = sig.generate(n, n - f)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)

    recv_queues = [asyncio.Queue() for _ in range(n)]
    input_queues = [asyncio.Queue(1) for _ in range(n)]
    decide_queues = [asyncio.Queue(1) for _ in range(n)]
    values = [f"batch-{i}".encode() for i in range(n)]

    for queue, value in zip(input_queues, values, strict=True):
        queue.put_nowait(value)

    tasks: list[asyncio.Task[None]] = []
    async with asyncio.TaskGroup() as tg:
        for pid in range(n):
            tasks.append(
                tg.create_task(
                    dumbo_acs(
                        DumboACSParams(
                            sid="test:dumbo-acs:basic",
                            pid=pid,
                            N=n,
                            f=f,
                            leader=0,
                            coin_pk=coin_pk,
                            coin_sk=coin_sks[pid],
                            proof_pk=proof_pk,
                            proof_sk=proof_sks[pid],
                            ecdsa_pks=ecdsa_pks,
                            ecdsa_sk=ecdsa_sks[pid],
                        ),
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
        decided = results[0]
        assert sum(value is not None for value in decided) >= n - f
        assert all(value is None or value in values for value in decided)

        await asyncio.wait_for(asyncio.gather(*tasks), timeout=20.0)
