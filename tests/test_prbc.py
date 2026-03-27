from __future__ import annotations

import asyncio

import pytest

from honey.crypto import ecdsa
from honey.subprotocols.provable_reliable_broadcast import (
    PRBCParams,
    PrbcProof,
    provable_reliable_broadcast,
    validate_prbc_proof,
)


def _network_sender(
    sender: int,
    queues: list[asyncio.Queue[tuple[int, object]]],
):
    async def _send(recipient: int, message: object) -> None:
        await queues[recipient].put((sender, message))

    return _send


@pytest.mark.asyncio
async def test_prbc_delivers_value_and_valid_proof() -> None:
    n = 4
    f = 1
    leader = 0
    value = b"prbc-payload"
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)

    recv_queues = [asyncio.Queue() for _ in range(n)]
    input_queues = [asyncio.Queue(1) for _ in range(n)]
    input_queues[leader].put_nowait(value)

    tasks: list[asyncio.Task[object]] = []
    async with asyncio.TaskGroup() as tg:
        for pid in range(n):
            tasks.append(
                tg.create_task(
                    provable_reliable_broadcast(
                        PRBCParams(
                            sid="test:prbc:deliver",
                            pid=pid,
                            N=n,
                            f=f,
                            leader=leader,
                            ecdsa_pks=ecdsa_pks,
                            ecdsa_sk=ecdsa_sks[pid],
                        ),
                        input_queues[pid],
                        recv_queues[pid],
                        _network_sender(pid, recv_queues),
                    )
                )
            )

        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10.0)

    assert all(result.value == value for result in results)
    assert len({result.proof.roothash for result in results}) == 1
    for result in results:
        assert validate_prbc_proof("test:prbc:deliver", n, f, ecdsa_pks, result.proof) is True


def test_prbc_proof_validation_rejects_wrong_sid() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)
    roothash = b"r" * 32
    digest = b"prbc-ready|sid-a|" + roothash

    proof = PrbcProof(
        roothash=roothash,
        sigmas=tuple((pid, ecdsa.sign(ecdsa_sks[pid], digest)) for pid in range(n - f)),
    )

    assert validate_prbc_proof("sid-a", n, f, ecdsa_pks, proof) is True
    assert validate_prbc_proof("sid-b", n, f, ecdsa_pks, proof) is False
