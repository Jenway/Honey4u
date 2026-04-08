from __future__ import annotations

import asyncio
import importlib

import pytest
from honey_acs.subprotocols.provable_reliable_broadcast import (
    PrbcEcho,
    PRBCParams,
    PrbcProof,
    PrbcReady,
    PrbcVal,
    provable_reliable_broadcast,
    validate_prbc_proof,
)
from honey_shared.crypto import ecdsa, merkle

prbc_module = importlib.import_module("honey_acs.subprotocols.provable_reliable_broadcast")


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


def test_prbc_proof_validation_rejects_duplicate_signer() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)
    roothash = b"d" * 32
    digest = b"prbc-ready|sid-dup|" + roothash

    proof = PrbcProof(
        roothash=roothash,
        sigmas=(
            (0, ecdsa.sign(ecdsa_sks[0], digest)),
            (0, ecdsa.sign(ecdsa_sks[0], digest)),
            (1, ecdsa.sign(ecdsa_sks[1], digest)),
        ),
    )

    assert validate_prbc_proof("sid-dup", n, f, ecdsa_pks, proof) is False


def test_prbc_proof_validation_rejects_out_of_range_signer() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)
    roothash = b"o" * 32
    digest = b"prbc-ready|sid-range|" + roothash

    proof = PrbcProof(
        roothash=roothash,
        sigmas=(
            (0, ecdsa.sign(ecdsa_sks[0], digest)),
            (1, ecdsa.sign(ecdsa_sks[1], digest)),
            (4, ecdsa.sign(ecdsa_sks[2], digest)),
        ),
    )

    assert validate_prbc_proof("sid-range", n, f, ecdsa_pks, proof) is False


def test_prbc_proof_validation_rejects_bad_signature() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)
    roothash = b"b" * 32
    digest = b"prbc-ready|sid-bad|" + roothash
    bad_sig = bytearray(ecdsa.sign(ecdsa_sks[2], digest))
    bad_sig[-1] ^= 0x01

    proof = PrbcProof(
        roothash=roothash,
        sigmas=(
            (0, ecdsa.sign(ecdsa_sks[0], digest)),
            (1, ecdsa.sign(ecdsa_sks[1], digest)),
            (2, bytes(bad_sig)),
        ),
    )

    assert validate_prbc_proof("sid-bad", n, f, ecdsa_pks, proof) is False


@pytest.mark.asyncio
async def test_prbc_skips_self_and_surplus_ready_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    n = 7
    f = 2
    pid = 0
    leader = 1
    sid = "test:prbc:skip-ready"
    value = b"prbc-surplus-ready"
    ecdsa_pks, ecdsa_sks = ecdsa.generate(n)
    roothash, stripes, proofs = merkle.encode(value, n - 2 * f, n)
    digest = b"prbc-ready|" + sid.encode("utf-8") + b"|" + roothash

    verify_calls = 0
    original_verify = prbc_module.ecdsa.verify

    def counting_verify(pk: bytes, message: bytes, signature: bytes) -> bool:
        nonlocal verify_calls
        verify_calls += 1
        return original_verify(pk, message, signature)

    monkeypatch.setattr(prbc_module.ecdsa, "verify", counting_verify)

    receive_queue: asyncio.Queue[tuple[int, object]] = asyncio.Queue()
    input_queue: asyncio.Queue[bytes | str] = asyncio.Queue()

    async def send(recipient: int, message: object) -> None:
        if recipient == pid:
            await receive_queue.put((pid, message))

    task = asyncio.create_task(
        provable_reliable_broadcast(
            PRBCParams(
                sid=sid,
                pid=pid,
                N=n,
                f=f,
                leader=leader,
                ecdsa_pks=ecdsa_pks,
                ecdsa_sk=ecdsa_sks[pid],
            ),
            input_queue,
            receive_queue,
            send,
        )
    )

    await receive_queue.put(
        (
            leader,
            PrbcVal(
                leader=leader,
                roothash=roothash,
                proof=proofs[pid].to_bytes(),
                stripe=stripes[pid],
                stripe_index=pid,
            ),
        )
    )
    await asyncio.sleep(0)

    for sender in (1, 2, 3):
        await receive_queue.put(
            (
                sender,
                PrbcReady(
                    leader=leader,
                    roothash=roothash,
                    signature=ecdsa.sign(ecdsa_sks[sender], digest),
                ),
            )
        )
    await asyncio.sleep(0)

    await receive_queue.put(
        (
            4,
            PrbcReady(
                leader=leader,
                roothash=roothash,
                signature=ecdsa.sign(ecdsa_sks[4], digest),
            ),
        )
    )
    await asyncio.sleep(0)

    for sender in (5, 6):
        await receive_queue.put(
            (
                sender,
                PrbcReady(
                    leader=leader,
                    roothash=roothash,
                    signature=ecdsa.sign(ecdsa_sks[sender], digest),
                ),
            )
        )
    await asyncio.sleep(0)

    for sender in (1, 2):
        await receive_queue.put(
            (
                sender,
                PrbcEcho(
                    leader=leader,
                    roothash=roothash,
                    proof=proofs[sender].to_bytes(),
                    stripe=stripes[sender],
                    stripe_index=sender,
                ),
            )
        )

    result = await asyncio.wait_for(task, timeout=1.0)

    assert result.value == value
    assert validate_prbc_proof(sid, n, f, ecdsa_pks, result.proof) is True
    assert verify_calls == 4
