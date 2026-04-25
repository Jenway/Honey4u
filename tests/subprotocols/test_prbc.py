from __future__ import annotations

import asyncio

import honey_native
import pytest
from honey_acs.runtime.native import NativeMerkleRuntime
from honey_acs.subprotocols.provable_reliable_broadcast import (
    PrbcEcho,
    PRBCParams,
    PrbcProof,
    PrbcReady,
    PrbcVal,
    provable_reliable_broadcast,
    validate_prbc_proof,
)

MERKLE = NativeMerkleRuntime()


def _generate_ecdsa(players: int) -> tuple[list[bytes], list[bytes]]:
    return honey_native.ecdsa_generate_keys(players)


def _prbc_crypto(
    public_keys: list[bytes], private_key: bytes | None = None
) -> honey_native.PrbcCryptoRuntime:
    return honey_native.PrbcCryptoRuntime(public_keys, private_key)


def _sign(private_key: bytes, digest: bytes) -> bytes:
    return honey_native.ecdsa_sign(private_key, digest)


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
    ecdsa_pks, ecdsa_sks = _generate_ecdsa(n)

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
                            crypto=_prbc_crypto(ecdsa_pks, ecdsa_sks[pid]),
                            merkle=MERKLE,
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
        assert (
            validate_prbc_proof("test:prbc:deliver", n, f, _prbc_crypto(ecdsa_pks), result.proof)
            is True
        )


def test_prbc_proof_validation_rejects_wrong_sid() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = _generate_ecdsa(n)
    roothash = b"r" * 32
    digest = b"prbc-ready|sid-a|" + roothash

    proof = PrbcProof(
        roothash=roothash,
        sigmas=tuple((pid, _sign(ecdsa_sks[pid], digest)) for pid in range(n - f)),
    )

    assert validate_prbc_proof("sid-a", n, f, _prbc_crypto(ecdsa_pks), proof) is True
    assert validate_prbc_proof("sid-b", n, f, _prbc_crypto(ecdsa_pks), proof) is False


def test_prbc_proof_validation_rejects_duplicate_signer() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = _generate_ecdsa(n)
    roothash = b"d" * 32
    digest = b"prbc-ready|sid-dup|" + roothash

    proof = PrbcProof(
        roothash=roothash,
        sigmas=(
            (0, _sign(ecdsa_sks[0], digest)),
            (0, _sign(ecdsa_sks[0], digest)),
            (1, _sign(ecdsa_sks[1], digest)),
        ),
    )

    assert validate_prbc_proof("sid-dup", n, f, _prbc_crypto(ecdsa_pks), proof) is False


def test_prbc_proof_validation_rejects_out_of_range_signer() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = _generate_ecdsa(n)
    roothash = b"o" * 32
    digest = b"prbc-ready|sid-range|" + roothash

    proof = PrbcProof(
        roothash=roothash,
        sigmas=(
            (0, _sign(ecdsa_sks[0], digest)),
            (1, _sign(ecdsa_sks[1], digest)),
            (4, _sign(ecdsa_sks[2], digest)),
        ),
    )

    assert validate_prbc_proof("sid-range", n, f, _prbc_crypto(ecdsa_pks), proof) is False


def test_prbc_proof_validation_rejects_bad_signature() -> None:
    n = 4
    f = 1
    ecdsa_pks, ecdsa_sks = _generate_ecdsa(n)
    roothash = b"b" * 32
    digest = b"prbc-ready|sid-bad|" + roothash
    bad_sig = bytearray(_sign(ecdsa_sks[2], digest))
    bad_sig[-1] ^= 0x01

    proof = PrbcProof(
        roothash=roothash,
        sigmas=(
            (0, _sign(ecdsa_sks[0], digest)),
            (1, _sign(ecdsa_sks[1], digest)),
            (2, bytes(bad_sig)),
        ),
    )

    assert validate_prbc_proof("sid-bad", n, f, _prbc_crypto(ecdsa_pks), proof) is False


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
    ecdsa_pks, ecdsa_sks = _generate_ecdsa(n)
    roothash, stripes, proofs = MERKLE.encode(value, n - 2 * f, n)
    digest = b"prbc-ready|" + sid.encode("utf-8") + b"|" + roothash

    class CountingPrbcCrypto:
        def __init__(self) -> None:
            self.inner = _prbc_crypto(ecdsa_pks, ecdsa_sks[pid])
            self.verify_calls = 0

        @property
        def players(self) -> int:
            return self.inner.players

        def sign_ready(self, digest: bytes) -> bytes:
            return self.inner.sign_ready(digest)

        def verify_ready_signature(self, player_id: int, signature: bytes, digest: bytes) -> bool:
            self.verify_calls += 1
            return self.inner.verify_ready_signature(player_id, signature, digest)

        def verify_ready_proof(
            self,
            digest: bytes,
            sigmas: tuple[tuple[int, bytes], ...],
            threshold: int,
        ) -> bool:
            return self.inner.verify_ready_proof(digest, sigmas, threshold)

    counting_crypto = CountingPrbcCrypto()

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
                crypto=counting_crypto,
                merkle=MERKLE,
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
                proof=proofs[pid],
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
                    signature=_sign(ecdsa_sks[sender], digest),
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
                signature=_sign(ecdsa_sks[4], digest),
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
                    signature=_sign(ecdsa_sks[sender], digest),
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
                    proof=proofs[sender],
                    stripe=stripes[sender],
                    stripe_index=sender,
                ),
            )
        )

    result = await asyncio.wait_for(task, timeout=1.0)

    assert result.value == value
    assert validate_prbc_proof(sid, n, f, _prbc_crypto(ecdsa_pks), result.proof) is True
    assert counting_crypto.verify_calls == 4
