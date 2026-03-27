from __future__ import annotations

import asyncio
import logging
import random
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import honey_native

from honey.crypto import merkle, sig
from honey.subprotocols.binary_agreement import BAParams, binaryagreement
from honey.subprotocols.common_coin import CoinParams, SharedCoin
from honey.support.exceptions import ProtocolInvariantError
from honey.support.messages import BaAux, BaConf, BaEst, CoinShareMessage
from honey.support.params import CommonParams
from honey.support.telemetry import METRICS

type AbaPayload = BaEst | BaAux | BaConf
type SendFn = Callable[[int, object], Awaitable[None]]
type PredicateFn = Callable[[bytes], bool]


@dataclass(slots=True)
class MVBAParams(CommonParams):
    coin_pk: sig.PublicKey
    coin_sk: sig.PrivateShare
    proof_pk: sig.PublicKey
    proof_sk: sig.PrivateShare

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.coin_pk.threshold != self.f + 1:
            raise ValueError(
                f"coin_pk.threshold={self.coin_pk.threshold} must equal f+1={self.f + 1}"
            )
        if self.coin_pk.players != self.N:
            raise ValueError(f"coin_pk.players={self.coin_pk.players} must equal N={self.N}")
        if self.proof_pk.threshold != self.N - self.f:
            raise ValueError(
                f"proof_pk.threshold={self.proof_pk.threshold} must equal N-f={self.N - self.f}"
            )
        if self.proof_pk.players != self.N:
            raise ValueError(f"proof_pk.players={self.proof_pk.players} must equal N={self.N}")


@dataclass(frozen=True, slots=True)
class PdStoreRecord:
    roothash: bytes
    stripe_owner: int
    stripe: bytes
    merkle_proof: bytes


@dataclass(frozen=True, slots=True)
class ThresholdShareProof:
    roothash: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class PdStore:
    leader: int
    roothash: bytes
    stripe: bytes
    merkle_proof: bytes


@dataclass(frozen=True, slots=True)
class PdStored:
    leader: int
    roothash: bytes
    share: bytes


@dataclass(frozen=True, slots=True)
class PdLock:
    leader: int
    proof: ThresholdShareProof


@dataclass(frozen=True, slots=True)
class PdLocked:
    leader: int
    roothash: bytes
    share: bytes


@dataclass(frozen=True, slots=True)
class PdDone:
    leader: int
    proof: ThresholdShareProof


@dataclass(frozen=True, slots=True)
class PdStoreEvent:
    leader: int
    store: PdStoreRecord


@dataclass(frozen=True, slots=True)
class PdLockEvent:
    leader: int
    proof: ThresholdShareProof


@dataclass(frozen=True, slots=True)
class PdDoneEvent:
    leader: int
    proof: ThresholdShareProof


@dataclass(frozen=True, slots=True)
class MvbaRcPrepare:
    mvba_round: int
    leader: int
    proof: ThresholdShareProof | None


@dataclass(frozen=True, slots=True)
class MvbaRcLock:
    mvba_round: int
    leader: int
    proof: ThresholdShareProof


@dataclass(frozen=True, slots=True)
class MvbaRcStore:
    mvba_round: int
    leader: int
    store: PdStoreRecord


@dataclass(frozen=True, slots=True)
class MvbaAbaMessage:
    mvba_round: int
    payload: AbaPayload


@dataclass(frozen=True, slots=True)
class MvbaElectionCoinShare:
    coin_round: int
    signature: bytes


@dataclass(frozen=True, slots=True)
class MvbaAbaCoinShare:
    mvba_round: int
    coin_round: int
    signature: bytes


type MVBAMessage = (
    PdStore
    | PdStored
    | PdLock
    | PdLocked
    | PdDone
    | MvbaRcPrepare
    | MvbaRcLock
    | MvbaRcStore
    | MvbaAbaMessage
    | MvbaElectionCoinShare
    | MvbaAbaCoinShare
)
type PdEvent = PdStoreEvent | PdLockEvent | PdDoneEvent


def _coerce_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ProtocolInvariantError(f"MVBA input must be bytes or str, got {type(value).__name__}")


def _pd_sid(sid: str, leader: int) -> str:
    return f"{sid}:pd:{leader}"


def _stored_digest(pd_sid: str, roothash: bytes) -> bytes:
    return b"stored|" + pd_sid.encode("utf-8") + b"|" + roothash


def _locked_digest(pd_sid: str, roothash: bytes) -> bytes:
    return b"locked|" + pd_sid.encode("utf-8") + b"|" + roothash


def _build_threshold_proof(
    pk: sig.PublicKey,
    shares: dict[int, bytes],
    roothash: bytes,
    msg: bytes,
) -> ThresholdShareProof:
    if len(shares) < pk.threshold:
        raise ProtocolInvariantError(
            f"need at least {pk.threshold} shares to build threshold proof, got {len(shares)}"
        )
    selected = dict(sorted(shares.items())[: pk.threshold])
    return ThresholdShareProof(roothash=roothash, signature=sig.combine_shares(pk, selected, msg))


def _verify_threshold_proof(
    pk: sig.PublicKey,
    proof: ThresholdShareProof,
    msg: bytes,
) -> bool:
    return sig.verify_combined(pk, proof.signature, msg)


async def _broadcast(num_nodes: int, send: SendFn, message: object) -> None:
    for recipient in range(num_nodes):
        await send(recipient, message)


async def _provable_dispersal(
    params: MVBAParams,
    *,
    sid: str,
    leader: int,
    input_value: bytes | None,
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
    event_queue: asyncio.Queue[PdEvent],
) -> None:
    pid = params.pid
    n = params.N
    f = params.f
    k = n - 2 * f
    pd_sid = _pd_sid(sid, leader)

    local_store: PdStoreRecord | None = None
    local_lock: ThresholdShareProof | None = None
    local_done: ThresholdShareProof | None = None
    lock_sent = False
    done_sent = False
    leader_root: bytes | None = None
    stored_shares: dict[int, bytes] = {}
    locked_shares: dict[int, bytes] = {}

    if pid == leader and input_value is not None:
        root, stripes, proofs = merkle.encode(input_value, k, n)
        leader_root = root
        for recipient in range(n):
            await send(
                recipient,
                PdStore(
                    leader=leader,
                    roothash=root,
                    stripe=stripes[recipient],
                    merkle_proof=proofs[recipient].to_bytes(),
                ),
            )

    while True:
        sender, message = await receive_queue.get()

        if isinstance(message, PdStore):
            if sender != leader or message.leader != leader or local_store is not None:
                continue
            if not merkle.verify(message.stripe, message.merkle_proof, message.roothash):
                continue
            local_store = PdStoreRecord(
                roothash=message.roothash,
                stripe_owner=pid,
                stripe=message.stripe,
                merkle_proof=message.merkle_proof,
            )
            await event_queue.put(PdStoreEvent(leader=leader, store=local_store))
            share = params.proof_sk.sign(_stored_digest(pd_sid, message.roothash))
            await send(leader, PdStored(leader=leader, roothash=message.roothash, share=share))

        elif isinstance(message, PdStored):
            if pid != leader or leader_root is None or message.leader != leader:
                continue
            if message.roothash != leader_root:
                continue
            if sender in stored_shares:
                continue
            digest = _stored_digest(pd_sid, message.roothash)
            if not sig.verify_share(params.proof_pk, message.share, sender, digest):
                continue
            stored_shares[sender] = message.share
            if len(stored_shares) >= n - f and not lock_sent:
                proof = _build_threshold_proof(
                    params.proof_pk, stored_shares, message.roothash, digest
                )
                lock_sent = True
                await _broadcast(n, send, PdLock(leader=leader, proof=proof))

        elif isinstance(message, PdLock):
            if sender != leader or message.leader != leader or local_lock is not None:
                continue
            digest = _stored_digest(pd_sid, message.proof.roothash)
            if not _verify_threshold_proof(params.proof_pk, message.proof, digest):
                continue
            local_lock = message.proof
            await event_queue.put(PdLockEvent(leader=leader, proof=message.proof))
            share = params.proof_sk.sign(_locked_digest(pd_sid, message.proof.roothash))
            await send(
                leader, PdLocked(leader=leader, roothash=message.proof.roothash, share=share)
            )

        elif isinstance(message, PdLocked):
            if pid != leader or leader_root is None or message.leader != leader:
                continue
            if message.roothash != leader_root:
                continue
            if sender in locked_shares:
                continue
            digest = _locked_digest(pd_sid, message.roothash)
            if not sig.verify_share(params.proof_pk, message.share, sender, digest):
                continue
            locked_shares[sender] = message.share
            if len(locked_shares) >= n - f and not done_sent:
                proof = _build_threshold_proof(
                    params.proof_pk, locked_shares, message.roothash, digest
                )
                done_sent = True
                await _broadcast(n, send, PdDone(leader=leader, proof=proof))

        elif isinstance(message, PdDone):
            if sender != leader or message.leader != leader or local_done is not None:
                continue
            digest = _locked_digest(pd_sid, message.proof.roothash)
            if not _verify_threshold_proof(params.proof_pk, message.proof, digest):
                continue
            local_done = message.proof
            await event_queue.put(PdDoneEvent(leader=leader, proof=message.proof))
            if local_store is not None and local_lock is not None:
                return


async def _recast_value(
    params: MVBAParams,
    *,
    sid: str,
    mvba_round: int,
    leader: int,
    local_store: PdStoreRecord | None,
    lock_proof: ThresholdShareProof,
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
) -> bytes:
    n = params.N
    f = params.f
    k = n - 2 * f
    pd_sid = _pd_sid(sid, leader)
    stripes_by_root: dict[bytes, dict[int, honey_native.EncodedShard]] = defaultdict(dict)
    selected_lock: ThresholdShareProof | None = None
    sent_lock = False
    sent_store = False

    if local_store is not None:
        proof = honey_native.MerkleProof.from_bytes(local_store.merkle_proof)
        stripes_by_root[local_store.roothash][local_store.stripe_owner] = honey_native.EncodedShard(
            local_store.stripe_owner,
            local_store.stripe,
            proof,
        )

    while True:
        if lock_proof is not None and not sent_lock:
            await _broadcast(
                n, send, MvbaRcLock(mvba_round=mvba_round, leader=leader, proof=lock_proof)
            )
            sent_lock = True
        if local_store is not None and not sent_store:
            await _broadcast(
                n, send, MvbaRcStore(mvba_round=mvba_round, leader=leader, store=local_store)
            )
            sent_store = True

        if selected_lock is not None:
            root = selected_lock.roothash
            if len(stripes_by_root[root]) >= k:
                available = list(stripes_by_root[root].values())
                value = merkle.decode(available, root, k, n)
                check_root, _, _ = merkle.encode(value, k, n)
                if check_root == root:
                    return value

        sender, message = await receive_queue.get()
        if isinstance(message, MvbaRcLock):
            if sender == params.pid and message.leader == leader:
                selected_lock = message.proof
                continue
            if message.leader != leader:
                continue
            digest = _stored_digest(pd_sid, message.proof.roothash)
            if _verify_threshold_proof(params.proof_pk, message.proof, digest):
                selected_lock = message.proof
        elif isinstance(message, MvbaRcStore):
            if message.leader != leader:
                continue
            store = message.store
            if not merkle.verify(store.stripe, store.merkle_proof, store.roothash):
                continue
            proof = honey_native.MerkleProof.from_bytes(store.merkle_proof)
            stripes_by_root[store.roothash][store.stripe_owner] = honey_native.EncodedShard(
                store.stripe_owner,
                store.stripe,
                proof,
            )


async def _recv_dispatcher(
    *,
    receive_queue: asyncio.Queue[tuple[int, object]],
    pd_recvs: list[asyncio.Queue[tuple[int, object]]],
    election_coin_recv: asyncio.Queue[tuple[int, CoinShareMessage]],
    rc_prepare_recvs: defaultdict[int, asyncio.Queue[tuple[int, object]]],
    rc_recvs: defaultdict[int, asyncio.Queue[tuple[int, object]]],
    aba_recvs: defaultdict[int, asyncio.Queue[tuple[int, AbaPayload]]],
    aba_coin_recvs: defaultdict[int, asyncio.Queue[tuple[int, CoinShareMessage]]],
) -> None:
    while True:
        sender, message = await receive_queue.get()
        if isinstance(message, (PdStore, PdStored, PdLock, PdLocked, PdDone)):
            pd_recvs[message.leader].put_nowait((sender, message))
        elif isinstance(message, MvbaRcPrepare):
            rc_prepare_recvs[message.mvba_round].put_nowait((sender, message))
        elif isinstance(message, (MvbaRcLock, MvbaRcStore)):
            rc_recvs[message.mvba_round].put_nowait((sender, message))
        elif isinstance(message, MvbaAbaMessage):
            aba_recvs[message.mvba_round].put_nowait((sender, message.payload))
        elif isinstance(message, MvbaElectionCoinShare):
            election_coin_recv.put_nowait(
                (sender, CoinShareMessage(round_id=message.coin_round, signature=message.signature))
            )
        elif isinstance(message, MvbaAbaCoinShare):
            aba_coin_recvs[message.mvba_round].put_nowait(
                (sender, CoinShareMessage(round_id=message.coin_round, signature=message.signature))
            )


async def _forward_election_coin_shares(
    num_nodes: int,
    queue: asyncio.Queue[CoinShareMessage],
    send: SendFn,
) -> None:
    while True:
        payload = await queue.get()
        wrapped = MvbaElectionCoinShare(coin_round=payload.round_id, signature=payload.signature)
        await _broadcast(num_nodes, send, wrapped)


async def _forward_aba_messages(
    mvba_round: int,
    queue: asyncio.Queue[tuple[int, AbaPayload]],
    send: SendFn,
) -> None:
    while True:
        recipient, payload = await queue.get()
        await send(recipient, MvbaAbaMessage(mvba_round=mvba_round, payload=payload))


async def _forward_aba_coin_shares(
    num_nodes: int,
    mvba_round: int,
    queue: asyncio.Queue[CoinShareMessage],
    send: SendFn,
) -> None:
    while True:
        payload = await queue.get()
        wrapped = MvbaAbaCoinShare(
            mvba_round=mvba_round,
            coin_round=payload.round_id,
            signature=payload.signature,
        )
        await _broadcast(num_nodes, send, wrapped)


async def _run_rc_prepare(
    params: MVBAParams,
    *,
    sid: str,
    mvba_round: int,
    leader: int,
    local_lock: ThresholdShareProof | None,
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
) -> tuple[int, ThresholdShareProof | None]:
    await _broadcast(
        params.N,
        send,
        MvbaRcPrepare(mvba_round=mvba_round, leader=leader, proof=local_lock),
    )

    none_votes = 0
    while True:
        _sender, message = await receive_queue.get()
        if not isinstance(message, MvbaRcPrepare) or message.leader != leader:
            continue
        if message.proof is None:
            none_votes += 1
            if none_votes >= 2 * params.f + 1:
                return 0, None
            continue
        digest = _stored_digest(_pd_sid(sid, leader), message.proof.roothash)
        if _verify_threshold_proof(params.proof_pk, message.proof, digest):
            return 1, message.proof


async def _run_mvba_aba_round(
    params: MVBAParams,
    *,
    mvba_round: int,
    aba_input: int,
    aba_recv_queue: asyncio.Queue[tuple[int, AbaPayload]],
    aba_coin_recv_queue: asyncio.Queue[tuple[int, CoinShareMessage]],
    send: SendFn,
    task_group: asyncio.TaskGroup,
    background_tasks: list[asyncio.Task[object]],
) -> int:
    decide_queue: asyncio.Queue[int] = asyncio.Queue(1)
    input_queue: asyncio.Queue[int] = asyncio.Queue(1)
    input_queue.put_nowait(aba_input)
    send_queue: asyncio.Queue[tuple[int, AbaPayload]] = asyncio.Queue()
    coin_send_queue: asyncio.Queue[CoinShareMessage] = asyncio.Queue()
    coin = SharedCoin(
        CoinParams(
            sid=f"{params.sid}:mvba:{mvba_round}:coin",
            pid=params.pid,
            N=params.N,
            f=params.f,
            leader=params.leader,
            PK=params.coin_pk,
            SK=params.coin_sk,
        )
    )
    coin.start(task_group, aba_coin_recv_queue)
    aba_task = task_group.create_task(
        binaryagreement(
            BAParams(
                sid=f"{params.sid}:mvba:{mvba_round}:aba",
                pid=params.pid,
                N=params.N,
                f=params.f,
                leader=params.leader,
            ),
            coin,
            coin_send_queue,
            input_queue,
            decide_queue,
            aba_recv_queue,
            send_queue,
        )
    )
    background_tasks.append(aba_task)
    background_tasks.append(
        task_group.create_task(_forward_aba_messages(mvba_round, send_queue, send))
    )
    background_tasks.append(
        task_group.create_task(
            _forward_aba_coin_shares(params.N, mvba_round, coin_send_queue, send)
        )
    )
    decision = await decide_queue.get()
    coin.stop()
    return decision


def _leader_permutation(seed: int, n: int) -> list[int]:
    rng = random.Random(seed)
    values = list(range(n))
    rng.shuffle(values)
    return values


async def dumbo_mvba(
    params: MVBAParams,
    input_queue: asyncio.Queue[bytes | str],
    decide_queue: asyncio.Queue[bytes],
    receive_queue: asyncio.Queue[tuple[int, object]],
    send: SendFn,
    predicate: PredicateFn | None = None,
) -> None:
    predicate = predicate or (lambda _value: True)
    logger = logging.LoggerAdapter(logging.getLogger("honey.mvba"), extra={"node": params.pid})

    input_value = _coerce_bytes(await input_queue.get())
    pd_input = input_value if predicate(input_value) else None

    pd_recvs = [asyncio.Queue() for _ in range(params.N)]
    pd_event_queue: asyncio.Queue[PdEvent] = asyncio.Queue()
    election_coin_recv: asyncio.Queue[tuple[int, CoinShareMessage]] = asyncio.Queue()
    rc_prepare_recvs: defaultdict[int, asyncio.Queue[tuple[int, object]]] = defaultdict(
        asyncio.Queue
    )
    rc_recvs: defaultdict[int, asyncio.Queue[tuple[int, object]]] = defaultdict(asyncio.Queue)
    aba_recvs: defaultdict[int, asyncio.Queue[tuple[int, AbaPayload]]] = defaultdict(asyncio.Queue)
    aba_coin_recvs: defaultdict[int, asyncio.Queue[tuple[int, CoinShareMessage]]] = defaultdict(
        asyncio.Queue
    )

    stores: dict[int, PdStoreRecord] = {}
    locks: dict[int, ThresholdShareProof] = {}
    dones: dict[int, ThresholdShareProof] = {}

    election_coin_send: asyncio.Queue[CoinShareMessage] = asyncio.Queue()

    async with asyncio.TaskGroup() as tg:
        background_tasks: list[asyncio.Task[object]] = []
        background_tasks.append(
            tg.create_task(
                _recv_dispatcher(
                    receive_queue=receive_queue,
                    pd_recvs=pd_recvs,
                    election_coin_recv=election_coin_recv,
                    rc_prepare_recvs=rc_prepare_recvs,
                    rc_recvs=rc_recvs,
                    aba_recvs=aba_recvs,
                    aba_coin_recvs=aba_coin_recvs,
                )
            )
        )
        background_tasks.append(
            tg.create_task(_forward_election_coin_shares(params.N, election_coin_send, send))
        )

        election_coin = SharedCoin(
            CoinParams(
                sid=f"{params.sid}:mvba:election",
                pid=params.pid,
                N=params.N,
                f=params.f,
                leader=params.leader,
                PK=params.coin_pk,
                SK=params.coin_sk,
            ),
            single_bit=False,
        )
        election_coin.start(tg, election_coin_recv)

        pd_tasks: list[asyncio.Task[object]] = []
        for leader in range(params.N):
            value = pd_input if leader == params.pid else None
            pd_tasks.append(
                tg.create_task(
                    _provable_dispersal(
                        params,
                        sid=params.sid,
                        leader=leader,
                        input_value=value,
                        receive_queue=pd_recvs[leader],
                        send=send,
                        event_queue=pd_event_queue,
                    )
                )
            )

        while len(dones) < params.N - params.f:
            event = await pd_event_queue.get()
            if isinstance(event, PdStoreEvent):
                stores.setdefault(event.leader, event.store)
            elif isinstance(event, PdLockEvent):
                locks.setdefault(event.leader, event.proof)
            elif isinstance(event, PdDoneEvent):
                dones.setdefault(event.leader, event.proof)

        for task in pd_tasks:
            task.cancel()

        permutation_round = 0
        permutation = _leader_permutation(
            await election_coin.get_coin(permutation_round, election_coin_send), params.N
        )
        mvba_round = 0

        while True:
            if mvba_round >= len(permutation):
                permutation_round += 1
                permutation = _leader_permutation(
                    await election_coin.get_coin(permutation_round, election_coin_send),
                    params.N,
                )
                mvba_round = 0

            leader = permutation[mvba_round]
            ballot, selected_lock = await _run_rc_prepare(
                params,
                sid=params.sid,
                mvba_round=mvba_round,
                leader=leader,
                local_lock=locks.get(leader),
                receive_queue=rc_prepare_recvs[mvba_round],
                send=send,
            )
            aba_decision = await _run_mvba_aba_round(
                params,
                mvba_round=mvba_round,
                aba_input=ballot,
                aba_recv_queue=aba_recvs[mvba_round],
                aba_coin_recv_queue=aba_coin_recvs[mvba_round],
                send=send,
                task_group=tg,
                background_tasks=background_tasks,
            )
            if aba_decision == 1:
                lock_proof = selected_lock or locks.get(leader)
                if lock_proof is None:
                    raise ProtocolInvariantError("ABA selected a leader without a lock proof")
                value = await _recast_value(
                    params,
                    sid=params.sid,
                    mvba_round=mvba_round,
                    leader=leader,
                    local_store=stores.get(leader),
                    lock_proof=lock_proof,
                    receive_queue=rc_recvs[mvba_round],
                    send=send,
                )
                await decide_queue.put(value)
                METRICS.increment("mvba.decision", node=params.pid, leader=leader)
                logger.info("MVBA decided", extra={"leader": leader, "round": mvba_round})
                break
            mvba_round += 1

        election_coin.stop()
        for task in background_tasks:
            task.cancel()
