from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from honey.acs.dumbo_acs import DumboACSParams, DumboProofDiffuse, dumbo_acs
from honey.consensus.honeybadger.block import honeybadger_block
from honey.consensus.honeybadger.core import HoneyBadgerBFT
from honey.data.pool_reuse import (
    PoolBundleProposal,
    PoolFetchRequest,
    PoolFetchResponse,
    PoolReference,
    decode_acs_payload,
)
from honey.runtime.router import DumboPoolRecv, DumboRecv, RoundProtocolRouter, TpkeRecv
from honey.subprotocols.dumbo_mvba import (
    MvbaAbaCoinShare,
    MvbaAbaMessage,
    MvbaElectionCoinShare,
    MvbaRcLock,
    MvbaRcPrepare,
    MvbaRcStore,
    PdDone,
    PdLock,
    PdLocked,
    PdStore,
    PdStored,
)
from honey.subprotocols.provable_reliable_broadcast import (
    PrbcEcho,
    PrbcOutcome,
    PrbcReady,
    PrbcVal,
    compute_prbc_roothash,
    deserialize_prbc_proof,
    serialize_prbc_proof,
    validate_prbc_proof,
)
from honey.support.exceptions import ProtocolInvariantError
from honey.support.messages import (
    Channel,
    ProtocolEnvelope,
    ProtocolMessage,
    encode_tx,
    encode_tx_batch,
)
from honey.support.params import HBConfig
from honey.support.results import Result, success
from network.transport import Transport

DUMBO_PRBC_MESSAGES = (PrbcVal, PrbcEcho, PrbcReady)
DUMBO_MVBA_MESSAGES = (
    PdStore,
    PdStored,
    PdLock,
    PdLocked,
    PdDone,
    MvbaRcPrepare,
    MvbaRcLock,
    MvbaRcStore,
    MvbaAbaMessage,
    MvbaElectionCoinShare,
    MvbaAbaCoinShare,
)
DUMBO_POOL_MESSAGES = (PoolFetchRequest, PoolFetchResponse)


@dataclass
class DumboRoundContext:
    round_id: int
    sid: str
    pid: int
    n: int
    f: int
    router: RoundProtocolRouter
    dumbo_recv_raw: asyncio.Queue[DumboRecv]
    dumbo_recv: asyncio.Queue[tuple[int, object]]
    dumbo_pool_recv_raw: asyncio.Queue[DumboPoolRecv]
    dumbo_pool_recv: asyncio.Queue[tuple[int, object]]
    tpke_recv: asyncio.Queue[TpkeRecv]
    tpke_bcast_queue: asyncio.Queue[ProtocolMessage]
    acs_input_queue: asyncio.Queue[bytes]
    acs_output_queue: asyncio.Queue[tuple[bytes | None, ...]]
    tasks: list[asyncio.Task[Any]] = field(default_factory=list)


class DumboBFT(HoneyBadgerBFT):
    def __init__(
        self,
        common_params,
        crypto_params,
        transport: Transport,
        config: HBConfig | None = None,
    ):
        super().__init__(common_params, crypto_params, transport, config=config)
        if self.crypto.proof_sig_pk is None or self.crypto.proof_sig_sk is None:
            raise ValueError("DumboBFT requires proof_sig_pk/proof_sig_sk in CryptoParams")
        if not self.crypto.ecdsa_pks or self.crypto.ecdsa_sk is None:
            raise ValueError("DumboBFT requires ECDSA material in CryptoParams")
        self.logger = logging.LoggerAdapter(
            logging.getLogger("honey.dumbo"), extra={"node": common_params.pid}
        )

    def _pool_reuse_enabled(self) -> bool:
        return self.config.enable_broadcast_pool_reuse

    @staticmethod
    async def _forward_dumbo_messages(
        source: asyncio.Queue[tuple[int, object]],
        target: asyncio.Queue[tuple[int, object]],
    ) -> None:
        while True:
            try:
                sender, message = await source.get()
                target.put_nowait((sender, message))
            except asyncio.CancelledError:
                break

    @staticmethod
    def _dumbo_channel_for_message(message: object) -> Channel:
        if isinstance(message, DUMBO_PRBC_MESSAGES):
            return Channel.DUMBO_PRBC
        if isinstance(message, DumboProofDiffuse):
            return Channel.DUMBO_PROOF
        if isinstance(message, DUMBO_MVBA_MESSAGES):
            return Channel.DUMBO_MVBA
        if isinstance(message, DUMBO_POOL_MESSAGES):
            return Channel.DUMBO_POOL
        raise ProtocolInvariantError(f"Unsupported Dumbo message type: {type(message).__name__}")

    @staticmethod
    def _dumbo_instance_id(message: object) -> int | None:
        if isinstance(message, DUMBO_PRBC_MESSAGES):
            return int(message.leader)
        return None

    def _pool_prbc_sid(self, origin_round: int, origin_sender: int) -> str:
        return f"{self.common.sid}:{origin_round}:dumbo:prbc:{origin_sender}"

    def _reuse_owner(self, payload_id: str, round_id: int) -> int:
        seed = f"{round_id}:{payload_id}".encode("ascii")
        digest = hashlib.sha256(seed).digest()
        return int.from_bytes(digest[:8], "big") % self.common.N

    def _build_round_proposal(
        self, round_id: int, tx_to_send: list[Any]
    ) -> bytes | PoolBundleProposal:
        payload = encode_tx_batch([encode_tx(tx) for tx in tx_to_send])
        if not self._pool_reuse_enabled():
            return payload

        references: list[PoolReference] = []
        if self.config.enable_pool_reference_proposals:
            reusable = self.mempool.list_reusable(
                current_round=round_id,
                limit=self.mempool.max_size,
            )
            for payload_id, entry in reusable:
                if len(references) >= self.config.pool_reuse_limit_per_round:
                    break
                if self._reuse_owner(payload_id, round_id) != self.common.pid:
                    continue
                if entry.proof_payload is None:
                    continue
                self.mempool.mark_selected(payload_id, round_id)
                references.append(
                    PoolReference(
                        item_id=payload_id,
                        origin_round=entry.round_no,
                        origin_sender=entry.sender_id,
                        roothash=entry.roothash,
                        proof_payload=entry.proof_payload,
                    )
                )

        return PoolBundleProposal(payload=payload, references=tuple(references))

    def _store_carryovers(self, round_id: int, carryovers: tuple[PrbcOutcome, ...]) -> None:
        for outcome in carryovers:
            decoded = decode_acs_payload(outcome.value)
            if decoded.inline_payload is None:
                continue
            self.mempool.add_reusable(
                payload=outcome.value,
                roothash=outcome.proof.roothash,
                proof_payload=serialize_prbc_proof(outcome.proof),
                round_no=round_id,
                sender_id=outcome.leader,
                timestamp=time.time(),
            )

    async def _serve_pool_requests(
        self,
        ctx: DumboRoundContext,
        pending_fetches: dict[str, asyncio.Future[PoolFetchResponse]],
        dumbo_send,
    ) -> None:
        while True:
            try:
                sender, message = await ctx.dumbo_pool_recv.get()
                if isinstance(message, PoolFetchRequest):
                    entry = self.mempool.get_reusable(message.item_id)
                    if entry is None or entry.roothash != message.roothash:
                        continue
                    await dumbo_send(
                        sender,
                        PoolFetchResponse(item_id=message.item_id, payload=entry.payload),
                    )
                elif isinstance(message, PoolFetchResponse):
                    future = pending_fetches.get(message.item_id)
                    if future is not None and not future.done():
                        future.set_result(message)
            except asyncio.CancelledError:
                break

    async def _resolve_pool_reference(
        self,
        ctx: DumboRoundContext,
        pending_fetches: dict[str, asyncio.Future[PoolFetchResponse]],
        dumbo_send,
        reference: PoolReference,
    ) -> bytes:
        proof = deserialize_prbc_proof(reference.proof_payload)
        if proof.roothash != reference.roothash:
            raise ProtocolInvariantError("pool reference proof roothash mismatch")
        if not validate_prbc_proof(
            self._pool_prbc_sid(reference.origin_round, reference.origin_sender),
            self.common.N,
            self.common.f,
            self.crypto.ecdsa_pks,
            proof,
        ):
            raise ProtocolInvariantError("pool reference proof is invalid")

        local_entry = self.mempool.get_reusable(reference.item_id)
        if local_entry is not None and local_entry.roothash == reference.roothash:
            if local_entry.consumed_in_round != ctx.round_id:
                self.mempool.mark_consumed(reference.item_id, ctx.round_id)
            return local_entry.payload

        if not self.config.enable_pool_fetch_fallback:
            raise ProtocolInvariantError(
                "pool reference missing locally and fetch fallback is disabled"
            )

        future = pending_fetches.get(reference.item_id)
        if future is None or future.done():
            future = asyncio.get_running_loop().create_future()
            pending_fetches[reference.item_id] = future
            await dumbo_send(
                reference.origin_sender,
                PoolFetchRequest(
                    item_id=reference.item_id,
                    origin_round=reference.origin_round,
                    origin_sender=reference.origin_sender,
                    roothash=reference.roothash,
                ),
            )

        response = await asyncio.wait_for(future, timeout=self.config.round_timeout)
        payload = response.payload
        if compute_prbc_roothash(payload, self.common.N, self.common.f) != reference.roothash:
            raise ProtocolInvariantError("fetched pool payload does not match referenced roothash")
        decode_acs_payload(payload)

        self.mempool.add_reusable(
            payload=payload,
            roothash=reference.roothash,
            proof_payload=reference.proof_payload,
            round_no=reference.origin_round,
            sender_id=reference.origin_sender,
            timestamp=time.time(),
        )
        self.mempool.mark_consumed(reference.item_id, ctx.round_id)
        pending_fetches.pop(reference.item_id, None)
        return payload

    async def _run_round(self, round_id: int, tx_to_send: list[Any]) -> Result[list[Any]]:
        try:
            async with asyncio.TaskGroup() as task_group:
                ctx = self._build_dumbo_round_context(round_id)
                spawn = self._task_spawner(task_group, ctx.tasks)
                pending_fetches: dict[str, asyncio.Future[PoolFetchResponse]] = {}
                carryover_queue: asyncio.Queue[tuple[PrbcOutcome, ...]] | None = (
                    asyncio.Queue(1) if self._pool_reuse_enabled() else None
                )

                spawn(ctx.router.recv_dispatcher())
                spawn(self._forward_dumbo_messages(ctx.dumbo_recv_raw, ctx.dumbo_recv))
                spawn(self._forward_dumbo_messages(ctx.dumbo_pool_recv_raw, ctx.dumbo_pool_recv))
                spawn(
                    ctx.router.route_broadcast_queue(
                        ctx.tpke_bcast_queue,
                        Channel.TPKE,
                        None,
                        broadcast=True,
                    )
                )

                async def dumbo_send(recipient: int, message: object) -> None:
                    envelope = ProtocolEnvelope(
                        round_id=ctx.round_id,
                        channel=self._dumbo_channel_for_message(message),
                        instance_id=self._dumbo_instance_id(message),
                        message=message,
                    )
                    await self.transport.send(recipient, envelope)

                if self._pool_reuse_enabled():
                    spawn(self._serve_pool_requests(ctx, pending_fetches, dumbo_send))

                spawn(
                    dumbo_acs(
                        DumboACSParams(
                            sid=f"{ctx.sid}:dumbo",
                            pid=ctx.pid,
                            N=ctx.n,
                            f=ctx.f,
                            leader=ctx.pid,
                            coin_pk=self.crypto.sig_pk,
                            coin_sk=self.crypto.sig_sk,
                            proof_pk=self.crypto.proof_sig_pk,
                            proof_sk=self.crypto.proof_sig_sk,
                            ecdsa_pks=self.crypto.ecdsa_pks,
                            ecdsa_sk=self.crypto.ecdsa_sk,
                            carryover_grace_ms=self.config.pool_grace_ms
                            if self._pool_reuse_enabled()
                            else 0,
                        ),
                        ctx.acs_input_queue,
                        ctx.acs_output_queue,
                        ctx.dumbo_recv,
                        dumbo_send,
                        carryover_queue=carryover_queue,
                    )
                )

                propose_queue: asyncio.Queue[bytes | PoolBundleProposal] = asyncio.Queue(1)
                propose_queue.put_nowait(self._build_round_proposal(round_id, tx_to_send))
                block_task = spawn(
                    honeybadger_block(
                        ctx.pid,
                        ctx.n,
                        ctx.f,
                        self.crypto.enc_pk,
                        self.crypto.enc_sk,
                        propose_queue,
                        ctx.acs_input_queue,
                        ctx.acs_output_queue,
                        ctx.tpke_bcast_queue,
                        ctx.tpke_recv,
                        self.logger,
                        pool_reuse_enabled=self._pool_reuse_enabled(),
                        resolve_pool_reference=(
                            lambda reference: self._resolve_pool_reference(
                                ctx,
                                pending_fetches,
                                dumbo_send,
                                reference,
                            )
                        )
                        if self._pool_reuse_enabled()
                        else None,
                    )
                )

                block = await asyncio.wait_for(block_task, timeout=self.config.round_timeout)
                if carryover_queue is not None:
                    self._store_carryovers(round_id, await carryover_queue.get())
                self._cancel_round_tasks(ctx.tasks, keep={block_task})

            self.mempool.cleanup(round_id)
            merged = await asyncio.to_thread(self._merge_block_batches, block)
            return success(merged)
        except TimeoutError:
            return self._round_failure("TIMEOUT", round_id, f"Round {round_id} exceeded timeout")
        except Exception as exc:
            code, message, details = self._classify_round_exception(round_id, exc)
            return self._round_failure(code, round_id, message, details)

    def _build_dumbo_round_context(self, round_id: int) -> DumboRoundContext:
        tpke_recv: asyncio.Queue[TpkeRecv] = asyncio.Queue()
        dumbo_recv_raw: asyncio.Queue[DumboRecv] = asyncio.Queue()
        dumbo_pool_recv_raw: asyncio.Queue[DumboPoolRecv] = asyncio.Queue()
        return DumboRoundContext(
            round_id=round_id,
            sid=f"{self.common.sid}:{round_id}",
            pid=self.common.pid,
            n=self.common.N,
            f=self.common.f,
            router=RoundProtocolRouter(
                round_id=round_id,
                num_nodes=self.common.N,
                transport=self.transport,
                inbound_queue=self.mailboxes.inbox(round_id),
                coin_recvs=None,
                aba_recvs=None,
                rbc_recvs=None,
                tpke_recv=tpke_recv,
                dumbo_recv=dumbo_recv_raw,
                dumbo_pool_recv=dumbo_pool_recv_raw,
                logger=self.logger,
            ),
            dumbo_recv_raw=dumbo_recv_raw,
            dumbo_recv=asyncio.Queue(),
            dumbo_pool_recv_raw=dumbo_pool_recv_raw,
            dumbo_pool_recv=asyncio.Queue(),
            tpke_recv=tpke_recv,
            tpke_bcast_queue=asyncio.Queue(),
            acs_input_queue=asyncio.Queue(1),
            acs_output_queue=asyncio.Queue(1),
        )
