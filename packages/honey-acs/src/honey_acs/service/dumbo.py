from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

from honey_acs.crypto import sig
from honey_acs.data.broadcast_mempool import BroadcastMempool
from honey_acs.dumbo.dumbo_acs import (
    DumboACSDecision,
    DumboACSParams,
    DumboProofDiffuse,
    dumbo_acs,
)
from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.messages import Channel
from honey_acs.params import CryptoParams, HBConfig
from honey_acs.service.base import AcsOutputMode, AcsService
from honey_acs.subprotocols.dumbo_mvba import (
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
from honey_acs.subprotocols.provable_reliable_broadcast import (
    PrbcEcho,
    PrbcOutcome,
    PrbcReady,
    PrbcVal,
    serialize_prbc_proof,
)

_DUMBO_PRBC_MESSAGES = (PrbcVal, PrbcEcho, PrbcReady)
_DUMBO_MVBA_MESSAGES = (
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

type DumboServiceDecision = DumboACSDecision | tuple[bytes | None, ...]


@dataclass(slots=True)
class DumboRoundState:
    round_id: int
    sid: str
    input_queue: asyncio.Queue[bytes]
    decide_queue: asyncio.Queue[DumboServiceDecision]
    receive_queue: asyncio.Queue[tuple[int, object]]
    task: asyncio.Task[None] | None = None


def _dumbo_channel_for_message(message: object) -> Channel:
    if isinstance(message, _DUMBO_PRBC_MESSAGES):
        return Channel.DUMBO_PRBC
    if isinstance(message, DumboProofDiffuse):
        return Channel.DUMBO_PROOF
    if isinstance(message, _DUMBO_MVBA_MESSAGES):
        return Channel.DUMBO_MVBA
    raise ProtocolInvariantError(f"Unsupported Dumbo ACS message type: {type(message).__name__}")


class DumboAcsService(AcsService):
    def __init__(
        self,
        *,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: CryptoParams,
        config: HBConfig | None = None,
        mempool: BroadcastMempool | None = None,
        event_notifier: Callable[[], None] | None = None,
        output_mode: AcsOutputMode = "selected_pids",
    ) -> None:
        super().__init__(
            protocol="dumbo",
            pid=pid,
            nodes=nodes,
            faulty=faulty,
            crypto=crypto,
            config=config,
            mempool=mempool,
            logger_name="honey.acs.dumbo.service",
            event_notifier=event_notifier,
            output_mode=output_mode,
        )
        self._rounds: dict[int, DumboRoundState] = {}

    def active_round_ids(self) -> list[int]:
        return list(self._rounds)

    async def _start_round(self, *, round_id: int, sid: str, proposal_input: bytes) -> None:
        if round_id in self._rounds:
            raise ValueError(f"round {round_id} is already active")
        state = DumboRoundState(
            round_id=round_id,
            sid=sid,
            input_queue=asyncio.Queue(1),
            decide_queue=asyncio.Queue(1),
            receive_queue=asyncio.Queue(),
        )
        state.input_queue.put_nowait(proposal_input)
        state.task = asyncio.create_task(self._run_round(state))
        self._rounds[round_id] = state

    async def deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        track_stats = self._track_internal_stats
        if track_stats:
            self._record_delivery_call(mode="single", items=1)
        del instance_id
        state = self._rounds.get(round_id)
        if state is None:
            return False

        channel_tag = Channel(channel)
        if channel_tag not in (Channel.DUMBO_PRBC, Channel.DUMBO_PROOF, Channel.DUMBO_MVBA):
            return False
        state.receive_queue.put_nowait((sender, message))
        if track_stats:
            self._record_inbound_channel(channel_tag.value)
            self._update_queue_peak("receive", state.receive_queue.qsize())
        return True

    async def deliver_batch_decoded(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int:
        track_stats = self._track_internal_stats
        if track_stats:
            self._record_delivery_call(mode="batch", items=len(items))
        delivered = 0
        for sender, round_id, channel, _instance_id, message in items:
            state = self._rounds.get(round_id)
            if state is None:
                continue

            channel_tag = Channel(channel)
            if channel_tag not in (
                Channel.DUMBO_PRBC,
                Channel.DUMBO_PROOF,
                Channel.DUMBO_MVBA,
            ):
                continue
            state.receive_queue.put_nowait((sender, message))
            if track_stats:
                self._update_queue_peak("receive", state.receive_queue.qsize())
                self._record_inbound_channel(channel_tag.value)
            delivered += 1
        return delivered

    async def abort_round(self, round_id: int) -> None:
        state = self._rounds.pop(round_id, None)
        if state is None:
            return
        if state.task is not None and not state.task.done():
            state.task.cancel()
            try:
                await state.task
            except asyncio.CancelledError:
                pass

    async def shutdown_rounds(self) -> None:
        for round_id in list(self._rounds):
            await self.abort_round(round_id)

    async def _run_round(self, state: DumboRoundState) -> None:
        carryover_queue: asyncio.Queue[tuple[PrbcOutcome, ...]] | None = None
        if self.config.enable_broadcast_pool_reuse:
            carryover_queue = asyncio.Queue(1)
        proof_pk = self.crypto.proof_sig_pk
        proof_sk = self.crypto.proof_sig_sk
        ecdsa_sk = self.crypto.ecdsa_sk
        if proof_pk is None or proof_sk is None or ecdsa_sk is None:
            raise ProtocolInvariantError("Dumbo ACS requires proof signature keys and ECDSA key")

        async def send(recipient: int, message: object) -> None:
            self.emit_event(
                {
                    "kind": "send",
                    "round_id": state.round_id,
                    "recipient": recipient,
                    "channel": _dumbo_channel_for_message(message).value,
                    "instance_id": int(message.leader)
                    if isinstance(message, _DUMBO_PRBC_MESSAGES)
                    else None,
                    "message": message,
                }
            )

        try:
            await dumbo_acs(
                DumboACSParams(
                    sid=f"{state.sid}:dumbo",
                    pid=self.pid,
                    N=self.nodes,
                    f=self.faulty,
                    leader=self.pid,
                    coin_pk=self.crypto.sig_pk,
                    coin_sk=self.crypto.sig_sk,
                    proof_pk=cast(sig.PublicKey, proof_pk),
                    proof_sk=cast(sig.PrivateShare, proof_sk),
                    ecdsa_pks=self.crypto.ecdsa_pks,
                    ecdsa_sk=ecdsa_sk,
                    carryover_grace_ms=self.config.pool_grace_ms
                    if self.config.enable_broadcast_pool_reuse
                    else 0,
                ),
                state.input_queue,
                state.decide_queue,
                state.receive_queue,
                send,
                carryover_queue=carryover_queue,
                output_mode=self.output_mode,
            )
            decision = await state.decide_queue.get()
            if self.output_mode == "payloads":
                self.emit_event(
                    {
                        "kind": "decision",
                        "round_id": state.round_id,
                        "selected_payloads": list(cast(tuple[bytes | None, ...], decision)),
                    }
                )
            else:
                self.emit_event(
                    {
                        "kind": "decision",
                        "round_id": state.round_id,
                        "selected_pids": [
                            pid for pid in cast(tuple[int | None, ...], decision) if pid is not None
                        ],
                    }
                )
            if carryover_queue is not None:
                carryovers = await carryover_queue.get()
                self.emit_event(
                    {
                        "kind": "carryovers",
                        "round_id": state.round_id,
                        "items": [
                            {
                                "leader": outcome.leader,
                                "value": outcome.value,
                                "roothash": outcome.proof.roothash,
                                "proof_payload": serialize_prbc_proof(outcome.proof),
                            }
                            for outcome in carryovers
                        ],
                    }
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.logger.exception("Dumbo ACS round failed", extra={"round": state.round_id})
            self.emit_failure(round_id=state.round_id, exc=exc)
        finally:
            self._rounds.pop(state.round_id, None)
            self.finish_round(state.round_id)
