from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import cast

from honey_acs.crypto.protocols import AcsRuntimeCrypto
from honey_acs.dumbo.dumbo_acs import (
    DumboACSDecision,
    DumboACSParams,
    DumboProofDiffuse,
    dumbo_acs,
)
from honey_acs.exceptions import ProtocolInvariantError
from honey_acs.messages import Channel
from honey_acs.params import HBConfig
from honey_acs.service.base import (
    AcsOutputMode,
    AcsRoundContext,
    AcsService,
    ManagedRoundSession,
    build_proposal_id,
)
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


def _dumbo_channel_for_message(message: object) -> Channel:
    if isinstance(message, _DUMBO_PRBC_MESSAGES):
        return Channel.DUMBO_PRBC
    if isinstance(message, DumboProofDiffuse):
        return Channel.DUMBO_PROOF
    if isinstance(message, _DUMBO_MVBA_MESSAGES):
        return Channel.DUMBO_MVBA
    raise ProtocolInvariantError(f"Unsupported Dumbo ACS message type: {type(message).__name__}")


class DumboRoundSession(ManagedRoundSession):
    def __init__(
        self,
        *,
        context: AcsRoundContext,
        round_id: int,
        sid: str,
        proposal_input: bytes,
    ) -> None:
        super().__init__(context=context, round_id=round_id, sid=sid)
        self.input_queue: asyncio.Queue[bytes] = asyncio.Queue(1)
        self.decide_queue: asyncio.Queue[DumboACSDecision | tuple[bytes | None, ...]] = (
            asyncio.Queue(1)
        )
        self.receive_queue: asyncio.Queue[tuple[int, object]] = asyncio.Queue()
        self.input_queue.put_nowait(proposal_input)
        self._proposal_ids: dict[int, str] = {}
        self._emitted_proposers: set[int] = set()

    async def deliver_decoded(
        self,
        *,
        sender: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        del instance_id
        channel_tag = Channel(channel)
        if channel_tag not in (Channel.DUMBO_PRBC, Channel.DUMBO_PROOF, Channel.DUMBO_MVBA):
            return False
        self.receive_queue.put_nowait((sender, message))
        self.context.record_inbound_channel(channel_tag.value, 1)
        self.context.update_queue_peak("receive", self.receive_queue.qsize())
        return True

    async def _run(self) -> None:
        carryover_queue: asyncio.Queue[tuple[PrbcOutcome, ...]] | None = None
        if self.context.config.enable_broadcast_pool_reuse:
            carryover_queue = asyncio.Queue(1)
        runtime = self.context.crypto
        if runtime.proof is None:
            raise ProtocolInvariantError("Dumbo ACS requires proof signature runtime")

        async def send(recipient: int, message: object) -> None:
            self.context.emit_event(
                {
                    "kind": "send",
                    "round_id": self.round_id,
                    "recipient": recipient,
                    "channel": _dumbo_channel_for_message(message).value,
                    "instance_id": int(message.leader)
                    if isinstance(message, _DUMBO_PRBC_MESSAGES)
                    else None,
                    "message": message,
                }
            )

        async def broadcast(message: object, *, include_self: bool = True) -> None:
            self.context.emit_event(
                {
                    "kind": "broadcast",
                    "round_id": self.round_id,
                    "channel": _dumbo_channel_for_message(message).value,
                    "instance_id": int(message.leader)
                    if isinstance(message, _DUMBO_PRBC_MESSAGES)
                    else None,
                    "include_self": include_self,
                    "message": message,
                }
            )

        def on_prbc_output(outcome: PrbcOutcome) -> None:
            if outcome.leader in self._emitted_proposers:
                return
            proposal_id = build_proposal_id(self.round_id, outcome.leader, outcome.proof.roothash)
            self._proposal_ids[outcome.leader] = proposal_id
            self._emitted_proposers.add(outcome.leader)
            self.context.emit_event(
                {
                    "kind": "proposal_ready",
                    "round_id": self.round_id,
                    "proposer": outcome.leader,
                    "proposal_id": proposal_id,
                    "payload": outcome.value,
                    "digest": outcome.proof.roothash,
                    "certificate": serialize_prbc_proof(outcome.proof),
                }
            )

        try:
            await dumbo_acs(
                DumboACSParams(
                    sid=f"{self.sid}:dumbo",
                    pid=self.context.pid,
                    N=self.context.nodes,
                    f=self.context.faulty,
                    leader=self.context.pid,
                    coin=runtime.coin,
                    proof=runtime.proof,
                    merkle=runtime.merkle,
                    prbc=runtime.prbc,
                    carryover_grace_ms=self.context.config.pool_grace_ms
                    if self.context.config.enable_broadcast_pool_reuse
                    else 0,
                ),
                self.input_queue,
                self.decide_queue,
                self.receive_queue,
                send,
                broadcast=broadcast,
                broadcast_others=lambda message: broadcast(message, include_self=False),
                on_prbc_output=on_prbc_output,
                carryover_queue=carryover_queue,
                output_mode="selected_pids",
            )
            decision = cast(DumboACSDecision, await self.decide_queue.get())
            selected_proposal_ids = []
            for pid in decision:
                if pid is None:
                    continue
                proposal_id = self._proposal_ids.get(pid)
                if proposal_id is None:
                    raise ProtocolInvariantError(
                        f"Dumbo ACS decided proposer {pid} before proposal_ready was emitted"
                    )
                selected_proposal_ids.append(proposal_id)
            self.context.emit_event(
                {
                    "kind": "decision",
                    "round_id": self.round_id,
                    "selected_proposal_ids": selected_proposal_ids,
                }
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.context.logger.exception("Dumbo ACS round failed", extra={"round": self.round_id})
            self.context.emit_failure(self.round_id, exc)
        finally:
            self.context.complete_round(self)


class DumboAcsService(AcsService):
    def __init__(
        self,
        *,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: AcsRuntimeCrypto,
        config: HBConfig | None = None,
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
            event_notifier=event_notifier,
            output_mode=output_mode,
        )
