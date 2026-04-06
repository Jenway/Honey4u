from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections.abc import Awaitable, Coroutine
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Any, Literal, cast

from honey.acs.bkr93 import CSParams, run_bkr93_acs_with_send
from honey.acs.dumbo_acs import DumboACSParams, DumboProofDiffuse, dumbo_acs
from honey.data.broadcast_mempool import BroadcastMempool
from honey.infra.exceptions import ProtocolInvariantError
from honey.protocol.messages import Channel, ProtocolEnvelope, ProtocolMessage
from honey.protocol.params import CryptoParams, HBConfig
from honey.runtime.launch.crypto_material import build_crypto_params_from_json
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
    serialize_prbc_proof,
)

type AcsProtocol = Literal["hb", "dumbo"]
type AcsEvent = dict[str, object]

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


@dataclass(slots=True)
class _HBRoundState:
    round_id: int
    sid: str
    coin_recvs: list[asyncio.Queue[tuple[int, object]]]
    aba_recvs: list[asyncio.Queue[tuple[int, object]]]
    rbc_recvs: list[asyncio.Queue[tuple[int, object]]]
    my_rbc_input: asyncio.Queue[bytes]
    task: asyncio.Task[None] | None = None


@dataclass(slots=True)
class _DumboRoundState:
    round_id: int
    sid: str
    input_queue: asyncio.Queue[bytes]
    decide_queue: asyncio.Queue[tuple[bytes | None, ...]]
    receive_queue: asyncio.Queue[tuple[int, object]]
    task: asyncio.Task[None] | None = None


type _RoundState = _HBRoundState | _DumboRoundState


def _dumbo_channel_for_message(message: object) -> Channel:
    if isinstance(message, _DUMBO_PRBC_MESSAGES):
        return Channel.DUMBO_PRBC
    if isinstance(message, DumboProofDiffuse):
        return Channel.DUMBO_PROOF
    if isinstance(message, _DUMBO_MVBA_MESSAGES):
        return Channel.DUMBO_MVBA
    raise ProtocolInvariantError(f"Unsupported Dumbo ACS message type: {type(message).__name__}")


class PersistentAcsHost:
    """Persistent ACS worker intended to be driven by a Rust outer scheduler."""

    def __init__(
        self,
        *,
        protocol: AcsProtocol,
        pid: int,
        nodes: int,
        faulty: int,
        crypto: CryptoParams,
        config: HBConfig | None = None,
        mempool: BroadcastMempool | None = None,
    ) -> None:
        if protocol not in {"hb", "dumbo"}:
            raise ValueError(f"unsupported ACS protocol: {protocol}")

        self._protocol = protocol
        self._pid = pid
        self._nodes = nodes
        self._faulty = faulty
        self._crypto = crypto
        self._config = config or HBConfig()
        self._mempool = mempool or BroadcastMempool(
            max_size=1000,
            expire_rounds=self._config.pool_expire_rounds,
        )
        self._logger = logging.LoggerAdapter(
            logging.getLogger(f"honey.acs_host.{protocol}"),
            extra={"node": pid},
        )
        self._commands: Queue[dict[str, object]] = Queue()
        self._events: Queue[AcsEvent] = Queue()
        self._rounds: dict[int, _RoundState] = {}
        self._rounds_started = 0
        self._rounds_finished = 0
        self._processed_commands = 0
        self._worker_error: str | None = None
        self._worker_running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._command_ready: asyncio.Event | None = None
        self._loop_ready = threading.Event()
        self._closed = False
        self._worker_ident: int | None = None
        self._thread = threading.Thread(
            target=self._run_worker_loop,
            name=f"honey-acs-{protocol}-node-{pid}",
            daemon=True,
        )
        self._thread.start()
        self._loop_ready.wait()

    def _run_worker_loop(self) -> None:
        loop = asyncio.new_event_loop()
        self._worker_ident = threading.get_ident()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._command_ready = asyncio.Event()
        self._loop_ready.set()
        try:
            loop.create_task(self._command_loop())
            loop.call_soon(self._mark_worker_running)
            loop.run_forever()
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    def _mark_worker_running(self) -> None:
        self._worker_running = True

    def _submit[T](self, coroutine: Coroutine[Any, Any, T]) -> T:
        if self._closed:
            raise RuntimeError("ACS host is already shut down")
        loop = self._loop
        if loop is None:
            raise RuntimeError("ACS host loop is not initialized")
        return asyncio.run_coroutine_threadsafe(coroutine, loop).result()

    def start_round(self, *, round_id: int, sid: str, local_input: bytes | str) -> None:
        payload = local_input.encode("utf-8") if isinstance(local_input, str) else local_input
        self._submit(self._start_round(round_id=round_id, sid=sid, local_input=payload))

    def submit_start_round(self, *, round_id: int, sid: str, local_input: bytes | str) -> None:
        if self._closed:
            raise RuntimeError("ACS host is already shut down")
        payload = local_input.encode("utf-8") if isinstance(local_input, str) else local_input
        self._enqueue_command(
            {
                "kind": "start_round",
                "round_id": round_id,
                "sid": sid,
                "local_input": payload,
            }
        )

    def deliver(self, payload: bytes) -> bool:
        return self._submit(self._deliver(payload))

    def submit_deliver(self, payload: bytes) -> None:
        if self._closed:
            raise RuntimeError("ACS host is already shut down")
        self._enqueue_command({"kind": "deliver", "payload": payload})

    def submit_deliver_batch(self, payloads: list[bytes]) -> None:
        if self._closed:
            raise RuntimeError("ACS host is already shut down")
        if not payloads:
            return
        self._enqueue_command({"kind": "deliver_batch", "payloads": payloads})

    def deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        return self._submit(
            self._deliver_decoded(
                sender=sender,
                round_id=round_id,
                channel=channel,
                instance_id=instance_id,
                message=message,
            )
        )

    def submit_deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> None:
        if self._closed:
            raise RuntimeError("ACS host is already shut down")
        self._enqueue_command(
            {
                "kind": "deliver_decoded",
                "sender": sender,
                "round_id": round_id,
                "channel": channel,
                "instance_id": instance_id,
                "message": message,
            }
        )

    def abort_round(self, round_id: int) -> None:
        self._submit(self._abort_round(round_id))

    def drain_events(self, limit: int = 128) -> list[AcsEvent]:
        drained: list[AcsEvent] = []
        while len(drained) < limit:
            try:
                drained.append(self._events.get_nowait())
            except Empty:
                break
        return drained

    def stats(self) -> dict[str, object]:
        return self._submit(self._stats())

    def bridge_stats(self) -> dict[str, object]:
        return {
            "protocol": self._protocol,
            "pid": self._pid,
            "nodes": self._nodes,
            "faulty": self._faulty,
            "worker_ident": self._worker_ident,
            "active_rounds": sorted(self._rounds),
            "rounds_started": self._rounds_started,
            "rounds_finished": self._rounds_finished,
            "processed_commands": self._processed_commands,
            "bridge_queue_size": self._commands.qsize(),
            "event_backlog": self._events.qsize(),
            "worker_running": self._worker_running,
            "worker_error": self._worker_error,
        }

    def shutdown(self) -> None:
        self.close_bridge()

    def close_bridge(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._enqueue_command({"kind": "shutdown"})
        self._thread.join(timeout=5.0)
        if self._thread.is_alive():
            raise RuntimeError("ACS host worker thread did not stop")

    def _enqueue_command(self, command: dict[str, object]) -> None:
        self._commands.put(command)
        loop = self._loop
        command_ready = self._command_ready
        if loop is None or command_ready is None:
            return
        try:
            loop.call_soon_threadsafe(command_ready.set)
        except RuntimeError:
            return

    async def _command_loop(self) -> None:
        command_ready = self._command_ready
        if command_ready is None:
            raise RuntimeError("ACS host command signal is not initialized")
        try:
            while True:
                await command_ready.wait()
                while True:
                    try:
                        command = self._commands.get_nowait()
                    except Empty:
                        command_ready.clear()
                        if self._commands.empty():
                            break
                        command_ready.set()
                        continue

                    self._processed_commands += 1
                    kind = str(command["kind"])

                    if kind == "start_round":
                        round_id = int(command["round_id"])
                        try:
                            await self._start_round(
                                round_id=round_id,
                                sid=str(command["sid"]),
                                local_input=cast(bytes, command["local_input"]),
                            )
                        except Exception as exc:
                            self._emit_failure(round_id=round_id, exc=exc)
                        continue

                    if kind == "deliver":
                        payload = cast(bytes, command["payload"])
                        try:
                            accepted = await self._deliver(payload)
                            if not accepted:
                                continue
                        except Exception as exc:
                            round_id = -1
                            try:
                                _, envelope = ProtocolEnvelope.from_bytes(payload)
                                round_id = envelope.round_id
                            except Exception:
                                pass
                            self._emit_failure(round_id=round_id, exc=exc)
                        continue

                    if kind == "deliver_batch":
                        payloads = cast(list[bytes], command["payloads"])
                        for payload in payloads:
                            try:
                                accepted = await self._deliver(payload)
                                if not accepted:
                                    continue
                            except Exception as exc:
                                round_id = -1
                                try:
                                    _, envelope = ProtocolEnvelope.from_bytes(payload)
                                    round_id = envelope.round_id
                                except Exception:
                                    pass
                                self._emit_failure(round_id=round_id, exc=exc)
                        continue

                    if kind == "deliver_decoded":
                        round_id = int(command["round_id"])
                        try:
                            accepted = await self._deliver_decoded(
                                sender=int(command["sender"]),
                                round_id=round_id,
                                channel=str(command["channel"]),
                                instance_id=cast(int | None, command["instance_id"]),
                                message=command["message"],
                            )
                            if not accepted:
                                continue
                        except Exception as exc:
                            self._emit_failure(round_id=round_id, exc=exc)
                        continue

                    if kind == "shutdown":
                        await self._shutdown_rounds()
                        loop = self._loop
                        if loop is not None:
                            loop.stop()
                        return

                    self._events.put(
                        {
                            "kind": "failure",
                            "round_id": -1,
                            "error": f"unknown command kind: {kind}",
                            "exception_type": "RuntimeError",
                        }
                    )
        except Exception as exc:
            self._worker_error = f"{type(exc).__name__}: {exc}"
            self._events.put(
                {
                    "kind": "failure",
                    "round_id": -1,
                    "error": self._worker_error,
                    "exception_type": type(exc).__name__,
                }
            )
            loop = self._loop
            if loop is not None:
                loop.stop()
            raise

    async def _start_round(self, *, round_id: int, sid: str, local_input: bytes) -> None:
        if round_id in self._rounds:
            raise ValueError(f"round {round_id} is already active")

        if self._protocol == "hb":
            state = _HBRoundState(
                round_id=round_id,
                sid=sid,
                coin_recvs=[asyncio.Queue() for _ in range(self._nodes)],
                aba_recvs=[asyncio.Queue() for _ in range(self._nodes)],
                rbc_recvs=[asyncio.Queue() for _ in range(self._nodes)],
                my_rbc_input=asyncio.Queue(1),
            )
            state.my_rbc_input.put_nowait(local_input)
            state.task = asyncio.create_task(self._run_hb_round(state))
            self._rounds[round_id] = state
        else:
            state = _DumboRoundState(
                round_id=round_id,
                sid=sid,
                input_queue=asyncio.Queue(1),
                decide_queue=asyncio.Queue(1),
                receive_queue=asyncio.Queue(),
            )
            state.input_queue.put_nowait(local_input)
            state.task = asyncio.create_task(self._run_dumbo_round(state))
            self._rounds[round_id] = state

        self._rounds_started += 1

    async def _deliver(self, payload: bytes) -> bool:
        sender, envelope = ProtocolEnvelope.from_bytes(payload)
        return await self._deliver_decoded(
            sender=sender,
            round_id=envelope.round_id,
            channel=envelope.channel.value,
            instance_id=envelope.instance_id,
            message=envelope.message,
        )

    async def _deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        state = self._rounds.get(round_id)
        if state is None:
            return False

        channel_tag = Channel(channel)

        if self._protocol == "hb":
            if not isinstance(state, _HBRoundState):
                raise ProtocolInvariantError("HB ACS host found a non-HB round state")
            if channel_tag == Channel.ACS_COIN:
                if instance_id is None or not 0 <= instance_id < self._nodes:
                    raise ProtocolInvariantError("HB coin envelope missing valid instance_id")
                state.coin_recvs[instance_id].put_nowait((sender, message))
                return True
            if channel_tag == Channel.ACS_ABA:
                if instance_id is None or not 0 <= instance_id < self._nodes:
                    raise ProtocolInvariantError("HB ABA envelope missing valid instance_id")
                state.aba_recvs[instance_id].put_nowait((sender, message))
                return True
            if channel_tag == Channel.ACS_RBC:
                if instance_id is None or not 0 <= instance_id < self._nodes:
                    raise ProtocolInvariantError("HB RBC envelope missing valid instance_id")
                state.rbc_recvs[instance_id].put_nowait((sender, message))
                return True
            return False

        if not isinstance(state, _DumboRoundState):
            raise ProtocolInvariantError("Dumbo ACS host found a non-Dumbo round state")
        if channel_tag not in (
            Channel.DUMBO_PRBC,
            Channel.DUMBO_PROOF,
            Channel.DUMBO_MVBA,
        ):
            return False
        state.receive_queue.put_nowait((sender, message))
        return True

    async def _abort_round(self, round_id: int) -> None:
        state = self._rounds.pop(round_id, None)
        if state is None:
            return
        if state.task is not None and not state.task.done():
            state.task.cancel()
            try:
                await state.task
            except asyncio.CancelledError:
                pass

    async def _shutdown_rounds(self) -> None:
        for round_id in list(self._rounds):
            await self._abort_round(round_id)

    async def _stats(self) -> dict[str, object]:
        return {
            "protocol": self._protocol,
            "pid": self._pid,
            "nodes": self._nodes,
            "faulty": self._faulty,
            "worker_ident": self._worker_ident,
            "active_rounds": sorted(self._rounds),
            "rounds_started": self._rounds_started,
            "rounds_finished": self._rounds_finished,
            "event_backlog": self._events.qsize(),
        }

    async def _emit_send(
        self,
        *,
        round_id: int,
        recipient: int,
        channel: Channel,
        instance_id: int | None,
        message: object,
    ) -> None:
        self._events.put(
            {
                "kind": "send",
                "round_id": round_id,
                "recipient": recipient,
                "channel": channel.value,
                "instance_id": instance_id,
                "message": cast(ProtocolMessage, message),
            }
        )

    def _emit_decision(self, *, round_id: int, values: tuple[bytes | None, ...]) -> None:
        self._events.put(
            {
                "kind": "decision",
                "round_id": round_id,
                "values": list(values),
            }
        )

    def _emit_failure(self, *, round_id: int, exc: Exception) -> None:
        self._events.put(
            {
                "kind": "failure",
                "round_id": round_id,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            }
        )

    def _emit_dumbo_carryovers(self, *, round_id: int, carryovers: tuple[PrbcOutcome, ...]) -> None:
        self._events.put(
            {
                "kind": "carryovers",
                "round_id": round_id,
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

    async def _run_hb_round(self, state: _HBRoundState) -> None:
        tasks: list[asyncio.Task[Any]] = []
        output_queue: asyncio.Queue[tuple[bytes | None, ...]] = asyncio.Queue(1)

        async def send(
            recipient: int,
            channel: Channel,
            instance_id: int | None,
            message: ProtocolMessage,
        ) -> None:
            await self._emit_send(
                round_id=state.round_id,
                recipient=recipient,
                channel=channel,
                instance_id=instance_id,
                message=message,
            )

        try:
            async with asyncio.TaskGroup() as task_group:

                def spawn(coro: Awaitable[Any]) -> asyncio.Task[Any]:
                    task = task_group.create_task(cast(Coroutine[Any, Any, Any], coro))
                    tasks.append(task)
                    return task

                await run_bkr93_acs_with_send(
                    params=CSParams(
                        sid=f"{state.sid}CS",
                        pid=self._pid,
                        N=self._nodes,
                        f=self._faulty,
                        leader=self._pid,
                    ),
                    crypto=self._crypto,
                    task_group=task_group,
                    spawn=spawn,
                    coin_recvs=state.coin_recvs,
                    aba_recvs=state.aba_recvs,
                    rbc_recvs=state.rbc_recvs,
                    mempool=self._mempool,
                    round_id=state.round_id,
                    my_rbc_input=state.my_rbc_input,
                    output_queue=output_queue,
                    logger=self._logger,
                    send=send,
                )
                for task in tasks:
                    if not task.done():
                        task.cancel()

            self._emit_decision(round_id=state.round_id, values=await output_queue.get())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._logger.exception("HB ACS round failed", extra={"round": state.round_id})
            self._emit_failure(round_id=state.round_id, exc=exc)
        finally:
            self._rounds.pop(state.round_id, None)
            self._rounds_finished += 1

    async def _run_dumbo_round(self, state: _DumboRoundState) -> None:
        carryover_queue: asyncio.Queue[tuple[PrbcOutcome, ...]] | None = None
        if self._config.enable_broadcast_pool_reuse:
            carryover_queue = asyncio.Queue(1)

        async def send(recipient: int, message: object) -> None:
            await self._emit_send(
                round_id=state.round_id,
                recipient=recipient,
                channel=_dumbo_channel_for_message(message),
                instance_id=int(message.leader)
                if isinstance(message, _DUMBO_PRBC_MESSAGES)
                else None,
                message=message,
            )

        try:
            await dumbo_acs(
                DumboACSParams(
                    sid=f"{state.sid}:dumbo",
                    pid=self._pid,
                    N=self._nodes,
                    f=self._faulty,
                    leader=self._pid,
                    coin_pk=self._crypto.sig_pk,
                    coin_sk=self._crypto.sig_sk,
                    proof_pk=self._crypto.proof_sig_pk,
                    proof_sk=self._crypto.proof_sig_sk,
                    ecdsa_pks=self._crypto.ecdsa_pks,
                    ecdsa_sk=self._crypto.ecdsa_sk,
                    carryover_grace_ms=self._config.pool_grace_ms
                    if self._config.enable_broadcast_pool_reuse
                    else 0,
                ),
                state.input_queue,
                state.decide_queue,
                state.receive_queue,
                send,
                carryover_queue=carryover_queue,
            )
            self._emit_decision(round_id=state.round_id, values=await state.decide_queue.get())
            if carryover_queue is not None:
                self._emit_dumbo_carryovers(
                    round_id=state.round_id,
                    carryovers=await carryover_queue.get(),
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._logger.exception("Dumbo ACS round failed", extra={"round": state.round_id})
            self._emit_failure(round_id=state.round_id, exc=exc)
        finally:
            self._rounds.pop(state.round_id, None)
            self._rounds_finished += 1


def build_persistent_acs_host_from_json(
    *,
    protocol: AcsProtocol,
    pid: int,
    nodes: int,
    faulty: int,
    crypto_json: str,
    config_json: str | None = None,
) -> PersistentAcsHost:
    config_payload = cast(dict[str, object], json.loads(config_json)) if config_json else {}
    return PersistentAcsHost(
        protocol=protocol,
        pid=pid,
        nodes=nodes,
        faulty=faulty,
        crypto=build_crypto_params_from_json(protocol, crypto_json),
        config=HBConfig(**config_payload),
    )
