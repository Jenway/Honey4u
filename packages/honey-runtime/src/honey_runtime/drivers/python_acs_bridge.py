from __future__ import annotations

import asyncio
import concurrent.futures
import cProfile
import io
import json
import os
import pstats
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Queue
from typing import cast

import honey_native
from honey_acs.service import AcsProtocol, AcsService, DumboAcsService, HoneyBadgerAcsService
from honey_shared.messages import Channel, ProtocolEnvelope
from honey_shared.params import HBConfig

from honey_runtime.drivers.crypto_material import build_crypto_params_from_json


@dataclass(slots=True)
class _HostCommand:
    kind: str
    payload: object | None = None
    response: concurrent.futures.Future[object] | None = None


class PersistentAcsHost:
    """Persistent in-process ACS kernel owned by Rust."""

    def __init__(
        self,
        *,
        protocol: AcsProtocol,
        pid: int,
        nodes: int,
        faulty: int,
        crypto,
        config: HBConfig | None = None,
    ) -> None:
        self._protocol = protocol
        self._pid = pid
        self._nodes = nodes
        self._faulty = faulty
        self._crypto = crypto
        self._config = config
        self._service: AcsService | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._processed_commands = 0
        self._command_counts: dict[str, int] = {
            "start_round": 0,
            "deliver_decoded": 0,
            "deliver_batch_decoded": 0,
            "push_inbound_batch": 0,
            "push_inbound_wire_batch": 0,
            "exchange_batches": 0,
            "pull_outbound_batch": 0,
            "pull_outbound_wire_batch": 0,
            "drain_events": 0,
            "abort_round": 0,
            "stats": 0,
            "shutdown": 0,
        }
        self._batch_item_counts: dict[str, int] = {
            "deliver_batch_decoded_items": 0,
            "push_inbound_batch_items": 0,
            "push_inbound_wire_batch_items": 0,
            "exchange_inbound_items": 0,
            "exchange_outbound_items": 0,
            "pull_outbound_batch_items": 0,
            "pull_outbound_wire_batch_items": 0,
            "drain_events_items": 0,
        }
        self._worker_error: str | None = None
        self._worker_ident = 0
        self._startup_error: str | None = None
        self._worker_ready = threading.Event()
        self._worker_stopped = threading.Event()
        self._outbound_ready = threading.Event()
        self._worker = threading.Thread(
            target=self._worker_main,
            name=f"honey-acs-host-{protocol}-{pid}",
            daemon=True,
        )
        self._profile: cProfile.Profile | None = None
        self._profile_path: Path | None = None
        self._track_exchange_timing = os.environ.get("HONEY_PROFILE_ACS_HOST_TIMING") is not None
        self._exchange_timing_seconds = {
            "deliver": 0.0,
            "pump": 0.0,
            "drain": 0.0,
            "total": 0.0,
        }
        self._pending_pull: concurrent.futures.Future[object] | None = None
        self._commands: Queue[_HostCommand] = Queue()
        self._command_task: asyncio.Task[None] | None = None
        self._worker.start()
        self._worker_ready.wait()
        if self._startup_error is not None:
            self._closed = True
            self._worker_stopped.wait()
            raise RuntimeError(self._startup_error)

    def _build_service(self) -> AcsService:
        if self._protocol == "hb":
            return HoneyBadgerAcsService(
                pid=self._pid,
                nodes=self._nodes,
                faulty=self._faulty,
                crypto=self._crypto,
                config=self._config,
                event_notifier=self._mark_outbound_ready,
            )
        if self._protocol == "dumbo":
            return DumboAcsService(
                pid=self._pid,
                nodes=self._nodes,
                faulty=self._faulty,
                crypto=self._crypto,
                config=self._config,
                event_notifier=self._mark_outbound_ready,
            )
        raise ValueError(f"unsupported ACS protocol: {self._protocol}")

    def _worker_main(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._worker_ident = threading.get_ident()
        try:
            self._service = self._build_service()
            self._maybe_start_profile(self._pid)
            self._command_task = loop.create_task(self._command_loop())
            self._worker_ready.set()
            loop.run_forever()
        except Exception as exc:
            self._worker_error = f"{type(exc).__name__}: {exc}"
            self._startup_error = self._worker_error
            self._worker_ready.set()
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            finally:
                self._finalize_profile()
                asyncio.set_event_loop(None)
                loop.close()
                self._worker_stopped.set()

    async def _command_loop(self) -> None:
        assert self._loop is not None
        while True:
            command = await asyncio.to_thread(self._commands.get)
            try:
                result = await self._execute_command(command)
            except Exception as exc:
                self._fail(exc)
                if command.response is not None:
                    command.response.set_exception(exc)
                if command.kind == "shutdown":
                    self._loop.stop()
                    break
            else:
                if command.response is not None:
                    command.response.set_result(result)
                if command.kind == "shutdown":
                    self._loop.stop()
                    break

    async def _execute_command(self, command: _HostCommand) -> object | None:
        assert self._service is not None
        if command.kind == "start_round":
            round_id, sid, proposal_input = cast(tuple[int, str, bytes], command.payload)
            await self._service.start_round(
                round_id=round_id,
                sid=sid,
                proposal_input=proposal_input,
            )
            return None
        if command.kind == "deliver_decoded":
            sender, round_id, channel, instance_id, message = cast(
                tuple[int, int, str, int | None, object],
                command.payload,
            )
            return await self._service.deliver_decoded(
                sender=sender,
                round_id=round_id,
                channel=channel,
                instance_id=instance_id,
                message=message,
            )
        if command.kind in {"deliver_batch_decoded", "push_inbound_batch"}:
            items = cast(list[tuple[int, int, str, int | None, object]], command.payload)
            return await self._service.deliver_batch_decoded(items)
        if command.kind == "push_inbound_wire_batch":
            payloads = cast(list[bytes], command.payload)
            items = [self._decode_protocol_wire(payload) for payload in payloads]
            return await self._service.deliver_batch_decoded(items)
        if command.kind == "abort_round":
            await self._service.abort_round(cast(int, command.payload))
            return None
        if command.kind == "drain_events":
            return self._drain_service_events(cast(int, command.payload))
        if command.kind == "pull_outbound_batch":
            return self._drain_service_events(cast(int, command.payload))
        if command.kind == "pull_outbound_wire_batch":
            return self._encode_wire_events(self._drain_service_events(cast(int, command.payload)))
        if command.kind == "exchange_batches":
            items, limit = cast(
                tuple[list[tuple[int, int, str, int | None, object]], int],
                command.payload,
            )
            track_timing = self._track_exchange_timing
            total_start = time.perf_counter() if track_timing else 0.0
            if items:
                deliver_start = time.perf_counter() if track_timing else 0.0
                await self._service.deliver_batch_decoded(items)
                if track_timing:
                    self._exchange_timing_seconds["deliver"] += time.perf_counter() - deliver_start
            pump_start = time.perf_counter() if track_timing else 0.0
            await self._yield_control()
            if track_timing:
                self._exchange_timing_seconds["pump"] += time.perf_counter() - pump_start
            drain_start = time.perf_counter() if track_timing else 0.0
            result = self._service.drain_events(limit)
            if track_timing:
                self._exchange_timing_seconds["drain"] += time.perf_counter() - drain_start
                self._exchange_timing_seconds["total"] += time.perf_counter() - total_start
            return result
        if command.kind == "stats":
            return self._service.stats()
        if command.kind == "shutdown":
            await self._service.shutdown_rounds()
            return None
        raise RuntimeError(f"unknown host command: {command.kind}")

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("ACS host is already shut down")
        if self._startup_error is not None:
            raise RuntimeError(self._startup_error)
        if self._service is None:
            raise RuntimeError("ACS host worker is not ready")

    def _fail(self, exc: BaseException) -> None:
        self._worker_error = f"{type(exc).__name__}: {exc}"

    def _mark_outbound_ready(self) -> None:
        self._outbound_ready.set()

    def _drain_service_events(self, limit: int) -> list[dict[str, object]]:
        assert self._service is not None
        drained = self._service.drain_events(limit)
        if self._service.event_backlog() == 0:
            self._outbound_ready.clear()
        return drained

    def _submit_command[T](
        self,
        kind: str,
        payload: object | None = None,
        *,
        wait: bool = True,
    ) -> T | None:
        self._ensure_open()
        self._processed_commands += 1
        response: concurrent.futures.Future[object] | None = (
            concurrent.futures.Future() if wait else None
        )
        command = _HostCommand(kind=kind, payload=payload, response=response)
        self._commands.put(command)
        if not wait:
            return None
        assert response is not None
        try:
            return cast(T, response.result())
        except Exception as exc:
            self._fail(exc)
            raise

    def _submit_async_command(
        self,
        kind: str,
        payload: object | None = None,
    ) -> concurrent.futures.Future[object]:
        self._ensure_open()
        self._processed_commands += 1
        response: concurrent.futures.Future[object] = concurrent.futures.Future()
        command = _HostCommand(kind=kind, payload=payload, response=response)
        self._commands.put(command)
        return response

    async def _yield_control(self, iterations: int = 1) -> None:
        for _ in range(iterations):
            await asyncio.sleep(0)

    def _maybe_start_profile(self, pid: int) -> None:
        target_pid = os.environ.get("HONEY_PROFILE_ACS_HOST_PID")
        output_dir = os.environ.get("HONEY_PROFILE_DIR")
        if target_pid is None or output_dir is None:
            return
        if target_pid != "all" and int(target_pid) != pid:
            return

        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        self._profile_path = directory / f"{self._protocol}_acs_host_pid{pid}.prof"
        self._profile = cProfile.Profile()
        self._profile.enable()

    def _finalize_profile(self) -> None:
        if self._profile is None or self._profile_path is None:
            return

        self._profile.disable()
        self._profile.dump_stats(str(self._profile_path))

        sort_by = os.environ.get("HONEY_PROFILE_SORT", "cumulative")
        limit = int(os.environ.get("HONEY_PROFILE_LIMIT", "80"))
        buffer = io.StringIO()
        stats = pstats.Stats(self._profile, stream=buffer)
        stats.sort_stats(sort_by)
        stats.print_stats(limit)
        self._profile_path.with_suffix(".txt").write_text(
            f"protocol={self._protocol}\nworker_ident={self._worker_ident}\n"
            f"sort={sort_by}\nlimit={limit}\n\n{buffer.getvalue()}",
            encoding="utf-8",
        )

    @staticmethod
    def _decode_protocol_wire(payload: bytes) -> tuple[int, int, str, int | None, object]:
        sender, envelope = cast(
            tuple[int, ProtocolEnvelope], honey_native.decode_protocol_envelope_py(payload)
        )
        return (
            sender,
            envelope.round_id,
            str(envelope.channel),
            envelope.instance_id,
            envelope.message,
        )

    def _encode_wire_events(self, events: list[dict[str, object]]) -> list[dict[str, object]]:
        encoded: list[dict[str, object]] = []
        for event in events:
            if str(event.get("kind")) != "send":
                encoded.append(event)
                continue

            channel = Channel(str(event["channel"]))
            envelope = ProtocolEnvelope(
                round_id=int(event["round_id"]),
                channel=channel,
                instance_id=cast(int | None, event.get("instance_id")),
                message=event["message"],
            )
            payload = honey_native.encode_protocol_envelope_py(self._pid, envelope)
            encoded.append(
                {
                    "kind": "send",
                    "round_id": int(event["round_id"]),
                    "recipient": int(event["recipient"]),
                    "payload": payload,
                }
            )
        return encoded

    def start_round(self, *, round_id: int, sid: str, proposal_input: bytes | str) -> None:
        self._command_counts["start_round"] += 1
        payload = (
            proposal_input.encode("utf-8") if isinstance(proposal_input, str) else proposal_input
        )
        self._submit_command("start_round", (round_id, sid, payload))

    def deliver_decoded(
        self,
        *,
        sender: int,
        round_id: int,
        channel: str,
        instance_id: int | None,
        message: object,
    ) -> bool:
        self._command_counts["deliver_decoded"] += 1
        delivered = self._submit_command(
            "deliver_decoded",
            (sender, round_id, channel, instance_id, message),
        )
        return cast(bool, delivered)

    def deliver_batch_decoded(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int:
        self._command_counts["deliver_batch_decoded"] += 1
        self._batch_item_counts["deliver_batch_decoded_items"] += len(items)
        delivered = self._submit_command("deliver_batch_decoded", items)
        return cast(int, delivered)

    def push_inbound_batch(
        self,
        items: list[tuple[int, int, str, int | None, object]],
    ) -> int:
        self._command_counts["push_inbound_batch"] += 1
        self._batch_item_counts["push_inbound_batch_items"] += len(items)
        if not items:
            return 0
        self._submit_command("push_inbound_batch", items, wait=False)
        return len(items)

    def push_inbound_wire_batch(self, items: list[bytes]) -> int:
        self._command_counts["push_inbound_wire_batch"] += 1
        self._batch_item_counts["push_inbound_wire_batch_items"] += len(items)
        if not items:
            return 0
        self._submit_command("push_inbound_wire_batch", items, wait=False)
        return len(items)

    def abort_round(self, round_id: int) -> None:
        self._command_counts["abort_round"] += 1
        self._submit_command("abort_round", round_id)

    def drain_events(self, limit: int = 128) -> list[dict[str, object]]:
        self._command_counts["drain_events"] += 1
        drained = self._submit_command("drain_events", limit)
        drained = cast(list[dict[str, object]], drained)
        self._batch_item_counts["drain_events_items"] += len(drained)
        return drained

    def pull_outbound_batch(self, limit: int = 128) -> list[dict[str, object]]:
        self._command_counts["pull_outbound_batch"] += 1
        drained = self._submit_command("pull_outbound_batch", limit)
        drained = cast(list[dict[str, object]], drained)
        self._batch_item_counts["pull_outbound_batch_items"] += len(drained)
        return drained

    def begin_pull_outbound_batch(self, limit: int = 128) -> None:
        self._command_counts["pull_outbound_batch"] += 1
        if self._pending_pull is not None:
            raise RuntimeError("pull_outbound_batch is already pending")
        self._pending_pull = self._submit_async_command("pull_outbound_batch", limit)

    def finish_pull_outbound_batch(self) -> list[dict[str, object]]:
        if self._pending_pull is None:
            raise RuntimeError("pull_outbound_batch was not started")
        pending_pull = self._pending_pull
        self._pending_pull = None
        try:
            drained = cast(list[dict[str, object]], pending_pull.result())
        except Exception as exc:
            self._fail(exc)
            raise
        self._batch_item_counts["pull_outbound_batch_items"] += len(drained)
        return drained

    def begin_pull_outbound_wire_batch(self, limit: int = 128) -> None:
        self._command_counts["pull_outbound_wire_batch"] += 1
        if self._pending_pull is not None:
            raise RuntimeError("pull_outbound_batch is already pending")
        self._pending_pull = self._submit_async_command("pull_outbound_wire_batch", limit)

    def finish_pull_outbound_wire_batch(self) -> list[dict[str, object]]:
        if self._pending_pull is None:
            raise RuntimeError("pull_outbound_batch was not started")
        pending_pull = self._pending_pull
        self._pending_pull = None
        try:
            drained = cast(list[dict[str, object]], pending_pull.result())
        except Exception as exc:
            self._fail(exc)
            raise
        self._batch_item_counts["pull_outbound_wire_batch_items"] += len(drained)
        return drained

    def exchange_batches(
        self,
        items: list[tuple[int, int, str, int | None, object]],
        limit: int = 128,
    ) -> list[dict[str, object]]:
        self._command_counts["exchange_batches"] += 1
        self._batch_item_counts["exchange_inbound_items"] += len(items)
        drained = self._submit_command("exchange_batches", (items, limit))
        drained = cast(list[dict[str, object]], drained)
        self._batch_item_counts["exchange_outbound_items"] += len(drained)
        return drained

    def stats(self) -> dict[str, object]:
        self._command_counts["stats"] += 1
        return self.kernel_stats()

    def kernel_stats(self) -> dict[str, object]:
        stats = self._submit_command("stats")
        stats = cast(dict[str, object], stats)
        stats.update(
            {
                "worker_ident": self._worker_ident,
                "processed_commands": self._processed_commands,
                "bridge_queue_size": self._commands.qsize(),
                "worker_running": not self._closed,
                "worker_error": self._worker_error,
                "command_counts": dict(self._command_counts),
                "batch_item_counts": dict(self._batch_item_counts),
                "exchange_timing_seconds": dict(self._exchange_timing_seconds),
            }
        )
        return stats

    def outbound_ready(self) -> bool:
        return self._outbound_ready.is_set()

    def shutdown(self) -> None:
        if self._closed:
            return
        self._command_counts["shutdown"] += 1
        try:
            self._submit_command("shutdown")
        finally:
            self._closed = True
            self._outbound_ready.clear()
            self._worker_stopped.wait()
            self._worker.join(timeout=1.0)


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
