from __future__ import annotations

import asyncio
import concurrent.futures
import cProfile
import io
import json
import os
import pstats
import threading
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from pathlib import Path
from queue import Queue
from typing import Any, cast

import honey_native

from honey_acs.host_crypto import build_crypto_params_from_json
from honey_acs.messages import Channel, ProtocolEnvelope, ProtocolMessage
from honey_acs.params import HBConfig
from honey_acs.service import (
    AcsOutputMode,
    AcsProtocol,
    AcsService,
)


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
        output_mode: AcsOutputMode = "selected_pids",
    ) -> None:
        self._protocol = protocol
        self._pid = pid
        self._nodes = nodes
        self._faulty = faulty
        self._crypto = crypto
        self._config = config
        self._output_mode = output_mode
        self._service: AcsService | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._processed_commands = 0
        self._command_counts: dict[str, int] = {
            "start_round": 0,
            "push_inbound_wire_batch": 0,
            "pull_outbound_wire_batch": 0,
            "abort_round": 0,
            "stats": 0,
            "shutdown": 0,
        }
        self._batch_item_counts: dict[str, int] = {
            "push_inbound_wire_batch_items": 0,
            "pull_outbound_wire_batch_items": 0,
        }
        self._worker_error: str | None = None
        self._worker_ident = 0
        self._startup_error: str | None = None
        self._worker_ready = threading.Event()
        self._worker_stopped = threading.Event()
        self._outbound_ready = threading.Event()
        self._outbound_signal_lock = threading.Lock()
        self._outbound_signal_pending = False
        self._outbound_signal_enabled = False
        self._outbound_rfd, self._outbound_wfd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self._worker = threading.Thread(
            target=self._worker_main,
            name=f"honey-acs-host-{protocol}-{pid}",
            daemon=True,
        )
        self._profile: cProfile.Profile | None = None
        self._profile_path: Path | None = None
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
        return AcsService(
            protocol=self._protocol,
            pid=self._pid,
            nodes=self._nodes,
            faulty=self._faulty,
            crypto=self._crypto,
            config=self._config,
            event_notifier=self._mark_outbound_ready,
            output_mode=self._output_mode,
        )

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
        if command.kind == "push_inbound_wire_batch":
            payloads = cast(list[bytes], command.payload)
            items = [self._decode_protocol_wire(payload) for payload in payloads]
            return await self._service.deliver_batch_decoded(items)
        if command.kind == "abort_round":
            await self._service.abort_round(cast(int, command.payload))
            return None
        if command.kind == "pull_outbound_wire_batch":
            return self._encode_wire_events(self._drain_service_events(cast(int, command.payload)))
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
        if not self._outbound_signal_enabled:
            return
        if self._outbound_signal_pending:
            return
        with self._outbound_signal_lock:
            if self._outbound_signal_pending:
                return
            try:
                os.write(self._outbound_wfd, b"\x01")
            except BlockingIOError:
                return
            except OSError:
                return
            self._outbound_signal_pending = True

    def _clear_outbound_signal(self) -> None:
        if not self._outbound_signal_enabled:
            return
        with self._outbound_signal_lock:
            if not self._outbound_signal_pending:
                return
            while True:
                try:
                    drained = os.read(self._outbound_rfd, 4096)
                except BlockingIOError:
                    break
                except OSError:
                    break
                if not drained or len(drained) < 4096:
                    break
            self._outbound_signal_pending = False

    def _drain_service_events(self, limit: int) -> list[dict[str, object]]:
        assert self._service is not None
        drained = self._service.drain_events(limit)
        if self._service.event_backlog() == 0:
            self._outbound_ready.clear()
            self._clear_outbound_signal()
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
            kind = str(event.get("kind"))
            if kind not in {"send", "broadcast_send"}:
                encoded.append(event)
                continue

            round_id = cast(int, event["round_id"])
            channel = Channel(str(event["channel"]))
            envelope = ProtocolEnvelope(
                round_id=round_id,
                channel=channel,
                instance_id=cast(int | None, event.get("instance_id")),
                message=cast(ProtocolMessage, event["message"]),
            )
            payload = honey_native.encode_protocol_envelope_py(self._pid, envelope)
            if kind == "send":
                encoded.append(
                    {
                        "kind": "send",
                        "round_id": round_id,
                        "recipient": cast(int, event["recipient"]),
                        "payload": payload,
                    }
                )
                continue

            encoded.append(
                {
                    "kind": "broadcast_send",
                    "round_id": round_id,
                    "include_self": bool(event.get("include_self", True)),
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

    def begin_pull_outbound_wire_batch(self, limit: int = 128) -> None:
        self._command_counts["pull_outbound_wire_batch"] += 1
        if self._pending_pull is not None:
            raise RuntimeError("pull_outbound_wire_batch is already pending")
        self._pending_pull = self._submit_async_command("pull_outbound_wire_batch", limit)

    def finish_pull_outbound_wire_batch(self) -> list[dict[str, object]]:
        if self._pending_pull is None:
            raise RuntimeError("pull_outbound_wire_batch was not started")
        pending_pull = self._pending_pull
        self._pending_pull = None
        try:
            drained = cast(list[dict[str, object]], pending_pull.result())
        except Exception as exc:
            self._fail(exc)
            raise
        self._batch_item_counts["pull_outbound_wire_batch_items"] += len(drained)
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
            }
        )
        return stats

    def outbound_ready(self) -> bool:
        return self._outbound_ready.is_set()

    def outbound_wait_fd(self) -> int:
        self._outbound_signal_enabled = True
        return self._outbound_rfd

    def shutdown(self) -> None:
        if self._closed:
            return
        self._command_counts["shutdown"] += 1
        try:
            self._submit_command("shutdown")
        finally:
            self._closed = True
            self._outbound_ready.clear()
            self._clear_outbound_signal()
            self._worker_stopped.wait()
            self._worker.join(timeout=1.0)
            os.close(self._outbound_rfd)
            os.close(self._outbound_wfd)


def build_persistent_acs_host_from_json(
    *,
    protocol: AcsProtocol,
    pid: int,
    nodes: int,
    faulty: int,
    crypto_json: str,
    config_json: str | None = None,
    output_mode: AcsOutputMode = "selected_pids",
) -> PersistentAcsHost:
    config_payload = cast(dict[str, object], json.loads(config_json)) if config_json else {}
    # Allow config_json to carry "output_mode" (used by bench-driver --mode dumbo
    # which cannot pass it as a separate kwarg).  Pop it before forwarding to HBConfig.
    if "output_mode" in config_payload:
        output_mode = cast(AcsOutputMode, config_payload.pop("output_mode"))
    # Strip any keys that HBConfig doesn't recognise before forwarding to Python.
    valid_hbconfig_fields = {f.name for f in dataclass_fields(HBConfig)}
    config_payload = {k: v for k, v in config_payload.items() if k in valid_hbconfig_fields}
    config_kwargs = cast(dict[str, Any], config_payload)
    return PersistentAcsHost(
        protocol=protocol,
        pid=pid,
        nodes=nodes,
        faulty=faulty,
        crypto=build_crypto_params_from_json(protocol, crypto_json),
        config=HBConfig(**config_kwargs),
        output_mode=output_mode,
    )
