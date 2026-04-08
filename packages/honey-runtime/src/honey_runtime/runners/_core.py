from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

import honey_native
from honey_legacy_node.dumbo.core import DumboBFT
from honey_legacy_node.honeybadger.core import HoneyBadgerBFT
from honey_shared.params import CommonParams, CryptoParams, HBConfig

from honey_runtime.drivers.crypto_material import build_materials
from honey_runtime.infra.logging import setup_logging
from honey_runtime.simulation import DeterministicNetworkSimulator

_HONEY_NODE_BINARY: Path | None = None
TxInputMode = Literal["json_str", "bytes"]
TransportBackend = Literal["tcp", "quic"]
AcsRuntimeProtocol = Literal["hb", "dumbo"]


@dataclass(frozen=True)
class MetricTimingSummary:
    sample_count: int = 0
    total_seconds: float = 0.0
    max_seconds: float = 0.0


@dataclass(frozen=True)
class NodeQueuePeaks:
    raw_inbound_messages: int = 0
    raw_outbound_messages: int = 0
    transport_inbound: int = 0
    transport_outbound: int = 0
    mailbox_round_inbox: int = 0


@dataclass(frozen=True)
class TransportStats:
    sent_frames: int = 0
    recv_frames: int = 0
    connect_retries: int = 0
    send_retries: int = 0


@dataclass(frozen=True)
class MultiprocessNodeResult:
    pid: int
    rounds: int
    delivered: int
    round_build_latencies: tuple[float, ...] = ()
    round_latencies: tuple[float, ...] = ()
    round_wall_latencies: tuple[float, ...] = ()
    round_proposed_counts: tuple[int, ...] = ()
    round_delivered_counts: tuple[int, ...] = ()
    origin_tx_latencies: tuple[float, ...] = ()
    origin_tx_latencies_by_round: tuple[tuple[float, ...], ...] = ()
    chain_digest: str | None = None
    ledger_path: str | None = None
    subprotocol_timings: dict[str, MetricTimingSummary] = field(default_factory=dict)
    queue_peaks: NodeQueuePeaks = field(default_factory=NodeQueuePeaks)
    transport_stats: TransportStats = field(default_factory=TransportStats)


@dataclass(frozen=True)
class RustDrivenAcsNodeResult:
    pid: int
    worker_ident: int
    rounds_started: int
    rounds_finished: int
    processed_commands: int = 0
    start_round_calls: int = 0
    push_inbound_batch_calls: int = 0
    push_inbound_batch_items: int = 0
    exchange_batches_calls: int = 0
    exchange_inbound_items: int = 0
    exchange_outbound_items: int = 0
    pull_outbound_batch_calls: int = 0
    pull_outbound_batch_items: int = 0
    stats_calls: int = 0
    bridge_queue_size: int = 0
    worker_running: bool = False
    worker_error: str | None = None
    exchange_deliver_seconds: float = 0.0
    exchange_pump_seconds: float = 0.0
    exchange_drain_seconds: float = 0.0
    exchange_total_seconds: float = 0.0


@dataclass(frozen=True)
class RustDrivenHostPhaseStats:
    pid: int
    push_calls: int = 0
    push_items: int = 0
    max_push_batch: int = 0
    push_seconds: float = 0.0
    pull_calls: int = 0
    empty_pull_calls: int = 0
    pulled_events: int = 0
    max_pull_batch: int = 0
    pull_limit_hits: int = 0
    pull_seconds: float = 0.0


@dataclass(frozen=True)
class RustDrivenDriverPhaseStats:
    sweep_count: int = 0
    active_sweeps: int = 0
    idle_sweeps: int = 0
    idle_backoff_count: int = 0
    total_pending_deliveries: int = 0
    max_pending_deliveries: int = 0
    total_pushed_items: int = 0
    total_pulled_events: int = 0
    max_pull_batch: int = 0
    pull_limit_hits: int = 0
    total_push_seconds: float = 0.0
    total_pull_seconds: float = 0.0
    host_stats: tuple[RustDrivenHostPhaseStats, ...] = ()


@dataclass(frozen=True)
class RustDrivenAcsRoundResult:
    round_id: int
    selected_count: int
    send_events: int
    selected_pids: tuple[int, ...] = ()
    drive_stats: RustDrivenDriverPhaseStats = field(default_factory=RustDrivenDriverPhaseStats)
    settle_stats: RustDrivenDriverPhaseStats = field(default_factory=RustDrivenDriverPhaseStats)


@dataclass(frozen=True)
class RustDrivenAcsRunResult:
    protocol: str
    sid: str
    nodes: tuple[RustDrivenAcsNodeResult, ...]
    rounds: tuple[RustDrivenAcsRoundResult, ...]


@dataclass(frozen=True)
class RustDrivenHoneyBadgerRoundResult:
    round_id: int
    selected_count: int
    selected_pids: tuple[int, ...]
    acs_send_events: int
    tpke_bundle_events: int
    delivered_count: int
    block_size: int
    block_digest: str
    chain_digest: str
    build_seconds: float
    acs_seconds: float
    tpke_seconds: float
    tpke_local_share_seconds: float
    tpke_combine_seconds: float
    protocol_seconds: float
    wall_seconds: float
    acs_drive_stats: RustDrivenDriverPhaseStats = field(default_factory=RustDrivenDriverPhaseStats)
    acs_settle_stats: RustDrivenDriverPhaseStats = field(default_factory=RustDrivenDriverPhaseStats)


@dataclass(frozen=True)
class RustDrivenHoneyBadgerRunResult:
    protocol: str
    sid: str
    chain_digest: str | None
    nodes: tuple[RustDrivenAcsNodeResult, ...]
    rounds: tuple[RustDrivenHoneyBadgerRoundResult, ...]
    acs_protocol: str = "hb"


@dataclass(frozen=True)
class RustDrivenDumboRoundResult:
    round_id: int
    selected_count: int
    selected_pids: tuple[int, ...]
    acs_send_events: int
    block_size: int
    block_digest: str
    chain_digest: str
    acs_seconds: float
    block_resolve_seconds: float
    wall_seconds: float
    # TPKE outer-shell fields (non-zero when has_tpke=True in driver output)
    delivered_count: int = 0
    tpke_seconds: float = 0.0
    tpke_bundle_events: int = 0
    build_seconds: float = 0.0
    acs_drive_stats: RustDrivenDriverPhaseStats = field(default_factory=RustDrivenDriverPhaseStats)
    acs_settle_stats: RustDrivenDriverPhaseStats = field(default_factory=RustDrivenDriverPhaseStats)


@dataclass(frozen=True)
class RustDrivenDumboNodeResult:
    pid: int
    worker_ident: int
    rounds_started: int
    rounds_finished: int
    processed_commands: int = 0
    start_round_calls: int = 0
    push_inbound_batch_calls: int = 0
    push_inbound_batch_items: int = 0
    pull_outbound_batch_calls: int = 0
    pull_outbound_batch_items: int = 0
    exchange_batches_calls: int = 0
    exchange_inbound_items: int = 0
    exchange_outbound_items: int = 0
    stats_calls: int = 0
    bridge_queue_size: int = 0
    worker_running: bool = False
    worker_error: str | None = None
    exchange_deliver_seconds: float = 0.0
    exchange_pump_seconds: float = 0.0
    exchange_drain_seconds: float = 0.0
    exchange_total_seconds: float = 0.0
    mempool_size: int = 0


@dataclass(frozen=True)
class RustDrivenDumboRunResult:
    protocol: str
    sid: str
    nodes_count: int
    faulty: int
    enable_pool_reuse: bool
    chain_digest: str | None
    nodes: tuple[RustDrivenDumboNodeResult, ...]
    rounds: tuple[RustDrivenDumboRoundResult, ...]


def _decode_result_payload(pid: int, value: dict[str, Any]) -> MultiprocessNodeResult:
    return MultiprocessNodeResult(
        pid=pid,
        rounds=int(value["rounds"]),
        delivered=int(value["delivered"]),
        round_build_latencies=tuple(float(v) for v in value.get("round_build_latencies", ())),
        round_latencies=tuple(float(v) for v in value.get("round_latencies", ())),
        round_wall_latencies=tuple(float(v) for v in value.get("round_wall_latencies", ())),
        round_proposed_counts=tuple(int(v) for v in value.get("round_proposed_counts", ())),
        round_delivered_counts=tuple(int(v) for v in value.get("round_delivered_counts", ())),
        origin_tx_latencies=tuple(float(v) for v in value.get("origin_tx_latencies", ())),
        origin_tx_latencies_by_round=tuple(
            tuple(float(sample) for sample in values)
            for values in value.get("origin_tx_latencies_by_round", ())
        ),
        chain_digest=str(value["chain_digest"]) if value.get("chain_digest") is not None else None,
        ledger_path=str(value["ledger_path"]) if value.get("ledger_path") is not None else None,
        subprotocol_timings={
            name: MetricTimingSummary(
                sample_count=int(summary.get("sample_count", 0)),
                total_seconds=float(summary.get("total_seconds", 0.0)),
                max_seconds=float(summary.get("max_seconds", 0.0)),
            )
            for name, summary in value.get("subprotocol_timings", {}).items()
        },
        queue_peaks=NodeQueuePeaks(
            raw_inbound_messages=int(value.get("queue_peaks", {}).get("raw_inbound_messages", 0)),
            raw_outbound_messages=int(value.get("queue_peaks", {}).get("raw_outbound_messages", 0)),
            transport_inbound=int(value.get("queue_peaks", {}).get("transport_inbound", 0)),
            transport_outbound=int(value.get("queue_peaks", {}).get("transport_outbound", 0)),
            mailbox_round_inbox=int(value.get("queue_peaks", {}).get("mailbox_round_inbox", 0)),
        ),
        transport_stats=TransportStats(
            sent_frames=int(value.get("transport_stats", {}).get("sent_frames", 0)),
            recv_frames=int(value.get("transport_stats", {}).get("recv_frames", 0)),
            connect_retries=int(value.get("transport_stats", {}).get("connect_retries", 0)),
            send_retries=int(value.get("transport_stats", {}).get("send_retries", 0)),
        ),
    )


def _decode_rust_driven_host_phase_stats(value: dict[str, Any]) -> RustDrivenHostPhaseStats:
    return RustDrivenHostPhaseStats(
        pid=int(value.get("pid", 0)),
        push_calls=int(value.get("push_calls", 0)),
        push_items=int(value.get("push_items", 0)),
        max_push_batch=int(value.get("max_push_batch", 0)),
        push_seconds=float(value.get("push_seconds", 0.0)),
        pull_calls=int(value.get("pull_calls", 0)),
        empty_pull_calls=int(value.get("empty_pull_calls", 0)),
        pulled_events=int(value.get("pulled_events", 0)),
        max_pull_batch=int(value.get("max_pull_batch", 0)),
        pull_limit_hits=int(value.get("pull_limit_hits", 0)),
        pull_seconds=float(value.get("pull_seconds", 0.0)),
    )


def _decode_rust_driven_driver_phase_stats(
    value: dict[str, Any],
) -> RustDrivenDriverPhaseStats:
    return RustDrivenDriverPhaseStats(
        sweep_count=int(value.get("sweep_count", 0)),
        active_sweeps=int(value.get("active_sweeps", 0)),
        idle_sweeps=int(value.get("idle_sweeps", 0)),
        idle_backoff_count=int(value.get("idle_backoff_count", 0)),
        total_pending_deliveries=int(value.get("total_pending_deliveries", 0)),
        max_pending_deliveries=int(value.get("max_pending_deliveries", 0)),
        total_pushed_items=int(value.get("total_pushed_items", 0)),
        total_pulled_events=int(value.get("total_pulled_events", 0)),
        max_pull_batch=int(value.get("max_pull_batch", 0)),
        pull_limit_hits=int(value.get("pull_limit_hits", 0)),
        total_push_seconds=float(value.get("total_push_seconds", 0.0)),
        total_pull_seconds=float(value.get("total_pull_seconds", 0.0)),
        host_stats=tuple(
            _decode_rust_driven_host_phase_stats(cast(dict[str, Any], host_stats))
            for host_stats in value.get("host_stats", ())
        ),
    )


def _decode_rust_driven_acs_payload(value: dict[str, Any]) -> RustDrivenAcsRunResult:
    return RustDrivenAcsRunResult(
        protocol=str(value["protocol"]),
        sid=str(value["sid"]),
        nodes=tuple(
            RustDrivenAcsNodeResult(
                pid=int(node["pid"]),
                worker_ident=int(node["worker_ident"]),
                rounds_started=int(node["rounds_started"]),
                rounds_finished=int(node["rounds_finished"]),
                processed_commands=int(node.get("processed_commands", 0)),
                start_round_calls=int(node.get("start_round_calls", 0)),
                push_inbound_batch_calls=int(node.get("push_inbound_batch_calls", 0)),
                push_inbound_batch_items=int(node.get("push_inbound_batch_items", 0)),
                exchange_batches_calls=int(node.get("exchange_batches_calls", 0)),
                exchange_inbound_items=int(node.get("exchange_inbound_items", 0)),
                exchange_outbound_items=int(node.get("exchange_outbound_items", 0)),
                pull_outbound_batch_calls=int(node.get("pull_outbound_batch_calls", 0)),
                pull_outbound_batch_items=int(node.get("pull_outbound_batch_items", 0)),
                stats_calls=int(node.get("stats_calls", 0)),
                bridge_queue_size=int(node.get("bridge_queue_size", 0)),
                worker_running=bool(node.get("worker_running", False)),
                worker_error=(
                    str(node["worker_error"]) if node.get("worker_error") is not None else None
                ),
                exchange_deliver_seconds=float(node.get("exchange_deliver_seconds", 0.0)),
                exchange_pump_seconds=float(node.get("exchange_pump_seconds", 0.0)),
                exchange_drain_seconds=float(node.get("exchange_drain_seconds", 0.0)),
                exchange_total_seconds=float(node.get("exchange_total_seconds", 0.0)),
            )
            for node in value.get("nodes", ())
        ),
        rounds=tuple(
            RustDrivenAcsRoundResult(
                round_id=int(round_data["round_id"]),
                selected_count=int(round_data["selected_count"]),
                selected_pids=tuple(int(pid) for pid in round_data.get("selected_pids", ())),
                send_events=int(round_data["send_events"]),
                drive_stats=_decode_rust_driven_driver_phase_stats(
                    cast(dict[str, Any], round_data.get("drive_stats", {}))
                ),
                settle_stats=_decode_rust_driven_driver_phase_stats(
                    cast(dict[str, Any], round_data.get("settle_stats", {}))
                ),
            )
            for round_data in value.get("rounds", ())
        ),
    )


def _decode_rust_driven_honeybadger_payload(
    value: dict[str, Any],
) -> RustDrivenHoneyBadgerRunResult:
    return RustDrivenHoneyBadgerRunResult(
        protocol=str(value["protocol"]),
        acs_protocol=str(value.get("acs_protocol", "hb")),
        sid=str(value["sid"]),
        chain_digest=str(value["chain_digest"]) if value.get("chain_digest") is not None else None,
        nodes=tuple(
            RustDrivenAcsNodeResult(
                pid=int(node["pid"]),
                worker_ident=int(node["worker_ident"]),
                rounds_started=int(node["rounds_started"]),
                rounds_finished=int(node["rounds_finished"]),
                processed_commands=int(node.get("processed_commands", 0)),
                start_round_calls=int(node.get("start_round_calls", 0)),
                push_inbound_batch_calls=int(node.get("push_inbound_batch_calls", 0)),
                push_inbound_batch_items=int(node.get("push_inbound_batch_items", 0)),
                exchange_batches_calls=int(node.get("exchange_batches_calls", 0)),
                exchange_inbound_items=int(node.get("exchange_inbound_items", 0)),
                exchange_outbound_items=int(node.get("exchange_outbound_items", 0)),
                pull_outbound_batch_calls=int(node.get("pull_outbound_batch_calls", 0)),
                pull_outbound_batch_items=int(node.get("pull_outbound_batch_items", 0)),
                stats_calls=int(node.get("stats_calls", 0)),
                bridge_queue_size=int(node.get("bridge_queue_size", 0)),
                worker_running=bool(node.get("worker_running", False)),
                worker_error=(
                    str(node["worker_error"]) if node.get("worker_error") is not None else None
                ),
                exchange_deliver_seconds=float(node.get("exchange_deliver_seconds", 0.0)),
                exchange_pump_seconds=float(node.get("exchange_pump_seconds", 0.0)),
                exchange_drain_seconds=float(node.get("exchange_drain_seconds", 0.0)),
                exchange_total_seconds=float(node.get("exchange_total_seconds", 0.0)),
            )
            for node in value.get("nodes", ())
        ),
        rounds=tuple(
            RustDrivenHoneyBadgerRoundResult(
                round_id=int(round_data["round_id"]),
                selected_count=int(round_data["selected_count"]),
                selected_pids=tuple(int(pid) for pid in round_data.get("selected_pids", ())),
                acs_send_events=int(round_data["acs_send_events"]),
                tpke_bundle_events=int(round_data["tpke_bundle_events"]),
                delivered_count=int(round_data["delivered_count"]),
                block_size=int(round_data["block_size"]),
                block_digest=str(round_data["block_digest"]),
                chain_digest=str(round_data["chain_digest"]),
                build_seconds=float(round_data["build_seconds"]),
                acs_seconds=float(round_data["acs_seconds"]),
                tpke_seconds=float(round_data["tpke_seconds"]),
                tpke_local_share_seconds=float(round_data["tpke_local_share_seconds"]),
                tpke_combine_seconds=float(round_data["tpke_combine_seconds"]),
                protocol_seconds=float(round_data["protocol_seconds"]),
                wall_seconds=float(round_data["wall_seconds"]),
                acs_drive_stats=_decode_rust_driven_driver_phase_stats(
                    cast(dict[str, Any], round_data.get("acs_drive_stats", {}))
                ),
                acs_settle_stats=_decode_rust_driven_driver_phase_stats(
                    cast(dict[str, Any], round_data.get("acs_settle_stats", {}))
                ),
            )
            for round_data in value.get("rounds", ())
        ),
    )


def _configure_logging(log_level: str) -> None:
    setup_logging(log_level)


def _resolve_protocol(protocol: str) -> str:
    normalized = protocol.strip().lower()
    if normalized in {"hb", "honeybadger"}:
        return "hb"
    if normalized == "dumbo":
        return "dumbo"
    raise ValueError(f"Unsupported protocol: {protocol}")


def _node_class(protocol: str):
    return DumboBFT if _resolve_protocol(protocol) == "dumbo" else HoneyBadgerBFT


def _seed_dummy_transactions(
    node: HoneyBadgerBFT,
    pid: int,
    transactions_per_node: int,
    tx_input: TxInputMode = "json_str",
) -> None:
    for tx_index in range(transactions_per_node):
        tx = f"Dummy TX node-{pid}-tx-{tx_index}"
        submitted_at_ns = time.time_ns()
        if tx_input == "json_str":
            node.submit_tx_json_str(tx, track_latency=True, submitted_at_ns=submitted_at_ns)
            continue
        if tx_input == "bytes":
            node.submit_tx_bytes(
                honey_native.encode_json_string(tx),
                track_latency=True,
                submitted_at_ns=submitted_at_ns,
            )
            continue
        raise ValueError(f"Unsupported tx input mode: {tx_input}")


def _build_honey_node_binary() -> Path:
    global _HONEY_NODE_BINARY
    if _HONEY_NODE_BINARY is not None and _HONEY_NODE_BINARY.exists():
        return _HONEY_NODE_BINARY
    # Allow an explicit override via environment variable (useful for release builds).
    env_override = os.environ.get("HONEY_NODE_BINARY")
    if env_override:
        override_path = Path(env_override)
        if override_path.exists():
            _HONEY_NODE_BINARY = override_path
            return _HONEY_NODE_BINARY
    use_release = os.environ.get("HONEY_NODE_RELEASE", "").lower() in ("1", "true", "yes")
    build_args = ["cargo", "build", "--manifest-path", "native/Cargo.toml", "-p", "honey-node"]
    if use_release:
        build_args.append("--release")
    subprocess.run(build_args, check=True)
    profile = "release" if use_release else "debug"
    _HONEY_NODE_BINARY = Path(f"native/target/{profile}/honey-node")
    return _HONEY_NODE_BINARY


def _benchmark_rust_driver_nodes(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    max_rounds: int,
    global_timeout: float,
    acs_protocol: AcsRuntimeProtocol,
    config_payload: dict[str, Any],
) -> list[MultiprocessNodeResult]:
    binary = _build_honey_node_binary()
    completed = subprocess.run(
        [
            str(binary),
            "bench-driver",
            "--sid",
            sid,
            "--acs-protocol",
            acs_protocol,
            "--nodes",
            str(num_nodes),
            "--faulty",
            str(faulty),
            "--rounds",
            str(max_rounds),
            "--batch-size",
            str(batch_size),
            "--global-timeout",
            str(global_timeout),
            "--config-json",
            json.dumps(config_payload, separators=(",", ":")),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"Rust-driver benchmark failed: {error_text}")

    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("Rust-driver benchmark produced no output")
    decoded = cast(list[dict[str, Any]], json.loads(payload))
    return [_decode_result_payload(pid, value) for pid, value in enumerate(decoded)]


def _run_rust_driven_acs(
    *,
    protocol: str,
    sid: str,
    num_nodes: int,
    faulty: int,
    max_rounds: int,
    global_timeout: float,
    config_payload: dict[str, Any] | None = None,
) -> RustDrivenAcsRunResult:
    binary = _build_honey_node_binary()
    completed = subprocess.run(
        [
            str(binary),
            "drive-acs",
            "--protocol",
            protocol,
            "--sid",
            sid,
            "--nodes",
            str(num_nodes),
            "--faulty",
            str(faulty),
            "--rounds",
            str(max_rounds),
            "--global-timeout",
            str(global_timeout),
            "--config-json",
            json.dumps(config_payload or {}, separators=(",", ":")),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"Rust-driven ACS run failed: {error_text}")

    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("Rust-driven ACS run produced no output")
    return _decode_rust_driven_acs_payload(cast(dict[str, Any], json.loads(payload)))


def _run_rust_driven_honeybadger(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    max_rounds: int,
    global_timeout: float,
    acs_protocol: AcsRuntimeProtocol = "hb",
    acs_config_payload: dict[str, Any] | None = None,
) -> RustDrivenHoneyBadgerRunResult:
    binary = _build_honey_node_binary()
    completed = subprocess.run(
        [
            str(binary),
            "drive-hb",
            "--sid",
            sid,
            "--acs-protocol",
            acs_protocol,
            "--nodes",
            str(num_nodes),
            "--faulty",
            str(faulty),
            "--rounds",
            str(max_rounds),
            "--batch-size",
            str(batch_size),
            "--global-timeout",
            str(global_timeout),
            "--config-json",
            json.dumps(acs_config_payload or {}, separators=(",", ":")),
        ],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"Rust-driven HoneyBadger run failed: {error_text}")

    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("Rust-driven HoneyBadger run produced no output")
    return _decode_rust_driven_honeybadger_payload(cast(dict[str, Any], json.loads(payload)))


def _decode_rust_driven_dumbo_payload(value: dict[str, Any]) -> RustDrivenDumboRunResult:
    return RustDrivenDumboRunResult(
        protocol=str(value.get("protocol", "dumbo")),
        sid=str(value["sid"]),
        nodes_count=int(value.get("nodes_count", 0)),
        faulty=int(value.get("faulty", 0)),
        enable_pool_reuse=bool(value.get("enable_pool_reuse", False)),
        chain_digest=str(value["chain_digest"]) if value.get("chain_digest") is not None else None,
        nodes=tuple(
            RustDrivenDumboNodeResult(
                pid=int(node["pid"]),
                worker_ident=int(node["worker_ident"]),
                rounds_started=int(node["rounds_started"]),
                rounds_finished=int(node["rounds_finished"]),
                processed_commands=int(node.get("processed_commands", 0)),
                start_round_calls=int(node.get("start_round_calls", 0)),
                push_inbound_batch_calls=int(node.get("push_inbound_batch_calls", 0)),
                push_inbound_batch_items=int(node.get("push_inbound_batch_items", 0)),
                pull_outbound_batch_calls=int(node.get("pull_outbound_batch_calls", 0)),
                pull_outbound_batch_items=int(node.get("pull_outbound_batch_items", 0)),
                exchange_batches_calls=int(node.get("exchange_batches_calls", 0)),
                exchange_inbound_items=int(node.get("exchange_inbound_items", 0)),
                exchange_outbound_items=int(node.get("exchange_outbound_items", 0)),
                stats_calls=int(node.get("stats_calls", 0)),
                bridge_queue_size=int(node.get("bridge_queue_size", 0)),
                worker_running=bool(node.get("worker_running", False)),
                worker_error=(
                    str(node["worker_error"]) if node.get("worker_error") is not None else None
                ),
                exchange_deliver_seconds=float(node.get("exchange_deliver_seconds", 0.0)),
                exchange_pump_seconds=float(node.get("exchange_pump_seconds", 0.0)),
                exchange_drain_seconds=float(node.get("exchange_drain_seconds", 0.0)),
                exchange_total_seconds=float(node.get("exchange_total_seconds", 0.0)),
                mempool_size=int(node.get("mempool_size", 0)),
            )
            for node in value.get("nodes", ())
        ),
        rounds=tuple(
            RustDrivenDumboRoundResult(
                round_id=int(round_data["round_id"]),
                selected_count=int(round_data["selected_count"]),
                selected_pids=tuple(int(pid) for pid in round_data.get("selected_pids", ())),
                acs_send_events=int(round_data.get("acs_send_events", 0)),
                block_size=int(round_data.get("block_size", 0)),
                block_digest=str(round_data.get("block_digest", "")),
                chain_digest=str(round_data.get("chain_digest", "")),
                acs_seconds=float(round_data.get("acs_seconds", 0.0)),
                block_resolve_seconds=float(round_data.get("block_resolve_seconds", 0.0)),
                wall_seconds=float(round_data.get("wall_seconds", 0.0)),
                delivered_count=int(round_data.get("delivered_count", 0)),
                tpke_seconds=float(round_data.get("tpke_seconds", 0.0)),
                tpke_bundle_events=int(round_data.get("tpke_bundle_events", 0)),
                build_seconds=float(round_data.get("build_seconds", 0.0)),
                acs_drive_stats=_decode_rust_driven_driver_phase_stats(
                    cast(dict[str, Any], round_data.get("acs_drive_stats", {}))
                ),
                acs_settle_stats=_decode_rust_driven_driver_phase_stats(
                    cast(dict[str, Any], round_data.get("acs_settle_stats", {}))
                ),
            )
            for round_data in value.get("rounds", ())
        ),
    )


def _run_rust_driven_dumbo(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    max_rounds: int,
    global_timeout: float,
    config_payload: dict[str, Any] | None = None,
    ledger_dir: str | None = None,
    tx_payload: list[list[str]] | None = None,
) -> RustDrivenDumboRunResult:
    binary = _build_honey_node_binary()
    cmd = [
        str(binary),
        "drive-dumbo",
        "--sid",
        sid,
        "--nodes",
        str(num_nodes),
        "--faulty",
        str(faulty),
        "--rounds",
        str(max_rounds),
        "--batch-size",
        str(batch_size),
        "--global-timeout",
        str(global_timeout),
        "--config-json",
        json.dumps(config_payload or {}, separators=(",", ":")),
    ]
    if ledger_dir is not None:
        cmd += ["--ledger-dir", ledger_dir]
    if tx_payload is not None:
        cmd += ["--tx-json", json.dumps(tx_payload, separators=(",", ":"))]
    completed = subprocess.run(
        cmd,
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"Rust-driven Dumbo (new driver) run failed: {error_text}")

    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("Rust-driven Dumbo (new driver) run produced no output")
    return _decode_rust_driven_dumbo_payload(cast(dict[str, Any], json.loads(payload)))


def _timing_summary(
    samples: tuple[float, ...], *, total_seconds: float | None = None
) -> MetricTimingSummary:
    if not samples:
        return MetricTimingSummary()
    return MetricTimingSummary(
        sample_count=len(samples),
        total_seconds=sum(samples) if total_seconds is None else total_seconds,
        max_seconds=max(samples),
    )


def _results_from_rust_driven_honeybadger(
    run_result: RustDrivenHoneyBadgerRunResult,
    *,
    batch_size: int,
) -> list[MultiprocessNodeResult]:
    round_build_latencies = tuple(round_data.build_seconds for round_data in run_result.rounds)
    round_latencies = tuple(round_data.protocol_seconds for round_data in run_result.rounds)
    round_wall_latencies = tuple(round_data.wall_seconds for round_data in run_result.rounds)
    round_proposed_counts = tuple(batch_size for _ in run_result.rounds)
    round_delivered_counts = tuple(round_data.delivered_count for round_data in run_result.rounds)
    delivered_total = sum(round_delivered_counts)
    node_run_total = sum(round_wall_latencies)
    shared_timings = {
        "hb.round.seconds": _timing_summary(round_latencies),
        "tpke.encrypt.seconds": _timing_summary(round_build_latencies),
        "tpke.partial_open.seconds": _timing_summary(
            tuple(round_data.tpke_local_share_seconds for round_data in run_result.rounds)
        ),
        "tpke.combine.seconds": _timing_summary(
            tuple(round_data.tpke_combine_seconds for round_data in run_result.rounds)
        ),
        "node.run.seconds": _timing_summary(
            (node_run_total,),
            total_seconds=node_run_total,
        ),
    }

    results: list[MultiprocessNodeResult] = []
    for node in run_result.nodes:
        origin_tx_latencies_by_round = tuple(
            (
                tuple(round_data.wall_seconds for _ in range(batch_size))
                if node.pid in round_data.selected_pids
                else ()
            )
            for round_data in run_result.rounds
        )
        origin_tx_latencies = tuple(
            latency for round_samples in origin_tx_latencies_by_round for latency in round_samples
        )
        results.append(
            MultiprocessNodeResult(
                pid=node.pid,
                rounds=node.rounds_finished,
                delivered=delivered_total,
                round_build_latencies=round_build_latencies,
                round_latencies=round_latencies,
                round_wall_latencies=round_wall_latencies,
                round_proposed_counts=round_proposed_counts,
                round_delivered_counts=round_delivered_counts,
                origin_tx_latencies=origin_tx_latencies,
                origin_tx_latencies_by_round=origin_tx_latencies_by_round,
                chain_digest=run_result.chain_digest,
                subprotocol_timings=dict(shared_timings),
                queue_peaks=NodeQueuePeaks(),
                transport_stats=TransportStats(),
            )
        )
    return results


def _relabel_rust_driven_protocol(
    run_result: RustDrivenHoneyBadgerRunResult, *, protocol: str
) -> RustDrivenHoneyBadgerRunResult:
    return RustDrivenHoneyBadgerRunResult(
        protocol=protocol,
        sid=run_result.sid,
        chain_digest=run_result.chain_digest,
        nodes=run_result.nodes,
        rounds=run_result.rounds,
        acs_protocol=run_result.acs_protocol,
    )


def benchmark_local_honeybadger_nodes_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    global_timeout: float = 30.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "json_str",
    transport_backend: TransportBackend = "tcp",
    log_level: str = "WARNING",
    rust_tx_pool_max_bytes: int = 0,
    ledger_dir: str | None = None,
    acs_protocol: AcsRuntimeProtocol = "hb",
    enable_broadcast_pool_reuse: bool = False,
    pool_grace_ms: int = 200,
) -> list[MultiprocessNodeResult]:
    del round_timeout, log_level, rust_tx_pool_max_bytes
    if tx_input != "json_str":
        raise ValueError(
            "Rust-driven HoneyBadger benchmark currently supports only tx_input='json_str'"
        )
    if transport_backend != "tcp":
        raise ValueError("Rust-driven HoneyBadger benchmark supports only transport_backend='tcp'")
    expected_transactions_per_node = batch_size * max_rounds
    if transactions_per_node != expected_transactions_per_node:
        raise ValueError(
            "Rust-driven HoneyBadger benchmark requires transactions_per_node == batch_size * max_rounds"
        )
    if ledger_dir is not None:
        raise ValueError("Rust-driven HoneyBadger benchmark does not support ledger persistence")

    acs_config_payload: dict[str, Any] | None = None
    if acs_protocol == "dumbo":
        acs_config_payload = {
            "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
            "pool_grace_ms": pool_grace_ms,
        }
    return _benchmark_rust_driver_nodes(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        acs_protocol=acs_protocol,
        config_payload=acs_config_payload or {},
    )


def benchmark_local_dumbo_nodes_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    global_timeout: float = 30.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "json_str",
    transport_backend: TransportBackend = "tcp",
    log_level: str = "WARNING",
    enable_broadcast_pool_reuse: bool = False,
    enable_pool_reference_proposals: bool = False,
    enable_pool_fetch_fallback: bool = False,
    pool_grace_ms: int = 200,
    rust_tx_pool_max_bytes: int = 0,
    ledger_dir: str | None = None,
) -> list[MultiprocessNodeResult]:
    del round_timeout
    del log_level
    del rust_tx_pool_max_bytes
    if tx_input != "json_str":
        raise ValueError("Rust-driven Dumbo benchmark currently supports only tx_input='json_str'")
    if transport_backend != "tcp":
        raise ValueError("Rust-driven Dumbo benchmark supports only transport_backend='tcp'")
    expected_transactions_per_node = batch_size * max_rounds
    if transactions_per_node != expected_transactions_per_node:
        raise ValueError(
            "Rust-driven Dumbo benchmark requires transactions_per_node == batch_size * max_rounds"
        )
    if ledger_dir is not None:
        raise ValueError("Rust-driven Dumbo benchmark does not support ledger persistence")
    return _benchmark_rust_driver_nodes(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        acs_protocol="dumbo",
        config_payload={
            "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
            "enable_pool_reference_proposals": enable_pool_reference_proposals,
            "enable_pool_fetch_fallback": enable_pool_fetch_fallback,
            "pool_grace_ms": pool_grace_ms,
        },
    )


def run_local_honeybadger_acs_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    max_rounds: int = 1,
    global_timeout: float = 30.0,
) -> RustDrivenAcsRunResult:
    return _run_rust_driven_acs(
        protocol="hb",
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
    )


def run_local_honeybadger_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    global_timeout: float = 30.0,
    acs_protocol: AcsRuntimeProtocol = "hb",
    enable_broadcast_pool_reuse: bool = False,
    pool_grace_ms: int = 200,
) -> RustDrivenHoneyBadgerRunResult:
    acs_config_payload: dict[str, Any] | None = None
    if acs_protocol == "dumbo":
        acs_config_payload = {
            "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
            "pool_grace_ms": pool_grace_ms,
        }
    return _run_rust_driven_honeybadger(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        acs_protocol=acs_protocol,
        acs_config_payload=acs_config_payload,
    )


def run_local_dumbo_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    global_timeout: float = 30.0,
    enable_broadcast_pool_reuse: bool = False,
    pool_grace_ms: int = 200,
) -> RustDrivenDumboRunResult:
    return _run_rust_driven_dumbo(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        config_payload={
            "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
            "pool_grace_ms": pool_grace_ms,
        },
    )


def run_local_dumbo_acs_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    max_rounds: int = 1,
    global_timeout: float = 30.0,
    enable_broadcast_pool_reuse: bool = False,
    pool_grace_ms: int = 200,
) -> RustDrivenAcsRunResult:
    config_payload: dict[str, Any] = {
        "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
        "pool_grace_ms": pool_grace_ms,
    }
    return _run_rust_driven_acs(
        protocol="dumbo",
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        config_payload=config_payload,
    )


def run_local_dumbo_new_driver(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    global_timeout: float = 30.0,
    enable_broadcast_pool_reuse: bool = False,
    enable_pool_reference_proposals: bool = False,
    enable_pool_fetch_fallback: bool = False,
    pool_grace_ms: int = 200,
    pool_reuse_limit_per_round: int = 4,
    pool_expire_rounds: int = 10,
    pool_mempool_max: int = 1024,
    ledger_dir: str | None = None,
    tx_payload: list[list[str]] | None = None,
) -> RustDrivenDumboRunResult:
    """Run the Dumbo BFT protocol using the new Rust-native ``drive-dumbo`` driver.

    Unlike ``benchmark_local_dumbo_nodes_rust_driven`` which wraps ``bench-driver``,
    this function invokes the new ``drive-dumbo`` command that manages BroadcastMempool,
    PoolReference building, and carryover processing fully in Rust.

    Args:
        ledger_dir: Optional path to write per-round ledger block JSON files.
        tx_payload: Optional per-node transaction lists ``[[tx, ...], ...]``.
            If ``None``, deterministic dummy transactions are generated.
            Each inner list must contain at least ``batch_size * max_rounds`` entries.
    """
    config_payload: dict[str, Any] = {
        "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
        "enable_pool_reference_proposals": enable_pool_reference_proposals,
        "enable_pool_fetch_fallback": enable_pool_fetch_fallback,
        "pool_grace_ms": pool_grace_ms,
        "pool_reuse_limit_per_round": pool_reuse_limit_per_round,
        "pool_expire_rounds": pool_expire_rounds,
        "pool_mempool_max": pool_mempool_max,
    }
    return _run_rust_driven_dumbo(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        config_payload=config_payload,
        ledger_dir=ledger_dir,
        tx_payload=tx_payload,
    )


async def run_local_honeybadger_nodes_deterministic(
    sid: str,
    num_nodes: int,
    faulty: int,
    *,
    seed: int = 0,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    min_delay_steps: int = 0,
    max_delay_steps: int = 0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "json_str",
    log_level: str = "WARNING",
    rust_tx_pool_max_bytes: int = 0,
) -> list[HoneyBadgerBFT]:
    _configure_logging(log_level)
    sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = build_materials(
        num_nodes, faulty
    )
    simulator = DeterministicNetworkSimulator(
        num_nodes,
        seed=seed,
        min_delay_steps=min_delay_steps,
        max_delay_steps=max_delay_steps,
    )

    nodes: list[HoneyBadgerBFT] = []
    for pid in range(num_nodes):
        common = CommonParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=0)
        crypto = CryptoParams(
            sig_pk=sig_pk,
            sig_sk=sig_shares[pid],
            enc_pk=enc_pk,
            enc_sk=enc_shares[pid],
            ecdsa_pks=ecdsa_pks,
            ecdsa_sk=ecdsa_sks[pid],
        )
        config = HBConfig(
            batch_size=batch_size,
            rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            log_level=log_level,
        )
        node = HoneyBadgerBFT(common, crypto, simulator.transports[pid], config=config)
        _seed_dummy_transactions(node, pid, transactions_per_node, tx_input)
        nodes.append(node)

    stop_event = asyncio.Event()
    sim_task = asyncio.create_task(simulator.run(stop_event))
    try:
        await asyncio.gather(*(asyncio.create_task(node.run()) for node in nodes))
        await simulator.flush()
    finally:
        stop_event.set()
        await sim_task

    return nodes
