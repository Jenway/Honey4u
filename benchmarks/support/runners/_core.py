from __future__ import annotations

import json
import logging
import math
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

_HONEY_BENCH_BINARY: Path | None = None
TxInputMode = Literal["json_str", "bytes"]
TransportBackend = Literal["tcp", "quic"]
AcsRuntimeProtocol = Literal["hb", "dumbo"]
BroadcastPoolBackend = Literal["none", "rust"]


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
    delayed_frames: int = 0
    total_injected_delay_ms: int = 0
    network_fault_seed: int = 0
    configured_fixed_delay_ms: int = 0
    configured_jitter_ms: int = 0
    configured_slow_honest_extra_delay_ms: int = 0


@dataclass(frozen=True)
class MultiprocessDriverStats:
    acs_pull_calls: int = 0
    acs_empty_pull_calls: int = 0
    acs_inbound_wire_batches: int = 0
    acs_inbound_wire_items: int = 0
    acs_outbound_events: int = 0
    tpke_combine_calls: int = 0
    stale_acs_frames_dropped: int = 0
    fetch_requests_sent: int = 0
    fetch_responses_served: int = 0
    fetch_responses_received: int = 0
    fetched_reference_count: int = 0
    byzantine_invalid_fetch_responses_sent: int = 0
    byzantine_fetch_requests_ignored: int = 0
    byzantine_share_broadcast_suppressed: int = 0
    byzantine_empty_proposal_rounds: int = 0


@dataclass(frozen=True)
class MultiprocessRoundDetail:
    round_id: int
    selected_proposal_ids: tuple[str, ...] = ()
    selected_pids: tuple[int, ...] = ()
    block_digest: str | None = None
    block_size: int = 0
    chain_digest: str | None = None
    build_seconds: float = 0.0
    acs_seconds: float = 0.0
    tpke_seconds: float = 0.0
    protocol_seconds: float = 0.0
    wall_seconds: float = 0.0
    delivered_count: int = 0
    reused_reference_count: int = 0
    tpke_partial_open_seconds: float = 0.0
    tpke_combine_seconds: float = 0.0
    acs_outbound_events: int = 0
    tpke_combine_calls: int = 0
    fetch_requests_sent: int = 0
    fetch_responses_served: int = 0
    fetch_responses_received: int = 0
    fetched_reference_count: int = 0
    byzantine_invalid_fetch_responses_sent: int = 0
    byzantine_fetch_requests_ignored: int = 0
    byzantine_share_broadcast_suppressed: int = 0
    byzantine_empty_proposal_used: bool = False
    driver_phase_stats: RustDrivenDriverPhaseStats | None = None


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
    driver_stats: MultiprocessDriverStats = field(default_factory=MultiprocessDriverStats)
    round_details: tuple[MultiprocessRoundDetail, ...] = ()
    byzantine_behavior: str | None = None


@dataclass(frozen=True)
class RustDrivenAcsNodeResult:
    pid: int
    worker_ident: int
    rounds_started: int
    rounds_finished: int
    processed_commands: int = 0
    start_round_calls: int = 0
    push_inbound_wire_batch_calls: int = 0
    push_inbound_wire_batch_items: int = 0
    pull_outbound_wire_batch_calls: int = 0
    pull_outbound_wire_batch_items: int = 0
    stats_calls: int = 0
    bridge_queue_size: int = 0
    worker_running: bool = False
    worker_error: str | None = None


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
    send_events: int = 0
    send_payload_bytes: int = 0
    proposal_available_events: int = 0
    proposal_available_payload_bytes: int = 0
    proposal_available_proof_bytes: int = 0
    decision_events: int = 0
    failure_events: int = 0
    host_stats: tuple[RustDrivenHostPhaseStats, ...] = ()


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
    reused_reference_count: int = 0
    tpke_seconds: float = 0.0
    tpke_bundle_events: int = 0
    build_seconds: float = 0.0
    fetch_requests_sent: int = 0
    fetch_responses_served: int = 0
    fetch_responses_received: int = 0
    fetched_reference_count: int = 0
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
    push_inbound_wire_batch_calls: int = 0
    push_inbound_wire_batch_items: int = 0
    pull_outbound_wire_batch_calls: int = 0
    pull_outbound_wire_batch_items: int = 0
    stats_calls: int = 0
    bridge_queue_size: int = 0
    worker_running: bool = False
    worker_error: str | None = None
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
            delayed_frames=int(value.get("transport_stats", {}).get("delayed_frames", 0)),
            total_injected_delay_ms=int(
                value.get("transport_stats", {}).get("total_injected_delay_ms", 0)
            ),
            network_fault_seed=int(value.get("transport_stats", {}).get("network_fault_seed", 0)),
            configured_fixed_delay_ms=int(
                value.get("transport_stats", {}).get("configured_fixed_delay_ms", 0)
            ),
            configured_jitter_ms=int(
                value.get("transport_stats", {}).get("configured_jitter_ms", 0)
            ),
            configured_slow_honest_extra_delay_ms=int(
                value.get("transport_stats", {}).get(
                    "configured_slow_honest_extra_delay_ms",
                    0,
                )
            ),
        ),
        driver_stats=_decode_multiprocess_driver_stats(
            cast(dict[str, Any], value.get("driver_stats", {}))
        ),
        round_details=tuple(
            _decode_multiprocess_round_detail(cast(dict[str, Any], round_detail))
            for round_detail in value.get("round_details", ())
        ),
        byzantine_behavior=(
            str(value["byzantine_behavior"])
            if value.get("byzantine_behavior") is not None
            else None
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
        send_events=int(value.get("send_events", 0)),
        send_payload_bytes=int(value.get("send_payload_bytes", 0)),
        proposal_available_events=int(value.get("proposal_available_events", 0)),
        proposal_available_payload_bytes=int(value.get("proposal_available_payload_bytes", 0)),
        proposal_available_proof_bytes=int(value.get("proposal_available_proof_bytes", 0)),
        decision_events=int(value.get("decision_events", 0)),
        failure_events=int(value.get("failure_events", 0)),
        host_stats=tuple(
            _decode_rust_driven_host_phase_stats(cast(dict[str, Any], host_stats))
            for host_stats in value.get("host_stats", ())
        ),
    )


def _decode_multiprocess_driver_stats(value: dict[str, Any]) -> MultiprocessDriverStats:
    return MultiprocessDriverStats(
        acs_pull_calls=int(value.get("acs_pull_calls", 0)),
        acs_empty_pull_calls=int(value.get("acs_empty_pull_calls", 0)),
        acs_inbound_wire_batches=int(value.get("acs_inbound_wire_batches", 0)),
        acs_inbound_wire_items=int(value.get("acs_inbound_wire_items", 0)),
        acs_outbound_events=int(value.get("acs_outbound_events", 0)),
        tpke_combine_calls=int(value.get("tpke_combine_calls", 0)),
        stale_acs_frames_dropped=int(value.get("stale_acs_frames_dropped", 0)),
        fetch_requests_sent=int(value.get("fetch_requests_sent", 0)),
        fetch_responses_served=int(value.get("fetch_responses_served", 0)),
        fetch_responses_received=int(value.get("fetch_responses_received", 0)),
        fetched_reference_count=int(value.get("fetched_reference_count", 0)),
        byzantine_invalid_fetch_responses_sent=int(
            value.get("byzantine_invalid_fetch_responses_sent", 0)
        ),
        byzantine_fetch_requests_ignored=int(value.get("byzantine_fetch_requests_ignored", 0)),
        byzantine_share_broadcast_suppressed=int(
            value.get("byzantine_share_broadcast_suppressed", 0)
        ),
        byzantine_empty_proposal_rounds=int(value.get("byzantine_empty_proposal_rounds", 0)),
    )


def _decode_multiprocess_round_detail(value: dict[str, Any]) -> MultiprocessRoundDetail:
    return MultiprocessRoundDetail(
        round_id=int(value.get("round_id", 0)),
        selected_proposal_ids=tuple(
            str(proposal_id) for proposal_id in value.get("selected_proposal_ids", ())
        ),
        selected_pids=tuple(int(pid) for pid in value.get("selected_pids", ())),
        block_digest=(
            str(value["block_digest"]) if value.get("block_digest") is not None else None
        ),
        block_size=int(value.get("block_size", 0)),
        chain_digest=(
            str(value["chain_digest"]) if value.get("chain_digest") is not None else None
        ),
        build_seconds=float(value.get("build_seconds", 0.0)),
        acs_seconds=float(value.get("acs_seconds", 0.0)),
        tpke_seconds=float(value.get("tpke_seconds", 0.0)),
        protocol_seconds=float(value.get("protocol_seconds", 0.0)),
        wall_seconds=float(value.get("wall_seconds", 0.0)),
        delivered_count=int(value.get("delivered_count", 0)),
        reused_reference_count=int(value.get("reused_reference_count", 0)),
        tpke_partial_open_seconds=float(value.get("tpke_partial_open_seconds", 0.0)),
        tpke_combine_seconds=float(value.get("tpke_combine_seconds", 0.0)),
        acs_outbound_events=int(value.get("acs_outbound_events", 0)),
        tpke_combine_calls=int(value.get("tpke_combine_calls", 0)),
        fetch_requests_sent=int(value.get("fetch_requests_sent", 0)),
        fetch_responses_served=int(value.get("fetch_responses_served", 0)),
        fetch_responses_received=int(value.get("fetch_responses_received", 0)),
        fetched_reference_count=int(value.get("fetched_reference_count", 0)),
        byzantine_invalid_fetch_responses_sent=int(
            value.get("byzantine_invalid_fetch_responses_sent", 0)
        ),
        byzantine_fetch_requests_ignored=int(value.get("byzantine_fetch_requests_ignored", 0)),
        byzantine_share_broadcast_suppressed=int(
            value.get("byzantine_share_broadcast_suppressed", 0)
        ),
        byzantine_empty_proposal_used=bool(value.get("byzantine_empty_proposal_used", False)),
        driver_phase_stats=(
            _decode_rust_driven_driver_phase_stats(
                cast(dict[str, Any], value.get("driver_phase_stats", {}))
            )
            if value.get("driver_phase_stats") is not None
            else None
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
                push_inbound_wire_batch_calls=int(node.get("push_inbound_wire_batch_calls", 0)),
                push_inbound_wire_batch_items=int(node.get("push_inbound_wire_batch_items", 0)),
                pull_outbound_wire_batch_calls=int(node.get("pull_outbound_wire_batch_calls", 0)),
                pull_outbound_wire_batch_items=int(node.get("pull_outbound_wire_batch_items", 0)),
                stats_calls=int(node.get("stats_calls", 0)),
                bridge_queue_size=int(node.get("bridge_queue_size", 0)),
                worker_running=bool(node.get("worker_running", False)),
                worker_error=(
                    str(node["worker_error"]) if node.get("worker_error") is not None else None
                ),
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
    level = getattr(logging, str(log_level).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def _build_honey_bench_binary() -> Path:
    global _HONEY_BENCH_BINARY
    if _HONEY_BENCH_BINARY is not None and _HONEY_BENCH_BINARY.exists():
        return _HONEY_BENCH_BINARY
    # Allow an explicit override via environment variable (useful for release builds).
    env_override = os.environ.get("HONEY_BENCH_BINARY") or os.environ.get("HONEY_NODE_BINARY")
    if env_override:
        override_path = Path(env_override)
        if override_path.exists():
            _HONEY_BENCH_BINARY = override_path
            return _HONEY_BENCH_BINARY
    use_release = os.environ.get("HONEY_NODE_RELEASE", "").lower() in ("1", "true", "yes")
    build_args = ["cargo", "build", "-p", "honey-bench", "-p", "honey-node"]
    if use_release:
        build_args.append("--release")
    subprocess.run(build_args, check=True)
    profile = "release" if use_release else "debug"
    _HONEY_BENCH_BINARY = Path(f"target/{profile}/honey-bench")
    return _HONEY_BENCH_BINARY


def _format_toml_key(key: str) -> str:
    if key and all(char.isascii() and (char.isalnum() or char in ("_", "-")) for char in key):
        return key
    return json.dumps(key)


def _format_toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"TOML does not support non-finite floats: {value!r}")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, Path):
        return json.dumps(str(value))
    if isinstance(value, list | tuple):
        return f"[{', '.join(_format_toml_value(item) for item in value)}]"
    if isinstance(value, dict):
        rendered_items = ", ".join(
            f"{_format_toml_key(str(key))} = {_format_toml_value(item)}"
            for key, item in value.items()
        )
        return f"{{ {rendered_items} }}"
    raise TypeError(f"Unsupported TOML value type: {type(value).__name__}")


def _render_bench_driver_config(
    *,
    mode: str,
    sid: str,
    num_nodes: int,
    faulty: int,
    max_rounds: int,
    global_timeout: float,
    batch_size: int | None = None,
    protocol: str | None = None,
    acs_protocol: str | None = None,
    result_path: str | None = None,
    ledger_dir: str | None = None,
    tx_payload: list[list[str]] | None = None,
    config_payload: dict[str, Any] | None = None,
) -> str:
    lines = [
        f"mode = {json.dumps(mode)}",
        f"sid = {json.dumps(sid)}",
        f"nodes = {num_nodes}",
        f"faulty = {faulty}",
        f"rounds = {max_rounds}",
        f"global_timeout = {_format_toml_value(global_timeout)}",
    ]
    if batch_size is not None:
        lines.append(f"batch_size = {batch_size}")
    if protocol is not None:
        lines.append(f"protocol = {json.dumps(protocol)}")
    if acs_protocol is not None:
        lines.append(f"acs_protocol = {json.dumps(acs_protocol)}")
    if result_path is not None:
        lines.append(f"result_path = {json.dumps(result_path)}")
    if ledger_dir is not None:
        lines.append(f"ledger_dir = {json.dumps(ledger_dir)}")
    if tx_payload is not None:
        lines.append(f"tx_json = {_format_toml_value(tx_payload)}")
    if config_payload:
        lines.append("")
        lines.append("[config]")
        for key, value in config_payload.items():
            lines.append(f"{_format_toml_key(str(key))} = {_format_toml_value(value)}")
    return "\n".join(lines) + "\n"


def _run_bench_driver(*, config_text: str) -> subprocess.CompletedProcess[str]:
    binary = _build_honey_bench_binary()
    with tempfile.TemporaryDirectory(prefix="honey-bench-driver-") as temp_dir:
        config_path = Path(temp_dir) / "bench-driver.toml"
        config_path.write_text(config_text, encoding="utf-8")
        return subprocess.run(
            [str(binary), "run", "--config", str(config_path)],
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
        )


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
    completed = _run_bench_driver(
        config_text=_render_bench_driver_config(
            mode="benchmark",
            sid=sid,
            num_nodes=num_nodes,
            faulty=faulty,
            max_rounds=max_rounds,
            batch_size=batch_size,
            global_timeout=global_timeout,
            acs_protocol=acs_protocol,
            config_payload=config_payload,
        )
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"Rust-driver benchmark failed: {error_text}")

    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("Rust-driver benchmark produced no output")
    decoded = cast(list[dict[str, Any]], json.loads(payload))
    return [_decode_result_payload(pid, value) for pid, value in enumerate(decoded)]


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
    completed = _run_bench_driver(
        config_text=_render_bench_driver_config(
            mode="hb",
            sid=sid,
            num_nodes=num_nodes,
            faulty=faulty,
            max_rounds=max_rounds,
            batch_size=batch_size,
            global_timeout=global_timeout,
            acs_protocol=acs_protocol,
            config_payload=acs_config_payload or {},
        )
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
                push_inbound_wire_batch_calls=int(node.get("push_inbound_wire_batch_calls", 0)),
                push_inbound_wire_batch_items=int(node.get("push_inbound_wire_batch_items", 0)),
                pull_outbound_wire_batch_calls=int(node.get("pull_outbound_wire_batch_calls", 0)),
                pull_outbound_wire_batch_items=int(node.get("pull_outbound_wire_batch_items", 0)),
                stats_calls=int(node.get("stats_calls", 0)),
                bridge_queue_size=int(node.get("bridge_queue_size", 0)),
                worker_running=bool(node.get("worker_running", False)),
                worker_error=(
                    str(node["worker_error"]) if node.get("worker_error") is not None else None
                ),
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
                reused_reference_count=int(round_data.get("reused_reference_count", 0)),
                tpke_seconds=float(round_data.get("tpke_seconds", 0.0)),
                tpke_bundle_events=int(round_data.get("tpke_bundle_events", 0)),
                build_seconds=float(round_data.get("build_seconds", 0.0)),
                fetch_requests_sent=int(round_data.get("fetch_requests_sent", 0)),
                fetch_responses_served=int(round_data.get("fetch_responses_served", 0)),
                fetch_responses_received=int(round_data.get("fetch_responses_received", 0)),
                fetched_reference_count=int(round_data.get("fetched_reference_count", 0)),
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
    completed = _run_bench_driver(
        config_text=_render_bench_driver_config(
            mode="dumbo",
            sid=sid,
            num_nodes=num_nodes,
            faulty=faulty,
            max_rounds=max_rounds,
            batch_size=batch_size,
            global_timeout=global_timeout,
            ledger_dir=ledger_dir,
            tx_payload=tx_payload,
            config_payload=config_payload or {},
        )
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(f"Rust-driven Dumbo (new driver) run failed: {error_text}")

    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("Rust-driven Dumbo (new driver) run produced no output")
    return _decode_rust_driven_dumbo_payload(cast(dict[str, Any], json.loads(payload)))


def _inject_runtime_faults(
    config_payload: dict[str, Any],
    network_faults: dict[str, Any] | None,
    byzantine_nodes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    merged = dict(config_payload)
    if network_faults:
        merged["network_faults"] = network_faults
    if byzantine_nodes:
        merged["byzantine_nodes"] = byzantine_nodes
    return merged


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
    hb_broadcast_protocol: str = "rbc",
    enable_broadcast_pool_reuse: bool = False,
    pool_grace_ms: int = 200,
    broadcast_mempool_backend: BroadcastPoolBackend = "rust",
    pool_mempool_max: int = 1000,
    network_faults: dict[str, Any] | None = None,
    byzantine_nodes: list[dict[str, Any]] | None = None,
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
    elif acs_protocol == "hb":
        acs_config_payload = {
            "hb_broadcast_protocol": hb_broadcast_protocol,
        }
    config_payload = dict(acs_config_payload or {})
    config_payload["acs_host_backend"] = "python"
    config_payload["broadcast_mempool_backend"] = broadcast_mempool_backend
    config_payload["pool_mempool_max"] = pool_mempool_max
    return _benchmark_rust_driver_nodes(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        acs_protocol=acs_protocol,
        config_payload=_inject_runtime_faults(config_payload, network_faults, byzantine_nodes),
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
    network_faults: dict[str, Any] | None = None,
    byzantine_nodes: list[dict[str, Any]] | None = None,
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
        config_payload=_inject_runtime_faults(
            {
                "acs_host_backend": "python",
                "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
                "enable_pool_reference_proposals": enable_pool_reference_proposals,
                "enable_pool_fetch_fallback": enable_pool_fetch_fallback,
                "pool_grace_ms": pool_grace_ms,
            },
            network_faults,
            byzantine_nodes,
        ),
    )


def run_local_honeybadger_rust_driven(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    global_timeout: float = 30.0,
    acs_protocol: AcsRuntimeProtocol = "hb",
    hb_broadcast_protocol: str = "rbc",
    enable_broadcast_pool_reuse: bool = False,
    pool_grace_ms: int = 200,
    broadcast_mempool_backend: BroadcastPoolBackend = "rust",
    pool_mempool_max: int = 1000,
    network_faults: dict[str, Any] | None = None,
    byzantine_nodes: list[dict[str, Any]] | None = None,
) -> RustDrivenHoneyBadgerRunResult:
    acs_config_payload: dict[str, Any] | None = None
    if acs_protocol == "dumbo":
        acs_config_payload = {
            "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
            "pool_grace_ms": pool_grace_ms,
        }
    elif acs_protocol == "hb":
        acs_config_payload = {
            "hb_broadcast_protocol": hb_broadcast_protocol,
        }
    config_payload = dict(acs_config_payload or {})
    config_payload["acs_host_backend"] = "python"
    config_payload["broadcast_mempool_backend"] = broadcast_mempool_backend
    config_payload["pool_mempool_max"] = pool_mempool_max
    return _run_rust_driven_honeybadger(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        acs_protocol=acs_protocol,
        acs_config_payload=_inject_runtime_faults(config_payload, network_faults, byzantine_nodes),
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
    network_faults: dict[str, Any] | None = None,
    byzantine_nodes: list[dict[str, Any]] | None = None,
) -> RustDrivenDumboRunResult:
    return _run_rust_driven_dumbo(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        global_timeout=global_timeout,
        config_payload=_inject_runtime_faults(
            {
                "acs_host_backend": "python",
                "enable_broadcast_pool_reuse": enable_broadcast_pool_reuse,
                "pool_grace_ms": pool_grace_ms,
            },
            network_faults,
            byzantine_nodes,
        ),
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
    network_faults: dict[str, Any] | None = None,
    byzantine_nodes: list[dict[str, Any]] | None = None,
) -> RustDrivenDumboRunResult:
    """Run the Dumbo BFT protocol using the unified Rust-native ``honey-bench`` entrypoint.

    Unlike ``benchmark_local_dumbo_nodes_rust_driven`` which consumes benchmark-style node output,
    this function writes a temporary TOML config for ``honey-bench`` to manage BroadcastMempool,
    PoolReference building, and carryover processing fully in Rust.

    Args:
        ledger_dir: Optional path to write per-round ledger block JSON files.
        tx_payload: Optional per-node transaction lists ``[[tx, ...], ...]``.
            If ``None``, deterministic dummy transactions are generated.
            Each inner list must contain at least ``batch_size * max_rounds`` entries.
    """
    config_payload: dict[str, Any] = {
        "acs_host_backend": "python",
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
        config_payload=_inject_runtime_faults(config_payload, network_faults, byzantine_nodes),
        ledger_dir=ledger_dir,
        tx_payload=tx_payload,
    )
