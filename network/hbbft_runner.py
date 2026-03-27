from __future__ import annotations

import asyncio
import cProfile
import io
import json
import logging
import multiprocessing as mp
import os
import pstats
import shutil
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Literal

import honey_native

from honey.consensus.dumbo.core import DumboBFT
from honey.consensus.honeybadger.core import HoneyBadgerBFT
from honey.support.logging_ext import setup_logging
from honey.support.messages import ProtocolEnvelope
from honey.support.params import CommonParams, CryptoParams, HBConfig
from honey.support.telemetry import METRICS, log_event, timed_metric
from network.crypto_material import build_dumbo_materials, build_materials
from network.deterministic_simulator import DeterministicNetworkSimulator
from network.local_socket_transport import start_local_socket_transport
from network.transport import QueueTransport

_TIMED_METRIC_NAMES = (
    "hb.round.seconds",
    "rbc.encode.seconds",
    "rbc.decode.seconds",
    "tpke.encrypt.seconds",
    "tpke.partial_open.seconds",
    "tpke.combine.seconds",
    "bridge.encode.seconds",
    "bridge.decode.seconds",
    "bridge.thread_queue_drain.seconds",
    "socket.send.seconds",
    "socket.recv.seconds",
    "node.run.seconds",
)

_BRIDGE_BATCH_SIZE = 64
_BRIDGE_QUEUE_TIMEOUT_SECONDS = 0.1
TxInputMode = Literal["python_json", "json_str", "bytes"]


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
    subprotocol_timings: dict[str, MetricTimingSummary] = field(default_factory=dict)
    queue_peaks: NodeQueuePeaks = field(default_factory=NodeQueuePeaks)


def _encode_result_payload(result: MultiprocessNodeResult) -> dict[str, Any]:
    return {
        "rounds": result.rounds,
        "delivered": result.delivered,
        "round_build_latencies": list(result.round_build_latencies),
        "round_latencies": list(result.round_latencies),
        "round_wall_latencies": list(result.round_wall_latencies),
        "round_proposed_counts": list(result.round_proposed_counts),
        "round_delivered_counts": list(result.round_delivered_counts),
        "origin_tx_latencies": list(result.origin_tx_latencies),
        "origin_tx_latencies_by_round": [
            list(values) for values in result.origin_tx_latencies_by_round
        ],
        "subprotocol_timings": {
            name: asdict(summary) for name, summary in result.subprotocol_timings.items()
        },
        "queue_peaks": asdict(result.queue_peaks),
    }


def _flush_result_queue(result_queue: Any) -> None:
    close = getattr(result_queue, "close", None)
    if callable(close):
        close()
    join_thread = getattr(result_queue, "join_thread", None)
    if callable(join_thread):
        join_thread()


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
    )


def _drain_result_queue(
    result_queue: Any,
    finished: dict[int, MultiprocessNodeResult],
    errors: list[tuple[int, str]],
    errored_pids: set[int],
) -> None:
    if result_queue is None:
        return
    while True:
        try:
            status, pid, value = result_queue.get_nowait()
        except Empty:
            break
        if status == "ok":
            finished[pid] = _decode_result_payload(pid, value)
        else:
            errors.append((pid, str(value)))
            errored_pids.add(pid)


def _publish_worker_status(
    *,
    result_queue: Any | None,
    result_dir: str | None,
    status: str,
    pid: int,
    value: Any,
) -> None:
    if result_queue is not None:
        result_queue.put((status, pid, value))
        _flush_result_queue(result_queue)
        return

    if result_dir is None:
        raise RuntimeError("worker result sink is not configured")

    result_path = Path(result_dir)
    result_path.mkdir(parents=True, exist_ok=True)
    target = result_path / f"{pid}.{status}.json"
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps({"pid": pid, "status": status, "value": value}), encoding="utf-8")
    tmp.replace(target)


def _drain_result_dir(
    result_dir: str | None,
    finished: dict[int, MultiprocessNodeResult],
    errors: list[tuple[int, str]],
    errored_pids: set[int],
) -> None:
    if result_dir is None:
        return

    for path in sorted(Path(result_dir).glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        pid = int(payload["pid"])
        status = str(payload["status"])
        value = payload["value"]
        if status == "ok":
            finished[pid] = _decode_result_payload(pid, value)
        else:
            errors.append((pid, str(value)))
            errored_pids.add(pid)
        path.unlink(missing_ok=True)


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
    tx_input: TxInputMode = "python_json",
) -> None:
    for tx_index in range(transactions_per_node):
        tx = f"Dummy TX node-{pid}-tx-{tx_index}"
        submitted_at_ns = time.time_ns()
        if tx_input == "python_json":
            node.submit_tx(tx, track_latency=True, submitted_at_ns=submitted_at_ns)
            continue
        if tx_input == "json_str":
            node.submit_tx_json_str(tx, track_latency=True, submitted_at_ns=submitted_at_ns)
            continue
        if tx_input == "bytes":
            node.submit_tx_bytes(
                honey_native.encode_json_string(tx),
                tx=tx,
                dedup_key=f"s:{tx}",
                track_latency=True,
                submitted_at_ns=submitted_at_ns,
            )
            continue
        raise ValueError(f"Unsupported tx input mode: {tx_input}")


def _collect_timing_summaries() -> dict[str, MetricTimingSummary]:
    summaries: dict[str, MetricTimingSummary] = {}
    for name in _TIMED_METRIC_NAMES:
        payload = METRICS.timing_summary(name)
        summaries[name] = MetricTimingSummary(
            sample_count=int(payload["count"]),
            total_seconds=float(payload["total"]),
            max_seconds=float(payload["max"]),
        )
    return summaries


def _drain_thread_queue_batch(
    queue: Queue,
    stop_event: threading.Event,
    *,
    timeout: float = _BRIDGE_QUEUE_TIMEOUT_SECONDS,
    max_items: int = _BRIDGE_BATCH_SIZE,
) -> list[Any]:
    try:
        first = queue.get(timeout=timeout)
    except Empty:
        if stop_event.is_set():
            return []
        raise

    items = [first]
    while len(items) < max_items:
        try:
            items.append(queue.get_nowait())
        except Empty:
            break
    return items


async def _drain_async_queue_batch(
    queue: asyncio.Queue[Any], *, max_items: int = _BRIDGE_BATCH_SIZE
) -> list[Any]:
    first = await queue.get()
    items = [first]
    while len(items) < max_items:
        try:
            items.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    return items


def _result_from_local_node(node: HoneyBadgerBFT, pid: int) -> MultiprocessNodeResult:
    round_total = sum(node.round_latencies)
    return MultiprocessNodeResult(
        pid=pid,
        rounds=node.round,
        delivered=node.txcnt,
        round_build_latencies=tuple(
            getattr(node, "round_build_latencies", tuple(0.0 for _ in node.round_latencies))
        ),
        round_latencies=tuple(node.round_latencies),
        round_wall_latencies=tuple(
            getattr(node, "round_wall_latencies", tuple(node.round_latencies))
        ),
        round_proposed_counts=tuple(node.round_proposed_counts),
        round_delivered_counts=tuple(node.round_delivered_counts),
        origin_tx_latencies=tuple(node.origin_tx_latencies),
        origin_tx_latencies_by_round=tuple(node.origin_tx_latencies_by_round),
        subprotocol_timings={
            "hb.round.seconds": MetricTimingSummary(
                sample_count=len(node.round_latencies),
                total_seconds=round_total,
                max_seconds=max(node.round_latencies, default=0.0),
            )
        },
        queue_peaks=NodeQueuePeaks(
            mailbox_round_inbox=node.mailboxes.peak_inbox_size,
        ),
    )


def _fallback_local_benchmark_results(nodes: list[HoneyBadgerBFT]) -> list[MultiprocessNodeResult]:
    return [_result_from_local_node(node, pid) for pid, node in enumerate(nodes)]


def _build_result_dir(prefix: str, sid: str) -> str:
    scratch_root = Path(".tmp_multiprocess_results")
    scratch_root.mkdir(exist_ok=True)
    safe_sid = "".join(ch if ch.isalnum() else "-" for ch in sid)[:48].strip("-") or "sid"
    result_dir = scratch_root / f"{prefix}-{safe_sid}-{os.getpid()}-{time.time_ns()}"
    result_dir.mkdir(parents=True, exist_ok=True)
    return str(result_dir)


def _maybe_start_worker_profile(
    pid: int, protocol: str
) -> tuple[cProfile.Profile | None, Path | None]:
    target_pid = os.environ.get("HONEY_PROFILE_NODE_PID")
    output_dir = os.environ.get("HONEY_PROFILE_DIR")
    if target_pid is None or output_dir is None:
        return None, None
    if int(target_pid) != pid:
        return None, None

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    profile = cProfile.Profile()
    profile.enable()
    return profile, directory / f"{protocol}_worker_pid{pid}.prof"


def _finalize_worker_profile(
    profile: cProfile.Profile | None,
    profile_path: Path | None,
    protocol: str,
    pid: int,
) -> None:
    if profile is None or profile_path is None:
        return

    profile.disable()
    profile.dump_stats(str(profile_path))

    sort_by = os.environ.get("HONEY_PROFILE_SORT", "cumulative")
    limit = int(os.environ.get("HONEY_PROFILE_LIMIT", "80"))
    buffer = io.StringIO()
    stats = pstats.Stats(profile, stream=buffer)
    stats.sort_stats(sort_by)
    stats.print_stats(limit)
    txt_path = profile_path.with_suffix(".txt")
    txt_path.write_text(
        f"protocol={protocol}\nworker_pid={pid}\nsort={sort_by}\nlimit={limit}\n\n{buffer.getvalue()}",
        encoding="utf-8",
    )


async def run_local_honeybadger_nodes_single_process(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    use_rust_tx_pool: bool = False,
    rust_tx_pool_max_bytes: int = 0,
) -> list[HoneyBadgerBFT]:
    _configure_logging(log_level)
    sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = build_materials(
        num_nodes, faulty
    )

    transports = [QueueTransport() for _ in range(num_nodes)]
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
            use_rust_tx_pool=use_rust_tx_pool,
            rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            log_level=log_level,
        )

        node = HoneyBadgerBFT(common, crypto, transports[pid], config=config)
        _seed_dummy_transactions(node, pid, transactions_per_node, tx_input)
        nodes.append(node)

    async def _message_router() -> None:
        while True:
            pending_sends = []
            for pid in range(num_nodes):
                try:
                    while True:
                        outbound = transports[pid].outbound.get_nowait()
                        pending_sends.append((pid, outbound.recipient, outbound.envelope))
                except asyncio.QueueEmpty:
                    pass

            for sender, recipient, envelope in pending_sends:
                transports[recipient].deliver_nowait(sender, envelope)

            await asyncio.sleep(0.001)

    router_task = asyncio.create_task(_message_router())

    try:
        tasks = [asyncio.create_task(node.run()) for node in nodes]
        await asyncio.gather(*tasks)
    finally:
        router_task.cancel()
        try:
            await router_task
        except asyncio.CancelledError:
            pass

    return nodes


async def run_local_dumbo_nodes_single_process(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    use_rust_tx_pool: bool = False,
    rust_tx_pool_max_bytes: int = 0,
) -> list[DumboBFT]:
    _configure_logging(log_level)
    coin_pk, coin_shares, proof_pk, proof_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = (
        build_dumbo_materials(num_nodes, faulty)
    )

    transports = [QueueTransport() for _ in range(num_nodes)]
    nodes: list[DumboBFT] = []

    for pid in range(num_nodes):
        common = CommonParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=0)
        crypto = CryptoParams(
            sig_pk=coin_pk,
            sig_sk=coin_shares[pid],
            enc_pk=enc_pk,
            enc_sk=enc_shares[pid],
            ecdsa_pks=ecdsa_pks,
            ecdsa_sk=ecdsa_sks[pid],
            proof_sig_pk=proof_pk,
            proof_sig_sk=proof_shares[pid],
        )
        config = HBConfig(
            batch_size=batch_size,
            use_rust_tx_pool=use_rust_tx_pool,
            rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
            max_rounds=max_rounds,
            round_timeout=round_timeout,
            log_level=log_level,
        )

        node = DumboBFT(common, crypto, transports[pid], config=config)
        _seed_dummy_transactions(node, pid, transactions_per_node, tx_input)
        nodes.append(node)

    async def _message_router() -> None:
        while True:
            pending_sends = []
            for pid in range(num_nodes):
                try:
                    while True:
                        outbound = transports[pid].outbound.get_nowait()
                        pending_sends.append((pid, outbound.recipient, outbound.envelope))
                except asyncio.QueueEmpty:
                    pass

            for sender, recipient, envelope in pending_sends:
                transports[recipient].deliver_nowait(sender, envelope)

            await asyncio.sleep(0.001)

    router_task = asyncio.create_task(_message_router())

    try:
        tasks = [asyncio.create_task(node.run()) for node in nodes]
        await asyncio.gather(*tasks)
    finally:
        router_task.cancel()
        try:
            await router_task
        except asyncio.CancelledError:
            pass

    return nodes


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
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    use_rust_tx_pool: bool = False,
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
            use_rust_tx_pool=use_rust_tx_pool,
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


async def _node_main_socket(
    sid: str,
    pid: int,
    num_nodes: int,
    faulty: int,
    sig_pk_bin: bytes,
    sig_sk_bin: bytes,
    enc_pk_bin: bytes,
    enc_sk_bin: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk_bin: bytes,
    addresses: list[tuple[str, int]],
    batch_size: int,
    max_rounds: int,
    round_timeout: float,
    transactions_per_node: int,
    tx_input: TxInputMode,
    enable_broadcast_pool_reuse: bool,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    pool_grace_ms: int,
    log_level: str,
    use_rust_tx_pool: bool,
    rust_tx_pool_max_bytes: int,
) -> MultiprocessNodeResult:
    METRICS.reset()
    logger = logging.LoggerAdapter(logging.getLogger("network.hbbft_runner"), extra={"node": pid})
    inbound_messages: Queue = Queue()
    outbound_messages: Queue = Queue()
    stop_event = threading.Event()
    queue_peaks = {
        "raw_inbound_messages": 0,
        "raw_outbound_messages": 0,
        "transport_inbound": 0,
        "transport_outbound": 0,
    }

    def update_peak(name: str, size: int) -> None:
        if size > queue_peaks[name]:
            queue_peaks[name] = size

    server_thread, sender_thread = start_local_socket_transport(
        pid,
        addresses,
        inbound_messages,
        outbound_messages,
        stop_event,
        on_inbound_enqueued=lambda size: update_peak("raw_inbound_messages", size),
    )

    transport = QueueTransport()

    async def _send_forwarder() -> None:
        while True:
            try:
                batch = await _drain_async_queue_batch(transport.outbound)
                update_peak("transport_outbound", transport.outbound.qsize() + len(batch))
                for outbound in batch:
                    with timed_metric("bridge.encode.seconds", node=pid):
                        payload = outbound.envelope.to_bytes(sender=pid)
                    outbound_messages.put((outbound.recipient, payload))
                update_peak("raw_outbound_messages", outbound_messages.qsize())
            except asyncio.CancelledError:
                break

    async def _recv_forwarder() -> None:
        while True:
            try:
                with timed_metric("bridge.thread_queue_drain.seconds", node=pid):
                    messages = await asyncio.to_thread(
                        _drain_thread_queue_batch,
                        inbound_messages,
                        stop_event,
                    )
            except Empty:
                if stop_event.is_set():
                    break
                continue
            try:
                for msg in messages:
                    with timed_metric("bridge.decode.seconds", node=pid):
                        sender, envelope = ProtocolEnvelope.from_bytes(msg)
                    transport.deliver_nowait(sender, envelope)
                update_peak("transport_inbound", transport.inbound.qsize())
            except asyncio.CancelledError:
                break

    common = CommonParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=0)
    crypto = CryptoParams(
        sig_pk=honey_native.SigPublicKey.from_bytes(sig_pk_bin),
        sig_sk=honey_native.SigPrivateShare.from_bytes(sig_sk_bin),
        enc_pk=honey_native.PkePublicKey.from_bytes(enc_pk_bin),
        enc_sk=honey_native.PkePrivateShare.from_bytes(enc_sk_bin),
        ecdsa_pks=ecdsa_pks,
        ecdsa_sk=ecdsa_sk_bin,
    )
    config = HBConfig(
        batch_size=batch_size,
        use_rust_tx_pool=use_rust_tx_pool,
        rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
        max_rounds=max_rounds,
        round_timeout=round_timeout,
        log_level=log_level,
        enable_broadcast_pool_reuse=enable_broadcast_pool_reuse,
        enable_pool_reference_proposals=enable_pool_reference_proposals,
        enable_pool_fetch_fallback=enable_pool_fetch_fallback,
        pool_grace_ms=pool_grace_ms,
    )

    node = HoneyBadgerBFT(common, crypto, transport, config=config)
    _seed_dummy_transactions(node, pid, transactions_per_node, tx_input)

    send_task = asyncio.create_task(_send_forwarder())
    recv_task = asyncio.create_task(_recv_forwarder())

    try:
        log_event(logger, logging.INFO, "node_run_start", sid=sid, rounds=max_rounds)
        with timed_metric("node.run.seconds", node=pid):
            await node.run()
        log_event(logger, logging.INFO, "node_run_finish", sid=sid, round=node.round)
        await asyncio.sleep(0.2)
        return MultiprocessNodeResult(
            pid=pid,
            rounds=node.round,
            delivered=node.txcnt,
            round_build_latencies=tuple(
                getattr(node, "round_build_latencies", tuple(0.0 for _ in node.round_latencies))
            ),
            round_latencies=tuple(node.round_latencies),
            round_wall_latencies=tuple(
                getattr(node, "round_wall_latencies", tuple(node.round_latencies))
            ),
            round_proposed_counts=tuple(node.round_proposed_counts),
            round_delivered_counts=tuple(node.round_delivered_counts),
            origin_tx_latencies=tuple(node.origin_tx_latencies),
            origin_tx_latencies_by_round=tuple(node.origin_tx_latencies_by_round),
            subprotocol_timings=_collect_timing_summaries(),
            queue_peaks=NodeQueuePeaks(
                raw_inbound_messages=queue_peaks["raw_inbound_messages"],
                raw_outbound_messages=queue_peaks["raw_outbound_messages"],
                transport_inbound=queue_peaks["transport_inbound"],
                transport_outbound=queue_peaks["transport_outbound"],
                mailbox_round_inbox=node.mailboxes.peak_inbox_size,
            ),
        )
    except Exception as exc:
        log_event(logger, logging.ERROR, "node_run_error", sid=sid, error=repr(exc))
        raise
    finally:
        stop_event.set()
        send_task.cancel()
        recv_task.cancel()
        try:
            await send_task
        except asyncio.CancelledError:
            pass
        try:
            await recv_task
        except asyncio.CancelledError:
            pass
        server_thread.join(timeout=1.0)
        sender_thread.join(timeout=1.0)
        log_event(logger, logging.DEBUG, "node_shutdown_complete", sid=sid)


def _node_worker(
    sid: str,
    pid: int,
    num_nodes: int,
    faulty: int,
    sig_pk_bin: bytes,
    sig_sk_bin: bytes,
    enc_pk_bin: bytes,
    enc_sk_bin: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk_bin: bytes,
    result_queue: Any | None,
    result_dir: str | None,
    batch_size: int,
    max_rounds: int,
    round_timeout: float,
    addresses: list[tuple[str, int]],
    transactions_per_node: int,
    tx_input: TxInputMode,
    enable_broadcast_pool_reuse: bool,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    pool_grace_ms: int,
    log_level: str,
    use_rust_tx_pool: bool,
    rust_tx_pool_max_bytes: int,
) -> None:
    import sys
    import traceback

    _configure_logging(log_level)
    logger = logging.LoggerAdapter(logging.getLogger("network.hbbft_runner"), extra={"node": pid})
    profile, profile_path = _maybe_start_worker_profile(pid, "hb")
    try:
        log_event(logger, logging.DEBUG, "node_worker_start", sid=sid)
        result = asyncio.run(
            _node_main_socket(
                sid,
                pid,
                num_nodes,
                faulty,
                sig_pk_bin,
                sig_sk_bin,
                enc_pk_bin,
                enc_sk_bin,
                ecdsa_pks,
                ecdsa_sk_bin,
                addresses,
                batch_size,
                max_rounds,
                round_timeout,
                transactions_per_node,
                tx_input,
                enable_broadcast_pool_reuse,
                enable_pool_reference_proposals,
                enable_pool_fetch_fallback,
                pool_grace_ms,
                log_level,
                use_rust_tx_pool,
                rust_tx_pool_max_bytes,
            )
        )
        METRICS.increment("node.worker.completed", node=pid)
        log_event(
            logger,
            logging.INFO,
            "node_worker_finish",
            sid=sid,
            round=result.rounds,
            delivered=result.delivered,
        )
        _publish_worker_status(
            result_queue=result_queue,
            result_dir=result_dir,
            status="ok",
            pid=pid,
            value=_encode_result_payload(result),
        )
    except Exception as exc:
        tb_str = traceback.format_exc()
        print(
            f"[FATAL] Uncaught exception in _node_worker (pid={pid}): {exc}\n{tb_str}",
            file=sys.stderr,
            flush=True,
        )
        logging.error(f"[FATAL] Uncaught exception in _node_worker (pid={pid}): {exc}\n{tb_str}")
        for handler in logging.root.handlers:
            handler.flush()
        _publish_worker_status(
            result_queue=result_queue,
            result_dir=result_dir,
            status="err",
            pid=pid,
            value=f"{repr(exc)}\n{tb_str}",
        )
        sys.exit(1)
    finally:
        _finalize_worker_profile(profile, profile_path, "hb", pid)
        log_event(logger, logging.DEBUG, "node_worker_exit", sid=sid)


def run_local_honeybadger_nodes_multiprocess(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    global_timeout: float = 30.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    enable_broadcast_pool_reuse: bool = False,
    enable_pool_reference_proposals: bool = False,
    enable_pool_fetch_fallback: bool = False,
    pool_grace_ms: int = 200,
    use_rust_tx_pool: bool = False,
    rust_tx_pool_max_bytes: int = 0,
) -> list[int]:
    results = benchmark_local_honeybadger_nodes_multiprocess(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        round_timeout=round_timeout,
        global_timeout=global_timeout,
        transactions_per_node=transactions_per_node,
        tx_input=tx_input,
        log_level=log_level,
        enable_broadcast_pool_reuse=enable_broadcast_pool_reuse,
        enable_pool_reference_proposals=enable_pool_reference_proposals,
        enable_pool_fetch_fallback=enable_pool_fetch_fallback,
        pool_grace_ms=pool_grace_ms,
        use_rust_tx_pool=use_rust_tx_pool,
        rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
    )
    return [result.rounds for result in results]


def benchmark_local_honeybadger_nodes_multiprocess(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    global_timeout: float = 30.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    enable_broadcast_pool_reuse: bool = False,
    enable_pool_reference_proposals: bool = False,
    enable_pool_fetch_fallback: bool = False,
    pool_grace_ms: int = 200,
    use_rust_tx_pool: bool = False,
    rust_tx_pool_max_bytes: int = 0,
) -> list[MultiprocessNodeResult]:
    _configure_logging(log_level)
    sig_pk, sig_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = build_materials(
        num_nodes, faulty
    )
    sig_pk_bin = sig_pk.to_bytes()
    sig_share_bins = [share.to_bytes() for share in sig_shares]
    enc_pk_bin = enc_pk.to_bytes()
    enc_share_bins = [share.to_bytes() for share in enc_shares]

    ctx = mp.get_context("spawn")
    result_queue: Any | None = None
    result_dir: str | None = None
    try:
        result_queue = ctx.Queue()
    except PermissionError:
        result_dir = _build_result_dir("hb", sid)

    base_port = 30000 + (abs(hash(sid)) % 10000)
    addresses = [("127.0.0.1", base_port + i * 4) for i in range(num_nodes)]

    processes: list[mp.Process] = []
    process_by_pid: dict[int, mp.Process] = {}
    for pid in range(num_nodes):
        process = ctx.Process(
            target=_node_worker,
            args=(
                sid,
                pid,
                num_nodes,
                faulty,
                sig_pk_bin,
                sig_share_bins[pid],
                enc_pk_bin,
                enc_share_bins[pid],
                ecdsa_pks,
                ecdsa_sks[pid],
                result_queue,
                result_dir,
                batch_size,
                max_rounds,
                round_timeout,
                addresses,
                transactions_per_node,
                tx_input,
                enable_broadcast_pool_reuse,
                enable_pool_reference_proposals,
                enable_pool_fetch_fallback,
                pool_grace_ms,
                log_level,
                use_rust_tx_pool,
                rust_tx_pool_max_bytes,
            ),
        )
        process.start()
        processes.append(process)
        process_by_pid[pid] = process

    finished: dict[int, MultiprocessNodeResult] = {}
    errors: list[tuple[int, str]] = []
    errored_pids: set[int] = set()
    deadline = time.monotonic() + global_timeout

    while len(finished) + len(errors) < num_nodes and time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0.0:
            break
        try:
            if result_queue is None:
                raise Empty
            status, pid, value = result_queue.get(timeout=min(0.05, remaining))
        except Empty:
            pass
        else:
            if status == "ok":
                finished[pid] = _decode_result_payload(pid, value)
            else:
                errors.append((pid, str(value)))
                errored_pids.add(pid)
        _drain_result_queue(result_queue, finished, errors, errored_pids)
        _drain_result_dir(result_dir, finished, errors, errored_pids)

        for pid, process in process_by_pid.items():
            if pid in finished or pid in errored_pids:
                continue
            if process.exitcode is not None and process.exitcode != 0:
                errors.append((pid, f"process exited with code {process.exitcode}"))
                errored_pids.add(pid)

    for process in processes:
        process.join(timeout=0.2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)
    _drain_result_queue(result_queue, finished, errors, errored_pids)
    _drain_result_dir(result_dir, finished, errors, errored_pids)
    if result_dir is not None:
        shutil.rmtree(result_dir, ignore_errors=True)

    if errors:
        error_text = "; ".join(f"pid={pid}: {msg}" for pid, msg in errors)
        raise RuntimeError(f"Node process failed: {error_text}")
    if len(finished) != num_nodes:
        if result_queue is None:
            fallback_nodes = asyncio.run(
                run_local_honeybadger_nodes_single_process(
                    sid=sid,
                    num_nodes=num_nodes,
                    faulty=faulty,
                    batch_size=batch_size,
                    max_rounds=max_rounds,
                    round_timeout=round_timeout,
                    transactions_per_node=transactions_per_node,
                    tx_input=tx_input,
                    log_level=log_level,
                )
            )
            return _fallback_local_benchmark_results(fallback_nodes)
        raise TimeoutError(
            f"Multiprocess run timed out: completed {len(finished)}/{num_nodes} nodes"
        )

    return [finished[pid] for pid in range(num_nodes)]


async def _dumbo_node_main_socket(
    sid: str,
    pid: int,
    num_nodes: int,
    faulty: int,
    coin_pk_bin: bytes,
    coin_sk_bin: bytes,
    proof_pk_bin: bytes,
    proof_sk_bin: bytes,
    enc_pk_bin: bytes,
    enc_sk_bin: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk_bin: bytes,
    addresses: list[tuple[str, int]],
    batch_size: int,
    max_rounds: int,
    round_timeout: float,
    transactions_per_node: int,
    tx_input: TxInputMode,
    enable_broadcast_pool_reuse: bool,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    pool_grace_ms: int,
    log_level: str,
    use_rust_tx_pool: bool,
    rust_tx_pool_max_bytes: int,
) -> MultiprocessNodeResult:
    METRICS.reset()
    logger = logging.LoggerAdapter(logging.getLogger("network.hbbft_runner"), extra={"node": pid})
    inbound_messages: Queue = Queue()
    outbound_messages: Queue = Queue()
    stop_event = threading.Event()
    queue_peaks = {
        "raw_inbound_messages": 0,
        "raw_outbound_messages": 0,
        "transport_inbound": 0,
        "transport_outbound": 0,
    }

    def update_peak(name: str, size: int) -> None:
        if size > queue_peaks[name]:
            queue_peaks[name] = size

    server_thread, sender_thread = start_local_socket_transport(
        pid,
        addresses,
        inbound_messages,
        outbound_messages,
        stop_event,
        on_inbound_enqueued=lambda size: update_peak("raw_inbound_messages", size),
    )

    transport = QueueTransport()

    async def _send_forwarder() -> None:
        while True:
            try:
                batch = await _drain_async_queue_batch(transport.outbound)
                update_peak("transport_outbound", transport.outbound.qsize() + len(batch))
                for outbound in batch:
                    with timed_metric("bridge.encode.seconds", node=pid):
                        payload = outbound.envelope.to_bytes(sender=pid)
                    outbound_messages.put((outbound.recipient, payload))
                update_peak("raw_outbound_messages", outbound_messages.qsize())
            except asyncio.CancelledError:
                break

    async def _recv_forwarder() -> None:
        while True:
            try:
                with timed_metric("bridge.thread_queue_drain.seconds", node=pid):
                    messages = await asyncio.to_thread(
                        _drain_thread_queue_batch,
                        inbound_messages,
                        stop_event,
                    )
            except Empty:
                if stop_event.is_set():
                    break
                continue
            try:
                for msg in messages:
                    with timed_metric("bridge.decode.seconds", node=pid):
                        sender, envelope = ProtocolEnvelope.from_bytes(msg)
                    transport.deliver_nowait(sender, envelope)
                update_peak("transport_inbound", transport.inbound.qsize())
            except asyncio.CancelledError:
                break

    common = CommonParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=0)
    crypto = CryptoParams(
        sig_pk=honey_native.SigPublicKey.from_bytes(coin_pk_bin),
        sig_sk=honey_native.SigPrivateShare.from_bytes(coin_sk_bin),
        enc_pk=honey_native.PkePublicKey.from_bytes(enc_pk_bin),
        enc_sk=honey_native.PkePrivateShare.from_bytes(enc_sk_bin),
        ecdsa_pks=ecdsa_pks,
        ecdsa_sk=ecdsa_sk_bin,
        proof_sig_pk=honey_native.SigPublicKey.from_bytes(proof_pk_bin),
        proof_sig_sk=honey_native.SigPrivateShare.from_bytes(proof_sk_bin),
    )
    config = HBConfig(
        batch_size=batch_size,
        use_rust_tx_pool=use_rust_tx_pool,
        rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
        max_rounds=max_rounds,
        round_timeout=round_timeout,
        log_level=log_level,
        enable_broadcast_pool_reuse=enable_broadcast_pool_reuse,
        enable_pool_reference_proposals=enable_pool_reference_proposals,
        enable_pool_fetch_fallback=enable_pool_fetch_fallback,
        pool_grace_ms=pool_grace_ms,
    )

    node = DumboBFT(common, crypto, transport, config=config)
    _seed_dummy_transactions(node, pid, transactions_per_node, tx_input)

    send_task = asyncio.create_task(_send_forwarder())
    recv_task = asyncio.create_task(_recv_forwarder())

    try:
        log_event(logger, logging.INFO, "node_run_start", sid=sid, rounds=max_rounds)
        with timed_metric("node.run.seconds", node=pid):
            await node.run()
        log_event(logger, logging.INFO, "node_run_finish", sid=sid, round=node.round)
        await asyncio.sleep(0.2)
        return MultiprocessNodeResult(
            pid=pid,
            rounds=node.round,
            delivered=node.txcnt,
            round_build_latencies=tuple(
                getattr(node, "round_build_latencies", tuple(0.0 for _ in node.round_latencies))
            ),
            round_latencies=tuple(node.round_latencies),
            round_wall_latencies=tuple(
                getattr(node, "round_wall_latencies", tuple(node.round_latencies))
            ),
            round_proposed_counts=tuple(node.round_proposed_counts),
            round_delivered_counts=tuple(node.round_delivered_counts),
            origin_tx_latencies=tuple(node.origin_tx_latencies),
            origin_tx_latencies_by_round=tuple(node.origin_tx_latencies_by_round),
            subprotocol_timings=_collect_timing_summaries(),
            queue_peaks=NodeQueuePeaks(
                raw_inbound_messages=queue_peaks["raw_inbound_messages"],
                raw_outbound_messages=queue_peaks["raw_outbound_messages"],
                transport_inbound=queue_peaks["transport_inbound"],
                transport_outbound=queue_peaks["transport_outbound"],
                mailbox_round_inbox=node.mailboxes.peak_inbox_size,
            ),
        )
    except Exception as exc:
        log_event(logger, logging.ERROR, "node_run_error", sid=sid, error=repr(exc))
        raise
    finally:
        stop_event.set()
        send_task.cancel()
        recv_task.cancel()
        try:
            await send_task
        except asyncio.CancelledError:
            pass
        try:
            await recv_task
        except asyncio.CancelledError:
            pass
        server_thread.join(timeout=1.0)
        sender_thread.join(timeout=1.0)
        log_event(logger, logging.DEBUG, "node_shutdown_complete", sid=sid)


def _dumbo_node_worker(
    sid: str,
    pid: int,
    num_nodes: int,
    faulty: int,
    coin_pk_bin: bytes,
    coin_sk_bin: bytes,
    proof_pk_bin: bytes,
    proof_sk_bin: bytes,
    enc_pk_bin: bytes,
    enc_sk_bin: bytes,
    ecdsa_pks: list[bytes],
    ecdsa_sk_bin: bytes,
    result_queue: Any | None,
    result_dir: str | None,
    batch_size: int,
    max_rounds: int,
    round_timeout: float,
    addresses: list[tuple[str, int]],
    transactions_per_node: int,
    tx_input: TxInputMode,
    enable_broadcast_pool_reuse: bool,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    pool_grace_ms: int,
    log_level: str,
    use_rust_tx_pool: bool,
    rust_tx_pool_max_bytes: int,
) -> None:
    import sys
    import traceback

    _configure_logging(log_level)
    logger = logging.LoggerAdapter(logging.getLogger("network.hbbft_runner"), extra={"node": pid})
    profile, profile_path = _maybe_start_worker_profile(pid, "dumbo")
    try:
        log_event(logger, logging.DEBUG, "node_worker_start", sid=sid)
        result = asyncio.run(
            _dumbo_node_main_socket(
                sid,
                pid,
                num_nodes,
                faulty,
                coin_pk_bin,
                coin_sk_bin,
                proof_pk_bin,
                proof_sk_bin,
                enc_pk_bin,
                enc_sk_bin,
                ecdsa_pks,
                ecdsa_sk_bin,
                addresses,
                batch_size,
                max_rounds,
                round_timeout,
                transactions_per_node,
                tx_input,
                enable_broadcast_pool_reuse,
                enable_pool_reference_proposals,
                enable_pool_fetch_fallback,
                pool_grace_ms,
                log_level,
                use_rust_tx_pool,
                rust_tx_pool_max_bytes,
            )
        )
        METRICS.increment("node.worker.completed", node=pid)
        log_event(
            logger,
            logging.INFO,
            "node_worker_finish",
            sid=sid,
            round=result.rounds,
            delivered=result.delivered,
        )
        _publish_worker_status(
            result_queue=result_queue,
            result_dir=result_dir,
            status="ok",
            pid=pid,
            value=_encode_result_payload(result),
        )
    except Exception as exc:
        tb_str = traceback.format_exc()
        print(
            f"[FATAL] Uncaught exception in _dumbo_node_worker (pid={pid}): {exc}\n{tb_str}",
            file=sys.stderr,
            flush=True,
        )
        logging.error(
            f"[FATAL] Uncaught exception in _dumbo_node_worker (pid={pid}): {exc}\n{tb_str}"
        )
        for handler in logging.root.handlers:
            handler.flush()
        _publish_worker_status(
            result_queue=result_queue,
            result_dir=result_dir,
            status="err",
            pid=pid,
            value=f"{repr(exc)}\n{tb_str}",
        )
        sys.exit(1)
    finally:
        _finalize_worker_profile(profile, profile_path, "dumbo", pid)
        log_event(logger, logging.DEBUG, "node_worker_exit", sid=sid)


def run_local_dumbo_nodes_multiprocess(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    global_timeout: float = 30.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    enable_broadcast_pool_reuse: bool = False,
    enable_pool_reference_proposals: bool = False,
    enable_pool_fetch_fallback: bool = False,
    pool_grace_ms: int = 200,
    use_rust_tx_pool: bool = False,
    rust_tx_pool_max_bytes: int = 0,
) -> list[int]:
    results = benchmark_local_dumbo_nodes_multiprocess(
        sid=sid,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=max_rounds,
        round_timeout=round_timeout,
        global_timeout=global_timeout,
        transactions_per_node=transactions_per_node,
        tx_input=tx_input,
        log_level=log_level,
        enable_broadcast_pool_reuse=enable_broadcast_pool_reuse,
        enable_pool_reference_proposals=enable_pool_reference_proposals,
        enable_pool_fetch_fallback=enable_pool_fetch_fallback,
        pool_grace_ms=pool_grace_ms,
        use_rust_tx_pool=use_rust_tx_pool,
        rust_tx_pool_max_bytes=rust_tx_pool_max_bytes,
    )
    return [result.rounds for result in results]


def benchmark_local_dumbo_nodes_multiprocess(
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int = 1,
    max_rounds: int = 1,
    round_timeout: float = 10.0,
    global_timeout: float = 30.0,
    transactions_per_node: int = 1,
    tx_input: TxInputMode = "python_json",
    log_level: str = "WARNING",
    enable_broadcast_pool_reuse: bool = False,
    enable_pool_reference_proposals: bool = False,
    enable_pool_fetch_fallback: bool = False,
    pool_grace_ms: int = 200,
    use_rust_tx_pool: bool = False,
    rust_tx_pool_max_bytes: int = 0,
) -> list[MultiprocessNodeResult]:
    _configure_logging(log_level)
    coin_pk, coin_shares, proof_pk, proof_shares, enc_pk, enc_shares, ecdsa_pks, ecdsa_sks = (
        build_dumbo_materials(num_nodes, faulty)
    )
    coin_pk_bin = coin_pk.to_bytes()
    coin_share_bins = [share.to_bytes() for share in coin_shares]
    proof_pk_bin = proof_pk.to_bytes()
    proof_share_bins = [share.to_bytes() for share in proof_shares]
    enc_pk_bin = enc_pk.to_bytes()
    enc_share_bins = [share.to_bytes() for share in enc_shares]

    ctx = mp.get_context("spawn")
    result_queue: Any | None = None
    result_dir: str | None = None
    try:
        result_queue = ctx.Queue()
    except PermissionError:
        result_dir = _build_result_dir("dumbo", sid)

    base_port = 30000 + (abs(hash(sid)) % 10000)
    addresses = [("127.0.0.1", base_port + i * 4) for i in range(num_nodes)]

    processes: list[mp.Process] = []
    process_by_pid: dict[int, mp.Process] = {}
    for pid in range(num_nodes):
        process = ctx.Process(
            target=_dumbo_node_worker,
            args=(
                sid,
                pid,
                num_nodes,
                faulty,
                coin_pk_bin,
                coin_share_bins[pid],
                proof_pk_bin,
                proof_share_bins[pid],
                enc_pk_bin,
                enc_share_bins[pid],
                ecdsa_pks,
                ecdsa_sks[pid],
                result_queue,
                result_dir,
                batch_size,
                max_rounds,
                round_timeout,
                addresses,
                transactions_per_node,
                tx_input,
                enable_broadcast_pool_reuse,
                enable_pool_reference_proposals,
                enable_pool_fetch_fallback,
                pool_grace_ms,
                log_level,
                use_rust_tx_pool,
                rust_tx_pool_max_bytes,
            ),
        )
        process.start()
        processes.append(process)
        process_by_pid[pid] = process

    finished: dict[int, MultiprocessNodeResult] = {}
    errors: list[tuple[int, str]] = []
    errored_pids: set[int] = set()
    deadline = time.monotonic() + global_timeout

    while len(finished) + len(errors) < num_nodes and time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0.0:
            break
        try:
            if result_queue is None:
                raise Empty
            status, pid, value = result_queue.get(timeout=min(0.05, remaining))
        except Empty:
            pass
        else:
            if status == "ok":
                finished[pid] = _decode_result_payload(pid, value)
            else:
                errors.append((pid, str(value)))
                errored_pids.add(pid)
        _drain_result_queue(result_queue, finished, errors, errored_pids)
        _drain_result_dir(result_dir, finished, errors, errored_pids)

        for pid, process in process_by_pid.items():
            if pid in finished or pid in errored_pids:
                continue
            if process.exitcode is not None and process.exitcode != 0:
                errors.append((pid, f"process exited with code {process.exitcode}"))
                errored_pids.add(pid)

    for process in processes:
        process.join(timeout=0.2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)
    _drain_result_queue(result_queue, finished, errors, errored_pids)
    _drain_result_dir(result_dir, finished, errors, errored_pids)
    if result_dir is not None:
        shutil.rmtree(result_dir, ignore_errors=True)

    if errors:
        error_text = "; ".join(f"pid={pid}: {msg}" for pid, msg in errors)
        raise RuntimeError(f"Node process failed: {error_text}")
    if len(finished) != num_nodes:
        if result_queue is None:
            fallback_nodes = asyncio.run(
                run_local_dumbo_nodes_single_process(
                    sid=sid,
                    num_nodes=num_nodes,
                    faulty=faulty,
                    batch_size=batch_size,
                    max_rounds=max_rounds,
                    round_timeout=round_timeout,
                    transactions_per_node=transactions_per_node,
                    tx_input=tx_input,
                    log_level=log_level,
                )
            )
            return _fallback_local_benchmark_results(fallback_nodes)
        raise TimeoutError(
            f"Multiprocess run timed out: completed {len(finished)}/{num_nodes} nodes"
        )

    return [finished[pid] for pid in range(num_nodes)]
