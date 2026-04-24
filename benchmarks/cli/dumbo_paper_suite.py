from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import subprocess
import sys
import time
import tomllib
from collections import defaultdict
from datetime import UTC, datetime
from itertools import product
from pathlib import Path
from statistics import fmean
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / "native" / "target" / "release" / "honey-bench"
DEFAULT_SUITE_CONFIG = REPO_ROOT / "benchmarks" / "configs" / "paper" / "dumbo_comprehensive.toml"

SUPPORTED_BACKENDS = {"python", "rust_fin", "rust_dumbo"}
DIMENSION_KEYS = (
    "backend",
    "reuse_enabled",
    "nodes",
    "faulty",
    "batch_size",
    "rounds",
    "global_timeout",
    "pool_grace_ms",
    "pool_reuse_limit_per_round",
    "pool_expire_rounds",
    "pool_mempool_max",
    "enable_pool_reference_proposals",
    "enable_pool_fetch_fallback",
    "network_faults",
)
SUMMARY_GROUP_KEYS = (
    "experiment",
    "backend",
    "reuse_mode",
    "nodes",
    "faulty",
    "batch_size",
    "rounds",
    "global_timeout",
    "pool_grace_ms",
    "pool_reuse_limit_per_round",
    "pool_expire_rounds",
    "pool_mempool_max",
    "enable_pool_reference_proposals",
    "enable_pool_fetch_fallback",
    "network_fault_label",
    "byzantine_label",
)
CASE_LABEL_KEYS = (
    "backend",
    "reuse_enabled",
    "nodes",
    "batch_size",
    "rounds",
    "pool_grace_ms",
    "pool_reuse_limit_per_round",
    "pool_expire_rounds",
    "pool_mempool_max",
    "network_fault_label",
    "byzantine_label",
)


def _format_toml_key(key: str) -> str:
    if key.isidentifier():
        return key
    return json.dumps(key)


def _format_toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not (value == value and value not in (float("inf"), float("-inf"))):
            raise ValueError(f"TOML does not support non-finite floats: {value!r}")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, dict):
        rendered = ", ".join(
            f"{_format_toml_key(str(key))} = {_format_toml_value(item)}"
            for key, item in value.items()
        )
        return f"{{ {rendered} }}"
    if isinstance(value, list):
        rendered = ", ".join(_format_toml_value(item) for item in value)
        return f"[{rendered}]"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def _render_config(
    *,
    sid: str,
    nodes: int,
    faulty: int,
    rounds: int,
    batch_size: int,
    global_timeout: float,
    config_payload: dict[str, object],
) -> str:
    lines = [
        'mode = "dumbo"',
        f"sid = {json.dumps(sid)}",
        f"nodes = {nodes}",
        f"faulty = {faulty}",
        f"rounds = {rounds}",
        f"batch_size = {batch_size}",
        f"global_timeout = {_format_toml_value(global_timeout)}",
        "",
        "[config]",
    ]
    for key, value in config_payload.items():
        lines.append(f"{_format_toml_key(key)} = {_format_toml_value(value)}")
    return "\n".join(lines) + "\n"


def _run_case(binary: Path, config_path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(binary), "run", "--config", str(config_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(error_text)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("honey-bench produced no output")
    return json.loads(payload)


def _git_metadata() -> dict[str, str | None]:
    def run_git(*args: str) -> str | None:
        completed = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return None
        return completed.stdout.strip() or None

    return {
        "commit": run_git("rev-parse", "HEAD"),
        "branch": run_git("rev-parse", "--abbrev-ref", "HEAD"),
        "status_short": run_git("status", "--short"),
    }


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return REPO_ROOT / "benchmarks" / "results" / f"dumbo-paper-suite-{stamp}"


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _as_list(value: object) -> list[object]:
    if isinstance(value, list):
        if not value:
            raise ValueError("list-valued experiment dimensions must not be empty")
        return list(value)
    return [value]


def _normalize_backend(value: object) -> str:
    backend = str(value)
    if backend not in SUPPORTED_BACKENDS:
        raise ValueError(f"unsupported backend: {backend}")
    return backend


def _normalize_bool(value: object, *, key: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _normalize_int(value: object, *, key: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if value < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    return value


def _normalize_float(value: object, *, key: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{key} must be numeric")
    result = float(value)
    if result < minimum:
        raise ValueError(f"{key} must be >= {minimum}")
    return result


def _normalize_nonnegative_int_list(value: object, *, key: str) -> list[int]:
    if not isinstance(value, list):
        raise ValueError(f"{key} must be an array")
    result: list[int] = []
    for item in value:
        result.append(_normalize_int(item, key=key, minimum=0))
    return result


def _slugify_label(label: str) -> str:
    compact = "".join(ch.lower() if ch.isalnum() else "-" for ch in label.strip())
    while "--" in compact:
        compact = compact.replace("--", "-")
    return compact.strip("-") or "unnamed"


def _normalize_network_faults(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("network_faults must be a TOML table or inline table")

    allowed_keys = {
        "label",
        "enabled",
        "seed",
        "fixed_delay_ms",
        "jitter_ms",
        "slow_honest",
    }
    unknown_keys = sorted(key for key in value if key not in allowed_keys)
    if unknown_keys:
        raise ValueError(f"network_faults contains unsupported keys: {', '.join(unknown_keys)}")

    normalized: dict[str, object] = {
        "enabled": _normalize_bool(value.get("enabled", False), key="network_faults.enabled")
    }
    if "label" in value:
        normalized["label"] = str(value["label"])

    seed = _normalize_int(value.get("seed", 0), key="network_faults.seed", minimum=0)
    fixed_delay_ms = _normalize_int(
        value.get("fixed_delay_ms", 0),
        key="network_faults.fixed_delay_ms",
        minimum=0,
    )
    jitter_ms = _normalize_int(
        value.get("jitter_ms", 0),
        key="network_faults.jitter_ms",
        minimum=0,
    )
    if seed:
        normalized["seed"] = seed
    if fixed_delay_ms:
        normalized["fixed_delay_ms"] = fixed_delay_ms
    if jitter_ms:
        normalized["jitter_ms"] = jitter_ms

    slow_honest_value = value.get("slow_honest")
    if slow_honest_value is not None:
        if not isinstance(slow_honest_value, dict):
            raise ValueError("network_faults.slow_honest must be a TOML table or inline table")
        allowed_slow_keys = {"pids", "extra_delay_ms"}
        unknown_slow_keys = sorted(key for key in slow_honest_value if key not in allowed_slow_keys)
        if unknown_slow_keys:
            raise ValueError(
                "network_faults.slow_honest contains unsupported keys: "
                + ", ".join(unknown_slow_keys)
            )
        pids = _normalize_nonnegative_int_list(
            slow_honest_value.get("pids", []),
            key="network_faults.slow_honest.pids",
        )
        extra_delay_ms = _normalize_int(
            slow_honest_value.get("extra_delay_ms", 0),
            key="network_faults.slow_honest.extra_delay_ms",
            minimum=0,
        )
        if pids and extra_delay_ms == 0:
            raise ValueError(
                "network_faults.slow_honest.extra_delay_ms must be > 0 when pids are provided"
            )
        if extra_delay_ms > 0 and not pids:
            raise ValueError(
                "network_faults.slow_honest.pids must be non-empty when extra_delay_ms > 0"
            )
        if pids:
            normalized["slow_honest"] = {
                "pids": pids,
                "extra_delay_ms": extra_delay_ms,
            }

    return normalized


def _normalize_byzantine_nodes(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ValueError("byzantine_nodes must be an array of inline tables")
    normalized: list[dict[str, object]] = []
    seen_pids: set[int] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError("byzantine_nodes entries must be TOML inline tables")
        allowed_keys = {"pid", "behavior"}
        unknown_keys = sorted(key for key in item if key not in allowed_keys)
        if unknown_keys:
            raise ValueError(
                "byzantine_nodes contains unsupported keys: " + ", ".join(unknown_keys)
            )
        pid = _normalize_int(item.get("pid"), key=f"byzantine_nodes[{index}].pid", minimum=0)
        behavior = str(item.get("behavior", ""))
        if behavior not in {"silent", "invalid_fetch_response"}:
            raise ValueError(
                "byzantine_nodes[].behavior must be one of: silent, invalid_fetch_response"
            )
        if pid in seen_pids:
            raise ValueError(f"duplicate byzantine_nodes pid: {pid}")
        seen_pids.add(pid)
        normalized.append({"pid": pid, "behavior": behavior})
    return normalized


def _network_fault_payload(network_faults: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in network_faults.items() if key != "label"}


def _network_fault_label(network_faults: dict[str, object]) -> str:
    custom_label = network_faults.get("label")
    if custom_label is not None:
        return _slugify_label(str(custom_label))
    if not bool(network_faults.get("enabled", False)):
        return "none"

    parts: list[str] = []
    fixed_delay_ms = int(network_faults.get("fixed_delay_ms", 0))
    jitter_ms = int(network_faults.get("jitter_ms", 0))
    seed = int(network_faults.get("seed", 0))
    if fixed_delay_ms:
        parts.append(f"fd{fixed_delay_ms}")
    if jitter_ms:
        parts.append(f"j{jitter_ms}")
    slow_honest = network_faults.get("slow_honest")
    if isinstance(slow_honest, dict):
        extra_delay_ms = int(slow_honest.get("extra_delay_ms", 0))
        pids = [int(pid) for pid in slow_honest.get("pids", [])]
        if extra_delay_ms and pids:
            pid_label = "-".join(str(pid) for pid in pids)
            parts.append(f"slow{extra_delay_ms}-p{pid_label}")
    if seed:
        parts.append(f"s{seed}")
    return "-".join(parts) if parts else "enabled"


def _byzantine_label(byzantine_nodes: list[dict[str, object]]) -> str:
    if not byzantine_nodes:
        return "none"
    parts = []
    for node in sorted(byzantine_nodes, key=lambda item: int(item["pid"])):
        parts.append(f"{node['behavior']}-p{node['pid']}")
    return "-".join(parts)


def _normalize_dimension_value(key: str, value: object) -> object:
    if key == "backend":
        return _normalize_backend(value)
    if key in {"reuse_enabled", "enable_pool_reference_proposals", "enable_pool_fetch_fallback"}:
        return _normalize_bool(value, key=key)
    if key == "network_faults":
        return _normalize_network_faults(value)
    if key in {
        "nodes",
        "faulty",
        "batch_size",
        "rounds",
        "pool_grace_ms",
        "pool_reuse_limit_per_round",
        "pool_expire_rounds",
        "pool_mempool_max",
    }:
        minimum = 1 if key in {"nodes", "batch_size", "rounds"} else 0
        return _normalize_int(value, key=key, minimum=minimum)
    if key == "global_timeout":
        return _normalize_float(value, key=key, minimum=0.001)
    raise ValueError(f"unsupported experiment dimension: {key}")


def _reuse_mode_label(enabled: bool) -> str:
    return "reuse_on" if enabled else "reuse_off"


def _load_suite(path: Path) -> tuple[str, dict[str, object], list[dict[str, object]]]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    suite_meta = payload.get("suite", {})
    defaults = payload.get("defaults", {})
    experiments = payload.get("experiments", [])
    if not isinstance(suite_meta, dict):
        raise ValueError("[suite] must be a TOML table")
    if not isinstance(defaults, dict):
        raise ValueError("[defaults] must be a TOML table")
    if not isinstance(experiments, list):
        raise ValueError("[[experiments]] entries are required")
    suite_name = str(suite_meta.get("name", path.stem))
    return suite_name, dict(defaults), [dict(item) for item in experiments]


def _expand_experiment(
    experiment: dict[str, object],
    defaults: dict[str, object],
) -> tuple[dict[str, object], list[dict[str, object]]]:
    merged: dict[str, object] = {**defaults, **experiment}
    name = str(merged.pop("name"))
    description = str(merged.pop("description", ""))
    repeats = _normalize_int(merged.pop("repeats", 1), key="repeats", minimum=1)
    byzantine_nodes = _normalize_byzantine_nodes(merged.pop("byzantine_nodes", []))

    dimensions: list[tuple[str, list[object]]] = []
    for key in DIMENSION_KEYS:
        if key not in merged:
            continue
        normalized_values = [
            _normalize_dimension_value(key, item) for item in _as_list(merged.pop(key))
        ]
        dimensions.append((key, normalized_values))

    if "backend" not in {key for key, _ in dimensions}:
        raise ValueError(f"experiment {name!r} is missing backend")
    if "nodes" not in {key for key, _ in dimensions}:
        raise ValueError(f"experiment {name!r} is missing nodes")
    if "batch_size" not in {key for key, _ in dimensions}:
        raise ValueError(f"experiment {name!r} is missing batch_size")
    if "rounds" not in {key for key, _ in dimensions}:
        raise ValueError(f"experiment {name!r} is missing rounds")
    if "global_timeout" not in {key for key, _ in dimensions}:
        raise ValueError(f"experiment {name!r} is missing global_timeout")

    unknown_keys = sorted(merged)
    if unknown_keys:
        raise ValueError(
            f"experiment {name!r} contains unsupported keys: {', '.join(unknown_keys)}"
        )

    case_dimensions = [values for _, values in dimensions]
    cases: list[dict[str, object]] = []
    for values in product(*case_dimensions):
        case = {key: value for (key, _), value in zip(dimensions, values, strict=True)}
        if "faulty" not in case:
            nodes = int(case["nodes"])
            case["faulty"] = max((nodes - 1) // 3, 0)
        if "reuse_enabled" not in case:
            case["reuse_enabled"] = False
        if "pool_grace_ms" not in case:
            case["pool_grace_ms"] = 100
        if "pool_reuse_limit_per_round" not in case:
            case["pool_reuse_limit_per_round"] = 4
        if "pool_expire_rounds" not in case:
            case["pool_expire_rounds"] = 10
        if "pool_mempool_max" not in case:
            case["pool_mempool_max"] = 1024
        if "enable_pool_reference_proposals" not in case:
            case["enable_pool_reference_proposals"] = True
        if "enable_pool_fetch_fallback" not in case:
            case["enable_pool_fetch_fallback"] = True
        if "network_faults" not in case:
            case["network_faults"] = {"enabled": False}
        case["byzantine_nodes"] = [dict(item) for item in byzantine_nodes]
        case["network_fault_label"] = _network_fault_label(
            dict(case["network_faults"])  # type: ignore[arg-type]
        )
        case["byzantine_label"] = _byzantine_label(
            list(case["byzantine_nodes"])  # type: ignore[arg-type]
        )
        cases.append(case)

    metadata = {
        "name": name,
        "description": description,
        "repeats": repeats,
        "case_count": len(cases),
        "run_count": len(cases) * repeats,
    }
    return metadata, cases


def _summarize_round_metrics(rounds: list[dict[str, Any]]) -> dict[str, int]:
    totals = {
        "send_events_total": 0,
        "send_payload_bytes_total": 0,
        "proposal_ready_events_total": 0,
        "proposal_ready_payload_bytes_total": 0,
        "proposal_ready_certificate_bytes_total": 0,
        "tracked_driver_bytes_total": 0,
        "reused_reference_total": 0,
        "fetch_requests_sent_total": 0,
        "fetch_responses_served_total": 0,
        "fetch_responses_received_total": 0,
        "fetched_reference_total": 0,
    }
    for round_data in rounds:
        stats = round_data.get("acs_drive_stats", {}) or {}
        send_payload_bytes = int(stats.get("send_payload_bytes", 0))
        proposal_payload_bytes = int(stats.get("proposal_ready_payload_bytes", 0))
        proposal_certificate_bytes = int(stats.get("proposal_ready_certificate_bytes", 0))
        totals["send_events_total"] += int(stats.get("send_events", 0))
        totals["send_payload_bytes_total"] += send_payload_bytes
        totals["proposal_ready_events_total"] += int(stats.get("proposal_ready_events", 0))
        totals["proposal_ready_payload_bytes_total"] += proposal_payload_bytes
        totals["proposal_ready_certificate_bytes_total"] += proposal_certificate_bytes
        totals["tracked_driver_bytes_total"] += (
            send_payload_bytes + proposal_payload_bytes + proposal_certificate_bytes
        )
        totals["reused_reference_total"] += int(round_data.get("reused_reference_count", 0))
        totals["fetch_requests_sent_total"] += int(round_data.get("fetch_requests_sent", 0))
        totals["fetch_responses_served_total"] += int(round_data.get("fetch_responses_served", 0))
        totals["fetch_responses_received_total"] += int(
            round_data.get("fetch_responses_received", 0)
        )
        totals["fetched_reference_total"] += int(round_data.get("fetched_reference_count", 0))
    return totals


def _summarize_transport_metrics(nodes: list[dict[str, Any]]) -> dict[str, int]:
    totals = {
        "transport_sent_frames_total": 0,
        "transport_recv_frames_total": 0,
        "transport_connect_retries_total": 0,
        "transport_delayed_frames_total": 0,
        "transport_injected_delay_ms_total": 0,
        "transport_max_delayed_frames_per_node": 0,
        "transport_max_injected_delay_ms_per_node": 0,
    }
    for node in nodes:
        sent_frames = int(node.get("transport_sent_frames", 0))
        recv_frames = int(node.get("transport_recv_frames", 0))
        connect_retries = int(node.get("transport_connect_retries", 0))
        delayed_frames = int(node.get("transport_delayed_frames", 0))
        injected_delay_ms = int(node.get("transport_total_injected_delay_ms", 0))
        totals["transport_sent_frames_total"] += sent_frames
        totals["transport_recv_frames_total"] += recv_frames
        totals["transport_connect_retries_total"] += connect_retries
        totals["transport_delayed_frames_total"] += delayed_frames
        totals["transport_injected_delay_ms_total"] += injected_delay_ms
        totals["transport_max_delayed_frames_per_node"] = max(
            totals["transport_max_delayed_frames_per_node"],
            delayed_frames,
        )
        totals["transport_max_injected_delay_ms_per_node"] = max(
            totals["transport_max_injected_delay_ms_per_node"],
            injected_delay_ms,
        )
    return totals


def _summarize_byzantine_metrics(nodes: list[dict[str, Any]]) -> dict[str, int]:
    totals = {
        "byzantine_invalid_fetch_responses_sent_total": 0,
        "byzantine_fetch_requests_ignored_total": 0,
        "byzantine_batch_broadcast_suppressed_total": 0,
        "byzantine_share_broadcast_suppressed_total": 0,
        "byzantine_empty_proposal_rounds_total": 0,
    }
    for node in nodes:
        totals["byzantine_invalid_fetch_responses_sent_total"] += int(
            node.get("byzantine_invalid_fetch_responses_sent", 0)
        )
        totals["byzantine_fetch_requests_ignored_total"] += int(
            node.get("byzantine_fetch_requests_ignored", 0)
        )
        totals["byzantine_batch_broadcast_suppressed_total"] += int(
            node.get("byzantine_batch_broadcast_suppressed", 0)
        )
        totals["byzantine_share_broadcast_suppressed_total"] += int(
            node.get("byzantine_share_broadcast_suppressed", 0)
        )
        totals["byzantine_empty_proposal_rounds_total"] += int(
            node.get("byzantine_empty_proposal_rounds", 0)
        )
    return totals


def _build_run_record(
    *,
    experiment: str,
    case: dict[str, object],
    repeat_index: int,
    elapsed_seconds: float,
    result: dict[str, Any],
) -> dict[str, Any]:
    rounds_data = result.get("rounds", [])
    nodes_data = result.get("nodes", [])
    transport_metrics = _summarize_transport_metrics(nodes_data)
    byzantine_metrics = _summarize_byzantine_metrics(nodes_data)
    network_faults = _network_fault_payload(dict(case["network_faults"]))  # type: ignore[arg-type]
    slow_honest = network_faults.get("slow_honest")
    slow_honest_pids = []
    slow_honest_extra_delay_ms = 0
    if isinstance(slow_honest, dict):
        slow_honest_pids = [int(pid) for pid in slow_honest.get("pids", [])]
        slow_honest_extra_delay_ms = int(slow_honest.get("extra_delay_ms", 0))
    delivered_total = sum(int(round_data.get("delivered_count", 0)) for round_data in rounds_data)
    wall_total_seconds = sum(
        float(round_data.get("wall_seconds", 0.0)) for round_data in rounds_data
    )
    acs_total_seconds = sum(float(round_data.get("acs_seconds", 0.0)) for round_data in rounds_data)
    round_metrics = _summarize_round_metrics(rounds_data)
    tracked_driver_bytes_total = int(round_metrics["tracked_driver_bytes_total"])

    return {
        "experiment": experiment,
        "backend": str(case["backend"]),
        "reuse_mode": _reuse_mode_label(bool(case["reuse_enabled"])),
        "reuse_enabled": bool(case["reuse_enabled"]),
        "nodes": int(case["nodes"]),
        "faulty": int(case["faulty"]),
        "batch_size": int(case["batch_size"]),
        "rounds": int(case["rounds"]),
        "global_timeout": float(case["global_timeout"]),
        "pool_grace_ms": int(case["pool_grace_ms"]),
        "pool_reuse_limit_per_round": int(case["pool_reuse_limit_per_round"]),
        "pool_expire_rounds": int(case["pool_expire_rounds"]),
        "pool_mempool_max": int(case["pool_mempool_max"]),
        "enable_pool_reference_proposals": bool(case["enable_pool_reference_proposals"]),
        "enable_pool_fetch_fallback": bool(case["enable_pool_fetch_fallback"]),
        "network_fault_label": str(case["network_fault_label"]),
        "byzantine_label": str(case["byzantine_label"]),
        "byzantine_nodes": tuple(
            (int(item["pid"]), str(item["behavior"]))
            for item in case["byzantine_nodes"]  # type: ignore[index]
        ),
        "network_fault_enabled": bool(network_faults.get("enabled", False)),
        "network_seed": int(network_faults.get("seed", 0)),
        "network_fixed_delay_ms": int(network_faults.get("fixed_delay_ms", 0)),
        "network_jitter_ms": int(network_faults.get("jitter_ms", 0)),
        "network_slow_honest_pids": tuple(slow_honest_pids),
        "network_slow_honest_extra_delay_ms": slow_honest_extra_delay_ms,
        "repeat_index": repeat_index,
        "elapsed_seconds": elapsed_seconds,
        "delivered_total": delivered_total,
        "wall_total_seconds": wall_total_seconds,
        "acs_total_seconds": acs_total_seconds,
        "tps_wall": (delivered_total / wall_total_seconds) if wall_total_seconds else 0.0,
        "tps_acs": (delivered_total / acs_total_seconds) if acs_total_seconds else 0.0,
        "send_events_total": int(round_metrics["send_events_total"]),
        "send_payload_bytes_total": int(round_metrics["send_payload_bytes_total"]),
        "proposal_ready_events_total": int(round_metrics["proposal_ready_events_total"]),
        "proposal_ready_payload_bytes_total": int(
            round_metrics["proposal_ready_payload_bytes_total"]
        ),
        "proposal_ready_certificate_bytes_total": int(
            round_metrics["proposal_ready_certificate_bytes_total"]
        ),
        "tracked_driver_bytes_total": tracked_driver_bytes_total,
        "tracked_driver_bytes_per_delivered_tx": (
            tracked_driver_bytes_total / delivered_total if delivered_total else 0.0
        ),
        "reused_reference_total": int(round_metrics["reused_reference_total"]),
        "reused_references_per_delivered_tx": (
            int(round_metrics["reused_reference_total"]) / delivered_total
            if delivered_total
            else 0.0
        ),
        "fetch_requests_sent_total": int(round_metrics["fetch_requests_sent_total"]),
        "fetch_responses_served_total": int(round_metrics["fetch_responses_served_total"]),
        "fetch_responses_received_total": int(round_metrics["fetch_responses_received_total"]),
        "fetched_reference_total": int(round_metrics["fetched_reference_total"]),
        "fetch_requests_per_delivered_tx": (
            int(round_metrics["fetch_requests_sent_total"]) / delivered_total
            if delivered_total
            else 0.0
        ),
        "fetched_references_per_delivered_tx": (
            int(round_metrics["fetched_reference_total"]) / delivered_total
            if delivered_total
            else 0.0
        ),
        "transport_sent_frames_total": int(transport_metrics["transport_sent_frames_total"]),
        "transport_recv_frames_total": int(transport_metrics["transport_recv_frames_total"]),
        "transport_connect_retries_total": int(
            transport_metrics["transport_connect_retries_total"]
        ),
        "transport_delayed_frames_total": int(transport_metrics["transport_delayed_frames_total"]),
        "transport_injected_delay_ms_total": int(
            transport_metrics["transport_injected_delay_ms_total"]
        ),
        "transport_max_delayed_frames_per_node": int(
            transport_metrics["transport_max_delayed_frames_per_node"]
        ),
        "transport_max_injected_delay_ms_per_node": int(
            transport_metrics["transport_max_injected_delay_ms_per_node"]
        ),
        "byzantine_invalid_fetch_responses_sent_total": int(
            byzantine_metrics["byzantine_invalid_fetch_responses_sent_total"]
        ),
        "byzantine_fetch_requests_ignored_total": int(
            byzantine_metrics["byzantine_fetch_requests_ignored_total"]
        ),
        "byzantine_batch_broadcast_suppressed_total": int(
            byzantine_metrics["byzantine_batch_broadcast_suppressed_total"]
        ),
        "byzantine_share_broadcast_suppressed_total": int(
            byzantine_metrics["byzantine_share_broadcast_suppressed_total"]
        ),
        "byzantine_empty_proposal_rounds_total": int(
            byzantine_metrics["byzantine_empty_proposal_rounds_total"]
        ),
        "chain_digest": result.get("chain_digest"),
        "result": result,
    }


def _aggregate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[object, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = tuple(record[field] for field in SUMMARY_GROUP_KEYS)
        grouped[key].append(record)

    summaries: list[dict[str, Any]] = []
    mean_fields = (
        "elapsed_seconds",
        "delivered_total",
        "wall_total_seconds",
        "acs_total_seconds",
        "tps_wall",
        "tps_acs",
        "send_events_total",
        "send_payload_bytes_total",
        "proposal_ready_events_total",
        "proposal_ready_payload_bytes_total",
        "proposal_ready_certificate_bytes_total",
        "tracked_driver_bytes_total",
        "tracked_driver_bytes_per_delivered_tx",
        "reused_reference_total",
        "reused_references_per_delivered_tx",
        "fetch_requests_sent_total",
        "fetch_responses_served_total",
        "fetch_responses_received_total",
        "fetched_reference_total",
        "fetch_requests_per_delivered_tx",
        "fetched_references_per_delivered_tx",
        "transport_sent_frames_total",
        "transport_recv_frames_total",
        "transport_connect_retries_total",
        "transport_delayed_frames_total",
        "transport_injected_delay_ms_total",
        "transport_max_delayed_frames_per_node",
        "transport_max_injected_delay_ms_per_node",
        "byzantine_invalid_fetch_responses_sent_total",
        "byzantine_fetch_requests_ignored_total",
        "byzantine_batch_broadcast_suppressed_total",
        "byzantine_share_broadcast_suppressed_total",
        "byzantine_empty_proposal_rounds_total",
    )
    for key, runs in sorted(grouped.items()):
        summary = {field: value for field, value in zip(SUMMARY_GROUP_KEYS, key, strict=True)}
        summary["run_count"] = len(runs)
        for field in mean_fields:
            summary[f"{field}_mean"] = fmean(float(run[field]) for run in runs)
        summaries.append(summary)
    return summaries


def _build_reuse_deltas(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = {tuple(item[field] for field in SUMMARY_GROUP_KEYS): item for item in summaries}
    delta_key_fields = tuple(field for field in SUMMARY_GROUP_KEYS if field != "reuse_mode")
    delta_records: list[dict[str, Any]] = []
    keys = sorted({tuple(item[field] for field in delta_key_fields) for item in summaries})
    for key in keys:
        common = {field: value for field, value in zip(delta_key_fields, key, strict=True)}
        off = indexed.get(
            tuple(
                common.get(field, "reuse_off") if field != "reuse_mode" else "reuse_off"
                for field in SUMMARY_GROUP_KEYS
            )
        )
        on = indexed.get(
            tuple(
                common.get(field, "reuse_on") if field != "reuse_mode" else "reuse_on"
                for field in SUMMARY_GROUP_KEYS
            )
        )
        if off is None or on is None:
            continue

        def pct_change(new_value: float, old_value: float) -> float:
            if old_value == 0.0:
                return 0.0
            return ((new_value / old_value) - 1.0) * 100.0

        delta_records.append(
            {
                **common,
                "tps_wall_delta_pct": pct_change(
                    float(on["tps_wall_mean"]),
                    float(off["tps_wall_mean"]),
                ),
                "tps_acs_delta_pct": pct_change(
                    float(on["tps_acs_mean"]),
                    float(off["tps_acs_mean"]),
                ),
                "wall_total_delta_pct": pct_change(
                    float(on["wall_total_seconds_mean"]),
                    float(off["wall_total_seconds_mean"]),
                ),
                "acs_total_delta_pct": pct_change(
                    float(on["acs_total_seconds_mean"]),
                    float(off["acs_total_seconds_mean"]),
                ),
                "tracked_driver_bytes_delta_pct": pct_change(
                    float(on["tracked_driver_bytes_total_mean"]),
                    float(off["tracked_driver_bytes_total_mean"]),
                ),
                "tracked_driver_bytes_per_tx_delta_pct": pct_change(
                    float(on["tracked_driver_bytes_per_delivered_tx_mean"]),
                    float(off["tracked_driver_bytes_per_delivered_tx_mean"]),
                ),
                "reused_reference_total_mean": float(on["reused_reference_total_mean"]),
                "fetch_requests_sent_total_mean": float(on["fetch_requests_sent_total_mean"]),
                "fetch_responses_served_total_mean": float(on["fetch_responses_served_total_mean"]),
                "fetch_responses_received_total_mean": float(
                    on["fetch_responses_received_total_mean"]
                ),
                "fetched_reference_total_mean": float(on["fetched_reference_total_mean"]),
            }
        )
    return delta_records


def _build_backend_deltas(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    index_fields = SUMMARY_GROUP_KEYS
    indexed = {tuple(item[field] for field in index_fields): item for item in summaries}
    common_fields = tuple(field for field in index_fields if field != "backend")
    common_keys = sorted({tuple(item[field] for field in common_fields) for item in summaries})
    deltas: list[dict[str, Any]] = []
    for key in common_keys:
        common = {field: value for field, value in zip(common_fields, key, strict=True)}
        python_key = tuple(
            common.get(field, "python") if field != "backend" else "python"
            for field in index_fields
        )
        python_item = indexed.get(python_key)
        if python_item is None:
            continue
        for backend in sorted(
            {str(item["backend"]) for item in summaries if item["backend"] != "python"}
        ):
            candidate_key = tuple(
                common.get(field, backend) if field != "backend" else backend
                for field in index_fields
            )
            candidate_item = indexed.get(candidate_key)
            if candidate_item is None:
                continue

            def pct_change(new_value: float, old_value: float) -> float:
                if old_value == 0.0:
                    return 0.0
                return ((new_value / old_value) - 1.0) * 100.0

            deltas.append(
                {
                    **common,
                    "candidate_backend": backend,
                    "baseline_backend": "python",
                    "candidate_vs_python_tps_wall_delta_pct": pct_change(
                        float(candidate_item["tps_wall_mean"]),
                        float(python_item["tps_wall_mean"]),
                    ),
                    "candidate_vs_python_tps_acs_delta_pct": pct_change(
                        float(candidate_item["tps_acs_mean"]),
                        float(python_item["tps_acs_mean"]),
                    ),
                    "candidate_vs_python_tracked_driver_bytes_delta_pct": pct_change(
                        float(candidate_item["tracked_driver_bytes_total_mean"]),
                        float(python_item["tracked_driver_bytes_total_mean"]),
                    ),
                    "candidate_vs_python_bytes_per_tx_delta_pct": pct_change(
                        float(candidate_item["tracked_driver_bytes_per_delivered_tx_mean"]),
                        float(python_item["tracked_driver_bytes_per_delivered_tx_mean"]),
                    ),
                    "python_fetch_requests_sent_total_mean": float(
                        python_item.get("fetch_requests_sent_total_mean", 0.0)
                    ),
                    "candidate_fetch_requests_sent_total_mean": float(
                        candidate_item.get("fetch_requests_sent_total_mean", 0.0)
                    ),
                    "python_fetched_reference_total_mean": float(
                        python_item.get("fetched_reference_total_mean", 0.0)
                    ),
                    "candidate_fetched_reference_total_mean": float(
                        candidate_item.get("fetched_reference_total_mean", 0.0)
                    ),
                }
            )
    return deltas


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    for row in rows[1:]:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _case_label(case: dict[str, object], repeat_index: int) -> str:
    parts = [
        str(case["backend"]),
        _reuse_mode_label(bool(case["reuse_enabled"])).replace("_", "-"),
        f"n{case['nodes']}",
        f"b{case['batch_size']}",
        f"r{case['rounds']}",
        f"g{case['pool_grace_ms']}",
        f"l{case['pool_reuse_limit_per_round']}",
        f"e{case['pool_expire_rounds']}",
        f"m{case['pool_mempool_max']}",
        f"nf{case['network_fault_label']}",
        f"rep{repeat_index}",
    ]
    return "-".join(parts)


def _case_sid(experiment_name: str, case: dict[str, object], repeat_index: int) -> str:
    return (
        f"bench:dumbo:paper:{experiment_name}:"
        f"{case['backend']}:{_reuse_mode_label(bool(case['reuse_enabled']))}:"
        f"n{case['nodes']}:b{case['batch_size']}:nf{case['network_fault_label']}:rep{repeat_index}"
    )


def _config_payload(case: dict[str, object]) -> dict[str, object]:
    return {
        "acs_host_backend": str(case["backend"]),
        "enable_broadcast_pool_reuse": bool(case["reuse_enabled"]),
        "enable_pool_reference_proposals": bool(case["enable_pool_reference_proposals"]),
        "enable_pool_fetch_fallback": bool(case["enable_pool_fetch_fallback"]),
        "pool_grace_ms": int(case["pool_grace_ms"]),
        "pool_reuse_limit_per_round": int(case["pool_reuse_limit_per_round"]),
        "pool_expire_rounds": int(case["pool_expire_rounds"]),
        "pool_mempool_max": int(case["pool_mempool_max"]),
        "network_faults": _network_fault_payload(dict(case["network_faults"])),  # type: ignore[arg-type]
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run reproducible Dumbo paper benchmark suites from a TOML matrix config"
    )
    parser.add_argument("--suite-config", default=str(DEFAULT_SUITE_CONFIG))
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--experiments", default=None)
    parser.add_argument("--all", action="store_true", help="run all experiments in the suite")
    parser.add_argument("--list-experiments", action="store_true")
    parser.add_argument(
        "--dry-run", action="store_true", help="expand cases without executing them"
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        default=None,
        help="optional cap on total executed runs after expansion",
    )
    parser.add_argument("--output-dir", default=None)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    suite_path = Path(args.suite_config)
    if not suite_path.is_file():
        raise FileNotFoundError(f"suite config not found: {suite_path}")

    suite_name, defaults, raw_experiments = _load_suite(suite_path)
    expanded: list[tuple[dict[str, object], list[dict[str, object]]]] = [
        _expand_experiment(experiment, defaults) for experiment in raw_experiments
    ]
    metadata_by_name = {str(metadata["name"]): metadata for metadata, _ in expanded}
    cases_by_name = {str(metadata["name"]): cases for metadata, cases in expanded}

    if args.list_experiments:
        for metadata, _cases in expanded:
            description = str(metadata["description"])
            line = (
                f"{metadata['name']}: cases={metadata['case_count']} runs={metadata['run_count']}"
            )
            if description:
                line += f" | {description}"
            print(line)
        return 0

    selected_names = list(metadata_by_name)
    if args.experiments:
        requested = [item.strip() for item in args.experiments.split(",") if item.strip()]
        if not requested:
            raise ValueError("--experiments must name at least one experiment")
        missing = [name for name in requested if name not in metadata_by_name]
        if missing:
            raise ValueError(f"unknown experiments: {', '.join(sorted(missing))}")
        selected_names = requested
    elif not args.all:
        raise ValueError("select experiments with --experiments or pass --all")

    selected = [(metadata_by_name[name], cases_by_name[name]) for name in selected_names]
    total_runs = sum(int(metadata["repeats"]) * len(cases) for metadata, cases in selected)

    print(
        "[suite]",
        f"name={suite_name}",
        f"experiments={','.join(selected_names)}",
        f"planned_runs={total_runs}",
        flush=True,
    )
    if args.dry_run:
        for metadata, cases in selected:
            print(
                "[experiment]",
                f"name={metadata['name']}",
                f"cases={len(cases)}",
                f"repeats={metadata['repeats']}",
                flush=True,
            )
        return 0

    binary = Path(args.binary)
    if not binary.is_file():
        raise FileNotFoundError(f"benchmark binary not found: {binary}")

    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    runs_executed = 0
    for metadata, cases in selected:
        experiment_name = str(metadata["name"])
        experiment_dir = output_dir / experiment_name
        configs_dir = experiment_dir / "configs"
        raw_dir = experiment_dir / "raw"
        configs_dir.mkdir(parents=True, exist_ok=True)
        raw_dir.mkdir(parents=True, exist_ok=True)

        for case in cases:
            for repeat_index in range(int(metadata["repeats"])):
                if args.max_runs is not None and runs_executed >= args.max_runs:
                    break
                case_label = _case_label(case, repeat_index)
                sid = _case_sid(experiment_name, case, repeat_index)
                config_path = configs_dir / f"{case_label}.toml"
                config_path.write_text(
                    _render_config(
                        sid=sid,
                        nodes=int(case["nodes"]),
                        faulty=int(case["faulty"]),
                        rounds=int(case["rounds"]),
                        batch_size=int(case["batch_size"]),
                        global_timeout=float(case["global_timeout"]),
                        config_payload=_config_payload(case),
                    ),
                    encoding="utf-8",
                )

                started = time.perf_counter()
                result = _run_case(binary, config_path)
                elapsed_seconds = time.perf_counter() - started
                record = _build_run_record(
                    experiment=experiment_name,
                    case=case,
                    repeat_index=repeat_index,
                    elapsed_seconds=elapsed_seconds,
                    result=result,
                )
                records.append(record)
                raw_path = raw_dir / f"{case_label}.json"
                raw_path.write_text(
                    json.dumps(record, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                runs_executed += 1
                print(
                    "[run]",
                    f"experiment={experiment_name}",
                    f"backend={record['backend']}",
                    f"reuse={'on' if record['reuse_enabled'] else 'off'}",
                    f"nodes={record['nodes']}",
                    f"batch={record['batch_size']}",
                    f"repeat={repeat_index}",
                    f"tps_wall={record['tps_wall']:.3f}",
                    f"bytes_per_tx={record['tracked_driver_bytes_per_delivered_tx']:.2f}",
                    f"reused={record['reused_reference_total']}",
                    f"fetched={record['fetched_reference_total']}",
                    flush=True,
                )
            if args.max_runs is not None and runs_executed >= args.max_runs:
                break
        if args.max_runs is not None and runs_executed >= args.max_runs:
            break

    summaries = _aggregate_records(records)
    reuse_deltas = _build_reuse_deltas(summaries)
    backend_deltas = _build_backend_deltas(summaries)

    payload = {
        "suite": suite_name,
        "records": records,
        "summaries": summaries,
        "reuse_deltas": reuse_deltas,
        "backend_deltas": backend_deltas,
    }
    payload_path = output_dir / "dumbo_paper_suite.json"
    payload_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_csv(output_dir / "summaries.csv", summaries)
    _write_csv(output_dir / "reuse_deltas.csv", reuse_deltas)
    _write_csv(output_dir / "backend_deltas.csv", backend_deltas)

    manifest = {
        "created_at": datetime.now(UTC).isoformat(),
        "suite": suite_name,
        "suite_config": str(suite_path.resolve()),
        "binary": str(binary.resolve()),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "argv": sys.argv,
        "selected_experiments": selected_names,
        "planned_runs": total_runs,
        "executed_runs": runs_executed,
        "git": _git_metadata(),
        "json": _display_path(payload_path),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[done] output_dir={_display_path(output_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
