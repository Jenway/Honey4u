from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = REPO_ROOT / "native" / "target" / "release" / "honey-node"
DEFAULT_BACKENDS = ("python", "rust_fin")
DEFAULT_REUSE_MODES = (False, True)


def _parse_int_list(raw: str) -> list[int]:
    values = [int(part.strip()) for part in raw.split(",") if part.strip()]
    if not values:
        raise ValueError("expected at least one integer")
    if any(value <= 0 for value in values):
        raise ValueError("values must be positive integers")
    return values


def _parse_backend_list(raw: str) -> list[str]:
    values = [part.strip() for part in raw.split(",") if part.strip()]
    if not values:
        raise ValueError("expected at least one backend")
    unsupported = [value for value in values if value not in {"python", "rust_fin", "rust_dumbo"}]
    if unsupported:
        raise ValueError(f"unsupported backends: {', '.join(sorted(unsupported))}")
    return values


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return REPO_ROOT / "benchmarks" / "results" / f"dumbo-backend-reuse-{stamp}"


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


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
        [str(binary), "bench-driver", "--config", str(config_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise RuntimeError(error_text)
    payload = completed.stdout.strip()
    if not payload:
        raise RuntimeError("bench-driver produced no output")
    return json.loads(payload)


def _build_run_record(
    *,
    backend: str,
    reuse_enabled: bool,
    nodes: int,
    faulty: int,
    rounds: int,
    batch_size: int,
    repeat_index: int,
    elapsed_seconds: float,
    result: dict[str, Any],
) -> dict[str, Any]:
    rounds_data = result.get("rounds", [])
    delivered_total = sum(int(round_data.get("delivered_count", 0)) for round_data in rounds_data)
    wall_total_seconds = sum(
        float(round_data.get("wall_seconds", 0.0)) for round_data in rounds_data
    )
    acs_total_seconds = sum(float(round_data.get("acs_seconds", 0.0)) for round_data in rounds_data)
    reused_reference_total = sum(
        int(round_data.get("reused_reference_count", 0)) for round_data in rounds_data
    )
    fetch_requests_sent_total = sum(
        int(round_data.get("fetch_requests_sent", 0)) for round_data in rounds_data
    )
    fetch_responses_served_total = sum(
        int(round_data.get("fetch_responses_served", 0)) for round_data in rounds_data
    )
    fetch_responses_received_total = sum(
        int(round_data.get("fetch_responses_received", 0)) for round_data in rounds_data
    )
    fetched_reference_total = sum(
        int(round_data.get("fetched_reference_count", 0)) for round_data in rounds_data
    )
    return {
        "backend": backend,
        "reuse_mode": "reuse_on" if reuse_enabled else "reuse_off",
        "reuse_enabled": reuse_enabled,
        "nodes": nodes,
        "faulty": faulty,
        "rounds": rounds,
        "batch_size": batch_size,
        "repeat_index": repeat_index,
        "elapsed_seconds": elapsed_seconds,
        "delivered_total": delivered_total,
        "wall_total_seconds": wall_total_seconds,
        "acs_total_seconds": acs_total_seconds,
        "tps_wall": (delivered_total / wall_total_seconds) if wall_total_seconds else 0.0,
        "tps_acs": (delivered_total / acs_total_seconds) if acs_total_seconds else 0.0,
        "reused_reference_total": reused_reference_total,
        "fetch_requests_sent_total": fetch_requests_sent_total,
        "fetch_responses_served_total": fetch_responses_served_total,
        "fetch_responses_received_total": fetch_responses_received_total,
        "fetched_reference_total": fetched_reference_total,
        "chain_digest": result.get("chain_digest"),
        "result": result,
    }


def _aggregate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = (
            str(record["backend"]),
            str(record["reuse_mode"]),
            int(record["nodes"]),
            int(record["batch_size"]),
        )
        grouped[key].append(record)

    summaries: list[dict[str, Any]] = []
    for (backend, reuse_mode, nodes, batch_size), runs in sorted(grouped.items()):
        summaries.append(
            {
                "backend": backend,
                "reuse_mode": reuse_mode,
                "nodes": nodes,
                "faulty": int(runs[0]["faulty"]),
                "batch_size": batch_size,
                "rounds": int(runs[0]["rounds"]),
                "run_count": len(runs),
                "elapsed_seconds_mean": fmean(float(run["elapsed_seconds"]) for run in runs),
                "delivered_total_mean": fmean(float(run["delivered_total"]) for run in runs),
                "wall_total_seconds_mean": fmean(float(run["wall_total_seconds"]) for run in runs),
                "acs_total_seconds_mean": fmean(float(run["acs_total_seconds"]) for run in runs),
                "tps_wall_mean": fmean(float(run["tps_wall"]) for run in runs),
                "tps_acs_mean": fmean(float(run["tps_acs"]) for run in runs),
                "reused_reference_total_mean": fmean(
                    float(run["reused_reference_total"]) for run in runs
                ),
                "fetch_requests_sent_total_mean": fmean(
                    float(run["fetch_requests_sent_total"]) for run in runs
                ),
                "fetch_responses_served_total_mean": fmean(
                    float(run["fetch_responses_served_total"]) for run in runs
                ),
                "fetch_responses_received_total_mean": fmean(
                    float(run["fetch_responses_received_total"]) for run in runs
                ),
                "fetched_reference_total_mean": fmean(
                    float(run["fetched_reference_total"]) for run in runs
                ),
            }
        )
    return summaries


def _build_reuse_deltas(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = {
        (
            str(item["backend"]),
            int(item["nodes"]),
            int(item["batch_size"]),
            str(item["reuse_mode"]),
        ): item
        for item in summaries
    }
    deltas: list[dict[str, Any]] = []
    keys = sorted(
        {(str(item["backend"]), int(item["nodes"]), int(item["batch_size"])) for item in summaries}
    )
    for backend, nodes, batch_size in keys:
        off = indexed.get((backend, nodes, batch_size, "reuse_off"))
        on = indexed.get((backend, nodes, batch_size, "reuse_on"))
        if off is None or on is None:
            continue

        def pct_change(new_value: float, old_value: float) -> float:
            if old_value == 0.0:
                return 0.0
            return ((new_value / old_value) - 1.0) * 100.0

        deltas.append(
            {
                "backend": backend,
                "nodes": nodes,
                "faulty": int(off["faulty"]),
                "batch_size": batch_size,
                "tps_wall_delta_pct": pct_change(
                    float(on["tps_wall_mean"]), float(off["tps_wall_mean"])
                ),
                "tps_acs_delta_pct": pct_change(
                    float(on["tps_acs_mean"]), float(off["tps_acs_mean"])
                ),
                "wall_total_delta_pct": pct_change(
                    float(on["wall_total_seconds_mean"]), float(off["wall_total_seconds_mean"])
                ),
                "acs_total_delta_pct": pct_change(
                    float(on["acs_total_seconds_mean"]), float(off["acs_total_seconds_mean"])
                ),
                "delivered_total_delta_pct": pct_change(
                    float(on["delivered_total_mean"]), float(off["delivered_total_mean"])
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
    return deltas


def _build_backend_deltas(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = {
        (
            str(item["backend"]),
            str(item["reuse_mode"]),
            int(item["nodes"]),
            int(item["batch_size"]),
        ): item
        for item in summaries
    }
    deltas: list[dict[str, Any]] = []
    keys = sorted(
        {
            (str(item["reuse_mode"]), int(item["nodes"]), int(item["batch_size"]))
            for item in summaries
        }
    )
    for reuse_mode, nodes, batch_size in keys:
        python_item = indexed.get(("python", reuse_mode, nodes, batch_size))
        rust_fin_item = indexed.get(("rust_fin", reuse_mode, nodes, batch_size))
        if python_item is None or rust_fin_item is None:
            continue

        def pct_change(new_value: float, old_value: float) -> float:
            if old_value == 0.0:
                return 0.0
            return ((new_value / old_value) - 1.0) * 100.0

        deltas.append(
            {
                "reuse_mode": reuse_mode,
                "nodes": nodes,
                "batch_size": batch_size,
                "rust_fin_vs_python_tps_wall_delta_pct": pct_change(
                    float(rust_fin_item["tps_wall_mean"]),
                    float(python_item["tps_wall_mean"]),
                ),
                "rust_fin_vs_python_tps_acs_delta_pct": pct_change(
                    float(rust_fin_item["tps_acs_mean"]),
                    float(python_item["tps_acs_mean"]),
                ),
                "rust_fin_vs_python_wall_total_delta_pct": pct_change(
                    float(rust_fin_item["wall_total_seconds_mean"]),
                    float(python_item["wall_total_seconds_mean"]),
                ),
                "rust_fin_vs_python_acs_total_delta_pct": pct_change(
                    float(rust_fin_item["acs_total_seconds_mean"]),
                    float(python_item["acs_total_seconds_mean"]),
                ),
                "python_fetch_requests_sent_total_mean": float(
                    python_item.get("fetch_requests_sent_total_mean", 0.0)
                ),
                "rust_fin_fetch_requests_sent_total_mean": float(
                    rust_fin_item.get("fetch_requests_sent_total_mean", 0.0)
                ),
                "python_fetched_reference_total_mean": float(
                    python_item.get("fetched_reference_total_mean", 0.0)
                ),
                "rust_fin_fetched_reference_total_mean": float(
                    rust_fin_item.get("fetched_reference_total_mean", 0.0)
                ),
            }
        )
    return deltas


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


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run reproducible Dumbo backend-vs-reuse benchmarks"
    )
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--nodes", default="4,8")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--global-timeout", type=float, default=120.0)
    parser.add_argument("--backends", default="python,rust_fin")
    parser.add_argument("--pool-grace-ms", type=int, default=100)
    parser.add_argument("--pool-reuse-limit-per-round", type=int, default=4)
    parser.add_argument("--pool-expire-rounds", type=int, default=10)
    parser.add_argument("--pool-mempool-max", type=int, default=1024)
    parser.add_argument("--output-dir", default=None)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    nodes_list = _parse_int_list(args.nodes)
    backends = _parse_backend_list(args.backends)
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")
    if args.rounds <= 0:
        raise ValueError("--rounds must be > 0")
    if args.repeats <= 0:
        raise ValueError("--repeats must be > 0")
    if args.global_timeout <= 0.0:
        raise ValueError("--global-timeout must be > 0")

    binary = Path(args.binary)
    if not binary.is_file():
        raise FileNotFoundError(f"benchmark binary not found: {binary}")

    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    configs_dir = output_dir / "configs"
    raw_dir = output_dir / "raw"
    configs_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    for backend in backends:
        for nodes in nodes_list:
            faulty = max((nodes - 1) // 3, 0)
            for reuse_enabled in DEFAULT_REUSE_MODES:
                for repeat_index in range(args.repeats):
                    sid = (
                        f"bench:dumbo:{backend}:"
                        f"{'reuse-on' if reuse_enabled else 'reuse-off'}:"
                        f"n{nodes}:b{args.batch_size}:r{repeat_index}"
                    )
                    config_payload: dict[str, object] = {
                        "acs_host_backend": backend,
                        "enable_broadcast_pool_reuse": reuse_enabled,
                        "enable_pool_reference_proposals": True,
                        "enable_pool_fetch_fallback": True,
                        "pool_grace_ms": args.pool_grace_ms,
                        "pool_reuse_limit_per_round": args.pool_reuse_limit_per_round,
                        "pool_expire_rounds": args.pool_expire_rounds,
                        "pool_mempool_max": args.pool_mempool_max,
                    }
                    config_text = _render_config(
                        sid=sid,
                        nodes=nodes,
                        faulty=faulty,
                        rounds=args.rounds,
                        batch_size=args.batch_size,
                        global_timeout=args.global_timeout,
                        config_payload=config_payload,
                    )
                    case_name = (
                        f"{backend}-{'reuse-on' if reuse_enabled else 'reuse-off'}-"
                        f"n{nodes}-b{args.batch_size}-rep{repeat_index}"
                    )
                    config_path = configs_dir / f"{case_name}.toml"
                    config_path.write_text(config_text, encoding="utf-8")

                    started = time.perf_counter()
                    result = _run_case(binary, config_path)
                    elapsed_seconds = time.perf_counter() - started
                    record = _build_run_record(
                        backend=backend,
                        reuse_enabled=reuse_enabled,
                        nodes=nodes,
                        faulty=faulty,
                        rounds=args.rounds,
                        batch_size=args.batch_size,
                        repeat_index=repeat_index,
                        elapsed_seconds=elapsed_seconds,
                        result=result,
                    )
                    records.append(record)
                    raw_path = raw_dir / f"{case_name}.json"
                    raw_path.write_text(
                        json.dumps(record, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    print(
                        "[run]",
                        f"backend={backend}",
                        f"reuse={'on' if reuse_enabled else 'off'}",
                        f"nodes={nodes}",
                        f"repeat={repeat_index}",
                        f"delivered={record['delivered_total']}",
                        f"tps_wall={record['tps_wall']:.3f}",
                        f"reused={record['reused_reference_total']}",
                        f"fetched={record['fetched_reference_total']}",
                        flush=True,
                    )

    summaries = _aggregate_records(records)
    reuse_deltas = _build_reuse_deltas(summaries)
    backend_deltas = _build_backend_deltas(summaries)

    payload = {
        "records": records,
        "summaries": summaries,
        "reuse_deltas": reuse_deltas,
        "backend_deltas": backend_deltas,
    }
    payload_path = output_dir / "dumbo_backend_reuse_compare.json"
    payload_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    manifest = {
        "created_at": datetime.now(UTC).isoformat(),
        "binary": str(binary.resolve()),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "argv": sys.argv,
        "parameters": {
            "nodes": nodes_list,
            "batch_size": args.batch_size,
            "rounds": args.rounds,
            "repeats": args.repeats,
            "global_timeout": args.global_timeout,
            "backends": backends,
            "pool_grace_ms": args.pool_grace_ms,
            "pool_reuse_limit_per_round": args.pool_reuse_limit_per_round,
            "pool_expire_rounds": args.pool_expire_rounds,
            "pool_mempool_max": args.pool_mempool_max,
        },
        "git": _git_metadata(),
        "json": _display_path(payload_path),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[done] output_dir={_display_path(output_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
