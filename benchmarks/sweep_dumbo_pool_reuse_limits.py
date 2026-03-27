from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
for path in (str(REPO_ROOT), str(SRC_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from honey.consensus.dumbo.core import DumboBFT  # noqa: E402
from honey.crypto import ecdsa, pke, sig  # noqa: E402
from honey.support.params import CommonParams, CryptoParams, HBConfig  # noqa: E402
from network.transport import QueueTransport  # noqa: E402


@dataclass(frozen=True)
class Point:
    batch_size: int
    rounds: int
    warmup_rounds: int
    measured_elapsed_seconds: float
    measured_tps: float
    measured_delivery_ratio: float
    measured_delivered_transactions: int
    measured_proposed_transactions: int
    measured_round_latency_p95_ms: float
    reusable_entries_max: int
    consumed_entries_max: int


class RecordingDumbo(DumboBFT):
    pass


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    rank = (percentile / 100.0) * (len(values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(values) - 1)
    weight = rank - lower
    return values[lower] * (1.0 - weight) + values[upper] * weight


async def _run_once(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    rounds: int,
    round_timeout: float,
    pool_reuse: bool,
    pool_limit: int,
    pool_grace_ms: int,
) -> Point:
    coin_pk, coin_sks = sig.generate(num_nodes, faulty + 1)
    proof_pk, proof_sks = sig.generate(num_nodes, num_nodes - faulty)
    enc_pk, enc_sks = pke.generate(num_nodes, faulty + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(num_nodes)

    transports = [QueueTransport() for _ in range(num_nodes)]
    nodes: list[RecordingDumbo] = []
    tx_per_node = batch_size * rounds

    for pid in range(num_nodes):
        common = CommonParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=0)
        crypto = CryptoParams(
            sig_pk=coin_pk,
            sig_sk=coin_sks[pid],
            enc_pk=enc_pk,
            enc_sk=enc_sks[pid],
            ecdsa_pks=ecdsa_pks,
            ecdsa_sk=ecdsa_sks[pid],
            proof_sig_pk=proof_pk,
            proof_sig_sk=proof_sks[pid],
        )
        config = HBConfig(
            batch_size=batch_size,
            max_rounds=rounds,
            round_timeout=round_timeout,
            log_level="ERROR",
            enable_broadcast_pool_reuse=pool_reuse,
            enable_pool_reference_proposals=pool_reuse,
            enable_pool_fetch_fallback=pool_reuse,
            pool_grace_ms=pool_grace_ms,
            pool_reuse_limit_per_round=pool_limit,
        )
        node = RecordingDumbo(common, crypto, transports[pid], config=config)
        for tx_index in range(tx_per_node):
            node.submit_tx(
                f"Dummy TX node-{pid}-tx-{tx_index}",
                track_latency=True,
                submitted_at_ns=time.time_ns(),
            )
        nodes.append(node)

    async def router() -> None:
        while True:
            pending = []
            for pid in range(num_nodes):
                try:
                    while True:
                        outbound = transports[pid].outbound.get_nowait()
                        pending.append((pid, outbound.recipient, outbound.envelope))
                except asyncio.QueueEmpty:
                    pass
            for sender, recipient, envelope in pending:
                transports[recipient].deliver_nowait(sender, envelope)
            await asyncio.sleep(0.0005)

    router_task = asyncio.create_task(router())
    try:
        await asyncio.wait_for(
            asyncio.gather(*(node.run() for node in nodes)),
            timeout=round_timeout * rounds * 2,
        )
    finally:
        router_task.cancel()
        try:
            await router_task
        except asyncio.CancelledError:
            pass

    warmup_rounds = 1 if rounds > 1 else 0
    measured_round_latencies = [
        lat for node in nodes for lat in node.round_latencies[warmup_rounds:]
    ]
    measured_elapsed_seconds = max(
        (sum(node.round_latencies[warmup_rounds:]) for node in nodes), default=0.0
    )
    measured_proposed_transactions = num_nodes * min(
        sum(node.round_proposed_counts[warmup_rounds:]) for node in nodes
    )
    measured_delivered_transactions = min(
        sum(node.round_delivered_counts[warmup_rounds:]) for node in nodes
    )
    measured_delivery_ratio = (
        measured_delivered_transactions / measured_proposed_transactions
        if measured_proposed_transactions
        else 0.0
    )
    measured_tps = (
        measured_delivered_transactions / measured_elapsed_seconds
        if measured_elapsed_seconds
        else 0.0
    )
    reusable_entries_max = max(node.mempool.stats().get("reusable", 0) for node in nodes)
    consumed_entries_max = max(node.mempool.stats().get("consumed", 0) for node in nodes)

    return Point(
        batch_size=batch_size,
        rounds=rounds,
        warmup_rounds=warmup_rounds,
        measured_elapsed_seconds=measured_elapsed_seconds,
        measured_tps=measured_tps,
        measured_delivery_ratio=measured_delivery_ratio,
        measured_delivered_transactions=measured_delivered_transactions,
        measured_proposed_transactions=measured_proposed_transactions,
        measured_round_latency_p95_ms=_percentile(
            sorted(x * 1000.0 for x in measured_round_latencies),
            95,
        ),
        reusable_entries_max=reusable_entries_max,
        consumed_entries_max=consumed_entries_max,
    )


async def _main_async(args: argparse.Namespace) -> dict[str, Any]:
    batches = [int(part.strip()) for part in args.sweep_batches.split(",") if part.strip()]
    reuse_limits = [int(part.strip()) for part in args.reuse_limits.split(",") if part.strip()]
    variants: list[tuple[str, bool, int]] = [("baseline", False, 0)] + [
        (f"pool_reuse_l{limit}", True, limit) for limit in reuse_limits
    ]
    payload: dict[str, Any] = {
        "meta": {
            "num_nodes": args.nodes,
            "faulty": args.faulty,
            "rounds": args.rounds,
            "round_timeout": args.round_timeout,
            "sweep_batches": batches,
            "reuse_limits": reuse_limits,
            "pool_grace_ms": args.pool_grace_ms,
            "mode": "queue_transport_single_process",
        },
        "variants": {},
    }

    for label, pool_reuse, pool_limit in variants:
        points = []
        for batch_size in batches:
            point = await _run_once(
                sid=f"bench:queue:{label}:{args.nodes}:{batch_size}:{int(time.time())}",
                num_nodes=args.nodes,
                faulty=args.faulty,
                batch_size=batch_size,
                rounds=args.rounds,
                round_timeout=args.round_timeout,
                pool_reuse=pool_reuse,
                pool_limit=pool_limit,
                pool_grace_ms=args.pool_grace_ms,
            )
            points.append(asdict(point))
        payload["variants"][label] = {
            "pool_reuse": pool_reuse,
            "pool_reuse_limit_per_round": pool_limit,
            "points": points,
        }

    return payload


def _format_number(value: float) -> str:
    if abs(value) >= 1000:
        return f"{value:,.0f}"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def _build_svg(payload: dict[str, Any]) -> str:
    meta = payload["meta"]
    variants = payload["variants"]
    labels = list(variants)
    color_map = {
        "baseline": "#0f766e",
        "pool_reuse_l1": "#2563eb",
        "pool_reuse_l2": "#d97706",
        "pool_reuse_l4": "#7c3aed",
        "pool_reuse_l8": "#dc2626",
    }
    batches = meta["sweep_batches"]
    x_labels = [str(batch) for batch in batches]
    width = 1420
    height = 1240
    left = 96
    right = width - 40
    top = 136
    panel_gap = 34
    panel_height = 210
    plot_width = right - left
    chart_height = 4 * panel_height + 3 * panel_gap
    bottom = top + chart_height

    def x_positions() -> list[float]:
        if len(x_labels) == 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + idx * step for idx in range(len(x_labels))]

    xs = x_positions()

    def series(metric: str) -> list[dict[str, Any]]:
        output = []
        for label in labels:
            output.append(
                {
                    "label": label,
                    "color": color_map.get(label, "#334155"),
                    "values": [
                        variants[label]["points"][idx][metric] for idx in range(len(batches))
                    ],
                }
            )
        return output

    panels = [
        {"label": "Measured TPS", "series": series("measured_tps"), "ymin": 0.0},
        {
            "label": "Measured Delivery Ratio",
            "series": series("measured_delivery_ratio"),
            "ymin": 0.0,
            "ymax": 1.05,
        },
        {
            "label": "Round Latency P95 (ms)",
            "series": series("measured_round_latency_p95_ms"),
            "ymin": 0.0,
        },
        {
            "label": "Consumed Carry-Over Max",
            "series": series("consumed_entries_max"),
            "ymin": 0.0,
        },
    ]

    lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        f"<rect width='{width}' height='{height}' fill='#f8fafc'/>",
        "<text x='96' y='48' font-size='30' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a' font-weight='700'>Dumbo Pool Reuse Limit Sweep</text>",
        (
            f"<text x='96' y='76' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#475569'>"
            f"N={meta['num_nodes']}, f={meta['faulty']}, rounds={meta['rounds']}, warmup=1, "
            f"queue single-process benchmark, pool_grace_ms={meta['pool_grace_ms']}</text>"
        ),
    ]

    legend_x = left
    legend_y = 104
    for label in labels:
        color = color_map.get(label, "#334155")
        pretty = (
            "baseline" if label == "baseline" else label.replace("pool_reuse_l", "reuse_limit=")
        )
        lines.append(
            f"<line x1='{legend_x}' y1='{legend_y}' x2='{legend_x + 28}' y2='{legend_y}' stroke='{color}' stroke-width='4' stroke-linecap='round'/>"
        )
        lines.append(f"<circle cx='{legend_x + 14}' cy='{legend_y}' r='4.5' fill='{color}'/>")
        lines.append(
            f"<text x='{legend_x + 36}' y='{legend_y + 5}' font-size='13' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(pretty)}</text>"
        )
        legend_x += 180

    for panel_idx, panel in enumerate(panels):
        y0 = top + panel_idx * (panel_height + panel_gap)
        y1 = y0 + panel_height
        flat_values = [float(value) for item in panel["series"] for value in item["values"]]
        ymin = float(panel.get("ymin", min(flat_values) if flat_values else 0.0))
        ymax = float(panel.get("ymax", max(flat_values) if flat_values else 1.0))
        if ymax <= ymin:
            ymax = ymin + 1.0

        lines.append(
            f"<text x='{left}' y='{y0 - 14}' font-size='19' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a' font-weight='600'>{escape(panel['label'])}</text>"
        )
        lines.append(
            f"<rect x='{left}' y='{y0}' width='{plot_width}' height='{panel_height}' fill='white' stroke='#cbd5e1'/>"
        )

        for tick in range(6):
            ratio = tick / 5
            y = y1 - ratio * panel_height
            tick_value = ymin + ratio * (ymax - ymin)
            lines.append(
                f"<line x1='{left}' y1='{y:.1f}' x2='{right}' y2='{y:.1f}' stroke='#e2e8f0' stroke-dasharray='4 4'/>"
            )
            lines.append(
                f"<text x='{left - 12}' y='{y + 5:.1f}' text-anchor='end' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#64748b'>{escape(_format_number(tick_value))}</text>"
            )

        for x, label in zip(xs, x_labels, strict=True):
            lines.append(
                f"<line x1='{x:.1f}' y1='{y0}' x2='{x:.1f}' y2='{y1}' stroke='#f1f5f9' stroke-dasharray='3 6'/>"
            )
            if panel_idx == len(panels) - 1:
                lines.append(
                    f"<text x='{x:.1f}' y='{bottom + 24}' text-anchor='middle' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#64748b'>{escape(label)}</text>"
                )

        def map_y(value: float, y1_: float = y1, ymin_: float = ymin, ymax_: float = ymax) -> float:
            return y1_ - ((value - ymin_) / (ymax_ - ymin_)) * panel_height

        for item in panel["series"]:
            points = " ".join(
                f"{x:.1f},{map_y(float(value)):.1f}"
                for x, value in zip(xs, item["values"], strict=True)
            )
            color = item["color"]
            lines.append(
                f"<polyline points='{points}' fill='none' stroke='{color}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
            )
            for idx, (x, value) in enumerate(zip(xs, item["values"], strict=True)):
                y = map_y(float(value))
                lines.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{color}'/>")
                if idx == len(item["values"]) - 1:
                    lines.append(
                        f"<text x='{x + 8:.1f}' y='{y - 8:.1f}' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(_format_number(float(value)))}</text>"
                    )

    lines.append(
        f"<text x='{left + plot_width / 2:.1f}' y='{bottom + 54}' text-anchor='middle' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a'>Batch size per node per round</text>"
    )
    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Queue benchmark sweep for Dumbo pool reuse limits"
    )
    parser.add_argument("--nodes", type=int, default=10)
    parser.add_argument("--faulty", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--round-timeout", type=float, default=20.0)
    parser.add_argument("--sweep-batches", type=str, default="1,2,4,8,16,32")
    parser.add_argument("--reuse-limits", type=str, default="1,2,4")
    parser.add_argument("--pool-grace-ms", type=int, default=50)
    parser.add_argument("--output-json", type=str, required=True)
    parser.add_argument("--output-svg", type=str, default=None)
    args = parser.parse_args()

    payload = asyncio.run(_main_async(args))
    output_json = Path(args.output_json)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if args.output_svg:
        output_svg = Path(args.output_svg)
        output_svg.parent.mkdir(parents=True, exist_ok=True)
        output_svg.write_text(_build_svg(payload), encoding="utf-8")

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
