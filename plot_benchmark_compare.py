from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


def _format_number(value: float) -> str:
    if abs(value) >= 1000:
        return f"{value:,.0f}"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def _load_payload(path_str: str) -> dict[str, Any]:
    return json.loads(Path(path_str).read_text(encoding="utf-8"))


def _index_points(payload: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(point["batch_size"]): point for point in payload["points"]}


def _build_svg(
    *,
    title: str,
    subtitle: str,
    x_labels: list[str],
    panels: list[dict[str, Any]],
    legend: list[dict[str, str]],
    width: int = 1360,
    height: int = 1120,
) -> str:
    left = 90
    right = width - 40
    top = 120
    panel_gap = 36
    panel_height = 220
    plot_width = right - left
    chart_height = len(panels) * panel_height + (len(panels) - 1) * panel_gap
    bottom = top + chart_height

    def x_positions() -> list[float]:
        if len(x_labels) == 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + idx * step for idx in range(len(x_labels))]

    xs = x_positions()
    lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        f"<rect width='{width}' height='{height}' fill='#f8fafc'/>",
        f"<text x='{left}' y='46' font-size='30' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a' font-weight='700'>{escape(title)}</text>",
        f"<text x='{left}' y='74' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#475569'>{escape(subtitle)}</text>",
    ]

    legend_x = left
    legend_y = 98
    for item in legend:
        lines.append(
            f"<line x1='{legend_x}' y1='{legend_y}' x2='{legend_x + 28}' y2='{legend_y}' stroke='{item['color']}' stroke-width='4' stroke-linecap='round'/>"
        )
        lines.append(
            f"<circle cx='{legend_x + 14}' cy='{legend_y}' r='4.5' fill='{item['color']}'/>"
        )
        lines.append(
            f"<text x='{legend_x + 36}' y='{legend_y + 5}' font-size='13' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(item['label'])}</text>"
        )
        legend_x += 160

    for panel_idx, panel in enumerate(panels):
        y0 = top + panel_idx * (panel_height + panel_gap)
        y1 = y0 + panel_height
        flat_values = [float(value) for series in panel["series"] for value in series["values"]]
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

        def map_y(value: float) -> float:
            return y1 - ((value - ymin) / (ymax - ymin)) * panel_height  # noqa B023

        for series in panel["series"]:
            points = " ".join(
                f"{x:.1f},{map_y(float(value)):.1f}"
                for x, value in zip(xs, series["values"], strict=True)
            )
            color = series["color"]
            lines.append(
                f"<polyline points='{points}' fill='none' stroke='{color}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
            )
            for idx, (x, value) in enumerate(zip(xs, series["values"], strict=True)):
                y = map_y(float(value))
                lines.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{color}'/>")
                if idx == len(series["values"]) - 1:
                    lines.append(
                        f"<text x='{x + 8:.1f}' y='{y - 8:.1f}' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(_format_number(float(value)))}</text>"
                    )

    lines.append(
        f"<text x='{left + plot_width / 2:.1f}' y='{bottom + 54}' text-anchor='middle' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a'>Batch size per node per round</text>"
    )
    lines.append("</svg>")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot a two-protocol benchmark comparison SVG")
    parser.add_argument("--baseline-json", required=True, help="path to baseline sweep json")
    parser.add_argument("--candidate-json", required=True, help="path to candidate sweep json")
    parser.add_argument("--baseline-label", default="HoneyBadger")
    parser.add_argument("--candidate-label", default="Dumbo")
    parser.add_argument("--output", required=True, help="output svg path")
    parser.add_argument("--title", default="Protocol benchmark comparison")
    args = parser.parse_args()

    baseline = _load_payload(args.baseline_json)
    candidate = _load_payload(args.candidate_json)
    baseline_points = _index_points(baseline)
    candidate_points = _index_points(candidate)
    batches = sorted(set(baseline_points) & set(candidate_points))
    if not batches:
        raise SystemExit("no overlapping batch sizes found between input sweeps")

    x_labels = [str(batch) for batch in batches]
    num_nodes = baseline["meta"]["num_nodes"]
    faulty = baseline["meta"]["faulty"]
    rounds = baseline["meta"]["rounds"]
    warmup = baseline["meta"]["warmup_rounds"]
    baseline_color = "#0f766e"
    candidate_color = "#7c3aed"

    panels = [
        {
            "label": "Measured TPS",
            "series": [
                {
                    "label": args.baseline_label,
                    "color": baseline_color,
                    "values": [baseline_points[batch]["measured_tps"] for batch in batches],
                },
                {
                    "label": args.candidate_label,
                    "color": candidate_color,
                    "values": [candidate_points[batch]["measured_tps"] for batch in batches],
                },
            ],
            "ymin": 0.0,
        },
        {
            "label": "Measured Delivery Ratio",
            "series": [
                {
                    "label": args.baseline_label,
                    "color": baseline_color,
                    "values": [
                        baseline_points[batch]["measured_delivery_ratio"] for batch in batches
                    ],
                },
                {
                    "label": args.candidate_label,
                    "color": candidate_color,
                    "values": [
                        candidate_points[batch]["measured_delivery_ratio"] for batch in batches
                    ],
                },
            ],
            "ymin": 0.0,
            "ymax": 1.05,
        },
        {
            "label": "Measured Tx Latency P95 (ms)",
            "series": [
                {
                    "label": args.baseline_label,
                    "color": baseline_color,
                    "values": [
                        baseline_points[batch]["measured_tx_latency"]["p95_ms"] for batch in batches
                    ],
                },
                {
                    "label": args.candidate_label,
                    "color": candidate_color,
                    "values": [
                        candidate_points[batch]["measured_tx_latency"]["p95_ms"]
                        for batch in batches
                    ],
                },
            ],
            "ymin": 0.0,
        },
        {
            "label": "Raw Inbound Queue Peak",
            "series": [
                {
                    "label": args.baseline_label,
                    "color": baseline_color,
                    "values": [
                        baseline_points[batch]["queue_backlog"]["raw_inbound_messages"]["max"]
                        for batch in batches
                    ],
                },
                {
                    "label": args.candidate_label,
                    "color": candidate_color,
                    "values": [
                        candidate_points[batch]["queue_backlog"]["raw_inbound_messages"]["max"]
                        for batch in batches
                    ],
                },
            ],
            "ymin": 0.0,
        },
    ]

    svg = _build_svg(
        title=args.title,
        subtitle=(
            f"N={num_nodes}, f={faulty}, rounds={rounds}, warmup={warmup}, "
            f"local socket transport, x-axis=batch size"
        ),
        x_labels=x_labels,
        panels=panels,
        legend=[
            {"label": args.baseline_label, "color": baseline_color},
            {"label": args.candidate_label, "color": candidate_color},
        ],
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(svg, encoding="utf-8")
    print(output_path)


if __name__ == "__main__":
    main()
