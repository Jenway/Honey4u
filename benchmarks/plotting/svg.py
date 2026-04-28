"""Shared SVG chart rendering extracted from `benchmarks/cli/tps.py`
and `benchmarks/cli/dumbo_reuse_sweep.py`.

After the benchmark logic migration to Rust, this module is the
only Python-side concern: turning structured JSON summaries into
publication-quality SVG charts.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

# ---------------------------------------------------------------------------
# Formatter (was duplicated in tps.py and dumbo_reuse_sweep.py)
# ---------------------------------------------------------------------------


def format_number(value: float) -> str:
    if abs(value) >= 1000.0:
        return f"{value:,.0f}"
    if abs(value) >= 100.0:
        return f"{value:.0f}"
    if abs(value) >= 10.0:
        return f"{value:.1f}"
    return f"{value:.2f}"


# ---------------------------------------------------------------------------
# Common constants for reuse on/off charts
# ---------------------------------------------------------------------------

MODE_ORDER: tuple[str, ...] = ("reuse_off", "reuse_on")
MODE_LABELS: dict[str, str] = {
    "reuse_off": "Reuse Off",
    "reuse_on": "Reuse On",
}
MODE_COLORS: dict[str, str] = {
    "reuse_off": "#0f766e",
    "reuse_on": "#c2410c",
}


def round_ms(value_seconds: float) -> float:
    return value_seconds * 1000.0


# ---------------------------------------------------------------------------
# Single-batch line chart (from tps.py `_build_svg_line_chart`)
# ---------------------------------------------------------------------------


def build_svg_line_chart(
    *,
    title: str,
    subtitle: str,
    x_labels: list[str],
    panels: list[dict[str, Any]],
    width: int = 1280,
    height: int = 980,
) -> str:
    left = 90
    right = width - 40
    top = 90
    panel_gap = 30
    panel_height = 180
    plot_width = right - left
    chart_height = len(panels) * panel_height + (len(panels) - 1) * panel_gap
    bottom = top + chart_height

    def x_positions() -> list[float]:
        if len(x_labels) == 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + step * idx for idx in range(len(x_labels))]

    xs = x_positions()
    lines: list[str] = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        f"<rect width='{width}' height='{height}' fill='#f7f4ea'/>",
        f"<text x='{left}' y='42' font-size='28' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937' font-weight='700'>{escape(title)}</text>",
        f"<text x='{left}' y='68' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#6b7280'>{escape(subtitle)}</text>",
    ]

    for panel_idx, panel in enumerate(panels):
        y0 = top + panel_idx * (panel_height + panel_gap)
        y1 = y0 + panel_height
        values = [float(value) for value in panel["values"]]
        ymin = float(panel.get("ymin", min(values) if values else 0.0))
        ymax = float(panel.get("ymax", max(values) if values else 1.0))
        if ymax <= ymin:
            ymax = ymin + 1.0

        lines.append(
            f"<text x='{left}' y='{y0 - 12}' font-size='18' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937' font-weight='600'>{escape(panel['label'])}</text>"
        )
        lines.append(
            f"<rect x='{left}' y='{y0}' width='{plot_width}' height='{panel_height}' fill='white' stroke='#d6d3d1'/>"
        )

        for tick in range(6):
            ratio = tick / 5
            y = y1 - ratio * panel_height
            tick_value = ymin + ratio * (ymax - ymin)
            lines.append(
                f"<line x1='{left}' y1='{y:.1f}' x2='{right}' y2='{y:.1f}' stroke='#d6d3d1' stroke-dasharray='4 4'/>"
            )
            lines.append(
                f"<text x='{left - 12}' y='{y + 5:.1f}' text-anchor='end' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#6b7280'>{escape(format_number(tick_value))}</text>"
            )

        for x, label in zip(xs, x_labels, strict=True):
            lines.append(
                f"<line x1='{x:.1f}' y1='{y0}' x2='{x:.1f}' y2='{y1}' stroke='#e7e5e4' stroke-dasharray='3 6'/>"
            )
            if panel_idx == len(panels) - 1:
                lines.append(
                    f"<text x='{x:.1f}' y='{bottom + 24}' text-anchor='middle' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#6b7280'>{escape(label)}</text>"
                )

        def _map_y(
            value: float,
            *,
            _y1: float = y1,
            _ymin: float = ymin,
            _ymax: float = ymax,
        ) -> float:
            return _y1 - ((value - _ymin) / (_ymax - _ymin)) * panel_height

        points = " ".join(
            f"{x:.1f},{_map_y(value):.1f}" for x, value in zip(xs, values, strict=True)
        )
        color = str(panel["color"])
        lines.append(
            f"<polyline points='{points}' fill='none' stroke='{color}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
        )
        for idx, (x, value) in enumerate(zip(xs, values, strict=True)):
            y = _map_y(value)
            lines.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{color}'/>")
            if idx == len(values) - 1:
                lines.append(
                    f"<text x='{x + 8:.1f}' y='{y - 8:.1f}' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937'>{escape(format_number(value))}</text>"
                )

    lines.append(
        f"<text x='{left + plot_width / 2:.1f}' y='{bottom + 52}' text-anchor='middle' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937'>Batch size per node per round</text>"
    )
    lines.append("</svg>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Multi-node comparison chart (from dumbo_reuse_sweep.py `_build_svg_chart`)
# ---------------------------------------------------------------------------


def collect_series(
    summaries: list[dict[str, Any]],
    *,
    nodes: int,
    batches: list[int],
    metric_key: str,
) -> list[dict[str, Any]]:
    indexed = {
        (int(item["nodes"]), int(item["batch_size"]), str(item["mode"])): item for item in summaries
    }
    series: list[dict[str, Any]] = []
    for mode in MODE_ORDER:
        values: list[float | None] = []
        for batch_size in batches:
            item = indexed.get((nodes, batch_size, mode))
            values.append(float(item[metric_key]) if item is not None else None)
        series.append(
            {
                "label": MODE_LABELS[mode],
                "color": MODE_COLORS[mode],
                "values": values,
            }
        )
    return series


def _split_segments(
    xs: list[float],
    values: list[float | None],
    *,
    y0: float,
    height: float,
    ymin: float,
    ymax: float,
) -> tuple[list[str], list[tuple[float, float, float, str]]]:
    def map_y(value: float) -> float:
        return y0 + height - ((value - ymin) / (ymax - ymin)) * height

    segments: list[str] = []
    points: list[tuple[float, float, float, str]] = []
    current: list[tuple[float, float]] = []

    for x, value in zip(xs, values, strict=True):
        if value is None:
            if len(current) >= 2:
                segments.append(" ".join(f"{px:.1f},{py:.1f}" for px, py in current))
            current = []
            continue
        y = map_y(float(value))
        current.append((x, y))
        points.append((x, y, float(value), f"{float(value):.6f}"))

    if len(current) >= 2:
        segments.append(" ".join(f"{px:.1f},{py:.1f}" for px, py in current))

    return segments, points


def build_comparison_svg_chart(
    *,
    title: str,
    subtitle: str,
    node_panels: list[dict[str, Any]],
    x_labels: list[str],
    output_metric_label: str,
    width: int = 1480,
    height_per_panel: int = 220,
) -> str:
    left = 96
    right = width - 40
    top = 118
    panel_gap = 40
    plot_width = right - left
    panel_height = height_per_panel
    height = top + len(node_panels) * panel_height + max(0, len(node_panels) - 1) * panel_gap + 88
    bottom = height - 68

    def x_positions() -> list[float]:
        if len(x_labels) == 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + step * idx for idx in range(len(x_labels))]

    xs = x_positions()
    lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        f"<rect width='{width}' height='{height}' fill='#f8fafc'/>",
        f"<text x='{left}' y='46' font-size='30' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a' font-weight='700'>{escape(title)}</text>",
        f"<text x='{left}' y='74' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#475569'>{escape(subtitle)}</text>",
    ]

    legend_x = left
    legend_y = 98
    for mode in MODE_ORDER:
        color = MODE_COLORS[mode]
        label = MODE_LABELS[mode]
        lines.append(
            f"<line x1='{legend_x}' y1='{legend_y}' x2='{legend_x + 28}' y2='{legend_y}' stroke='{color}' stroke-width='4' stroke-linecap='round'/>"
        )
        lines.append(f"<circle cx='{legend_x + 14}' cy='{legend_y}' r='4.5' fill='{color}'/>")
        lines.append(
            f"<text x='{legend_x + 38}' y='{legend_y + 5}' font-size='13' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(label)}</text>"
        )
        legend_x += 150

    lines.append(
        f"<text x='{width - 42}' y='98' text-anchor='end' font-size='13' font-family='Segoe UI, Arial, sans-serif' fill='#475569'>{escape(output_metric_label)}</text>"
    )

    for panel_index, panel in enumerate(node_panels):
        y0 = top + panel_index * (panel_height + panel_gap)
        y1 = y0 + panel_height
        flat_values = [
            float(value)
            for series in panel["series"]
            for value in series["values"]
            if value is not None
        ]
        ymin = float(panel.get("ymin", 0.0))
        ymax = float(panel.get("ymax", max(flat_values) if flat_values else 1.0))
        if ymax <= ymin:
            ymax = ymin + 1.0
        if ymax > ymin:
            ymax = ymax * 1.08

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
                f"<text x='{left - 12}' y='{y + 5:.1f}' text-anchor='end' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#64748b'>{escape(format_number(tick_value))}</text>"
            )

        for x, label in zip(xs, x_labels, strict=True):
            lines.append(
                f"<line x1='{x:.1f}' y1='{y0}' x2='{x:.1f}' y2='{y1}' stroke='#f1f5f9' stroke-dasharray='3 6'/>"
            )
            if panel_index == len(node_panels) - 1:
                lines.append(
                    f"<text x='{x:.1f}' y='{bottom + 20}' text-anchor='middle' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#64748b'>{escape(label)}</text>"
                )

        for series in panel["series"]:
            segments, points = _split_segments(
                xs,
                list(series["values"]),
                y0=y0,
                height=panel_height,
                ymin=ymin,
                ymax=ymax,
            )
            for segment in segments:
                lines.append(
                    f"<polyline points='{segment}' fill='none' stroke='{series['color']}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
                )
            for x, y, _value, _ in points:
                lines.append(
                    f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{series['color']}'/>"
                )
            if points:
                x, y, value, _ = points[-1]
                lines.append(
                    f"<text x='{x + 8:.1f}' y='{y - 8:.1f}' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(format_number(value))}</text>"
                )

    lines.append(
        f"<text x='{left + plot_width / 2:.1f}' y='{bottom + 48}' text-anchor='middle' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a'>Batch size per node per round</text>"
    )
    lines.append("</svg>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SVG → PNG conversion
# ---------------------------------------------------------------------------


def render_png(svg_path: Path) -> Path | None:
    png_path = svg_path.with_suffix(".png")
    try:
        subprocess.run(
            ["rsvg-convert", "-o", str(png_path), str(svg_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except OSError, subprocess.CalledProcessError:
        return None
    return png_path
