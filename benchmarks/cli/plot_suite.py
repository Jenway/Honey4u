#!/usr/bin/env python3
"""
plot_suite.py — Generate SVG charts from a honey-bench suite result.

Reads dumbo_paper_suite.json (written by `honey-bench suite`) and produces
SVG files in a plots/ subdirectory.  Zero external dependencies (stdlib only).

Usage:
    python benchmarks/cli/plot_suite.py --results-dir benchmarks/results/smoke-...
    python benchmarks/cli/plot_suite.py --json path/to/dumbo_paper_suite.json
    python benchmarks/cli/plot_suite.py --results-dir ... --experiments smoke_reuse_scale
    python benchmarks/cli/plot_suite.py --results-dir ... --skip-png
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

# ---------------------------------------------------------------------------
# Color palette — consistent across all charts
# ---------------------------------------------------------------------------

_SERIES_COLORS: dict[tuple[str, str], str] = {
    ("python", "reuse_off"): "#0f766e",
    ("python", "reuse_on"): "#c2410c",
    ("rust_fin", "reuse_off"): "#1d4ed8",
    ("rust_fin", "reuse_on"): "#7c3aed",
    ("rust_dumbo", "reuse_off"): "#065f46",
    ("rust_dumbo", "reuse_on"): "#d97706",
}
_FALLBACK_COLORS = ["#0ea5e9", "#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#f97316", "#ec4899"]


def _series_color(backend: str, reuse_mode: str, fallback_idx: int = 0) -> str:
    return _SERIES_COLORS.get(
        (backend, reuse_mode),
        _FALLBACK_COLORS[fallback_idx % len(_FALLBACK_COLORS)],
    )


# ---------------------------------------------------------------------------
# Number formatting
# ---------------------------------------------------------------------------


def _fmt(v: float) -> str:
    """Format a plain number compactly."""
    if abs(v) >= 10_000:
        return f"{v:,.0f}"
    if abs(v) >= 100:
        return f"{v:.0f}"
    if abs(v) >= 10:
        return f"{v:.1f}"
    return f"{v:.2f}"


def _fmt_pct(v: float) -> str:
    """Format a percentage with explicit sign."""
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.1f}%"


# ---------------------------------------------------------------------------
# SVG line chart  (multi-panel, one panel per grouping key, one line per series)
# Adapted from benchmarks/cli/dumbo_reuse_sweep.py
# ---------------------------------------------------------------------------


def _split_segments(
    xs: list[float],
    values: list[float | None],
    *,
    y0: float,
    height: float,
    ymin: float,
    ymax: float,
) -> tuple[list[str], list[tuple[float, float, float]]]:
    """Split value series into SVG polyline segments, skipping None gaps."""

    def map_y(v: float) -> float:
        return y0 + height - ((v - ymin) / (ymax - ymin)) * height

    segments: list[str] = []
    points: list[tuple[float, float, float]] = []
    current: list[tuple[float, float]] = []

    for x, value in zip(xs, values, strict=True):
        if value is None:
            if len(current) >= 2:
                segments.append(" ".join(f"{px:.1f},{py:.1f}" for px, py in current))
            current = []
        else:
            y = map_y(value)
            current.append((x, y))
            points.append((x, y, value))

    if len(current) >= 2:
        segments.append(" ".join(f"{px:.1f},{py:.1f}" for px, py in current))

    return segments, points


def build_svg_line_chart(
    *,
    title: str,
    subtitle: str,
    # panels: list of {label, series: [{label, color, values: [float|None]}]}
    panels: list[dict[str, Any]],
    x_labels: list[str],
    y_label: str,
    x_axis_label: str = "",
    width: int = 1480,
    height_per_panel: int = 220,
) -> str:
    left = 96
    right = width - 40
    top = 122
    panel_gap = 36
    plot_width = right - left
    n_panels = len(panels)
    total_height = top + n_panels * height_per_panel + max(0, n_panels - 1) * panel_gap + 72

    def x_positions() -> list[float]:
        if len(x_labels) <= 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + step * i for i in range(len(x_labels))]

    xs = x_positions()

    # Collect series labels in order of first appearance (for legend)
    seen: dict[str, str] = {}
    for panel in panels:
        for s in panel.get("series", []):
            if s["label"] not in seen:
                seen[s["label"]] = s["color"]

    lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{total_height}' "
        f"viewBox='0 0 {width} {total_height}'>",
        f"<rect width='{width}' height='{total_height}' fill='#f8fafc'/>",
        f"<text x='{left}' y='40' font-size='26' font-weight='700' "
        f"font-family='Segoe UI,Arial,sans-serif' fill='#0f172a'>{escape(title)}</text>",
        f"<text x='{left}' y='64' font-size='12' "
        f"font-family='Segoe UI,Arial,sans-serif' fill='#64748b'>{escape(subtitle)}</text>",
    ]

    # Legend
    lx = left
    ly = 96
    for label, color in seen.items():
        lines += [
            f"<line x1='{lx}' y1='{ly}' x2='{lx + 24}' y2='{ly}' stroke='{color}' "
            f"stroke-width='3.5' stroke-linecap='round'/>",
            f"<circle cx='{lx + 12}' cy='{ly}' r='4' fill='{color}'/>",
            f"<text x='{lx + 32}' y='{ly + 5}' font-size='12' "
            f"font-family='Segoe UI,Arial,sans-serif' fill='#1e293b'>{escape(label)}</text>",
        ]
        lx += max(130, len(label) * 8 + 44)

    # Y-axis label (rotated)
    mid_y = top + n_panels * (height_per_panel + panel_gap) // 2
    lines.append(
        f"<text x='14' y='{mid_y}' font-size='12' "
        f"font-family='Segoe UI,Arial,sans-serif' fill='#475569' "
        f"transform='rotate(-90 14 {mid_y})'>{escape(y_label)}</text>"
    )

    for pi, panel in enumerate(panels):
        y0 = top + pi * (height_per_panel + panel_gap)
        y1 = y0 + height_per_panel

        all_vals = [
            float(v) for s in panel.get("series", []) for v in s.get("values", []) if v is not None
        ]
        ymin = 0.0
        ymax = max(all_vals) * 1.1 if all_vals else 1.0
        if ymax <= ymin:
            ymax = ymin + 1.0

        lines.append(
            f"<text x='{left}' y='{y0 - 10}' font-size='16' font-weight='600' "
            f"font-family='Segoe UI,Arial,sans-serif' fill='#0f172a'>"
            f"{escape(panel.get('label', ''))}</text>"
        )

        # Horizontal grid lines + y-axis tick labels
        for tick in range(5):
            frac = tick / 4.0
            tick_y = y0 + height_per_panel * (1.0 - frac)
            tick_v = ymin + frac * (ymax - ymin)
            lines += [
                f"<line x1='{left}' y1='{tick_y:.1f}' x2='{right}' y2='{tick_y:.1f}' "
                f"stroke='#e2e8f0' stroke-width='1'/>",
                f"<text x='{left - 6}' y='{tick_y + 4:.1f}' font-size='10' text-anchor='end' "
                f"font-family='Segoe UI,Arial,sans-serif' fill='#94a3b8'>{_fmt(tick_v)}</text>",
            ]

        # X axis line
        lines.append(
            f"<line x1='{left}' y1='{y1}' x2='{right}' y2='{y1}' "
            f"stroke='#94a3b8' stroke-width='1.5'/>"
        )

        # X tick marks and labels
        for x, lbl in zip(xs, x_labels, strict=True):
            lines += [
                f"<line x1='{x:.1f}' y1='{y1}' x2='{x:.1f}' y2='{y1 + 5}' "
                f"stroke='#94a3b8' stroke-width='1.5'/>",
                f"<text x='{x:.1f}' y='{y1 + 17}' font-size='11' text-anchor='middle' "
                f"font-family='Segoe UI,Arial,sans-serif' fill='#64748b'>{escape(lbl)}</text>",
            ]

        # Series lines and dots
        for s in panel.get("series", []):
            color = s["color"]
            segs, pts = _split_segments(
                xs,
                s.get("values", []),
                y0=y0,
                height=height_per_panel,
                ymin=ymin,
                ymax=ymax,
            )
            for seg in segs:
                lines.append(
                    f"<polyline points='{seg}' fill='none' stroke='{color}' "
                    f"stroke-width='2.5' stroke-linejoin='round' stroke-linecap='round'/>"
                )
            for px, py, pv in pts:
                lines.append(
                    f"<circle cx='{px:.1f}' cy='{py:.1f}' r='4' fill='{color}'>"
                    f"<title>{escape(s['label'])}: {_fmt(pv)}</title></circle>"
                )

    # X-axis label below last panel
    if x_axis_label:
        lines.append(
            f"<text x='{(left + right) / 2:.0f}' y='{total_height - 14}' font-size='12' "
            f"text-anchor='middle' font-family='Segoe UI,Arial,sans-serif' fill='#475569'>"
            f"{escape(x_axis_label)}</text>"
        )

    lines.append("</svg>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SVG bar chart  (vertical bars, for delta/condition comparisons)
# ---------------------------------------------------------------------------


def build_svg_bar_chart(
    *,
    title: str,
    subtitle: str,
    # bars: list of {label, value, color}
    bars: list[dict[str, Any]],
    y_label: str,
    width: int = 1480,
    pct_labels: bool = True,
    force_ymin_zero: bool = False,
) -> str:
    if not bars:
        return ""

    left = 80
    right = width - 32
    top = 100
    bottom_margin = 120  # room for rotated x-axis labels
    plot_width = right - left

    values = [float(b["value"]) for b in bars]
    ymax_raw = max(max(values), 0.0)
    ymin_raw = 0.0 if force_ymin_zero else min(min(values), 0.0)
    y_range = (ymax_raw - ymin_raw) or 1.0
    ymax = ymax_raw + y_range * 0.14
    ymin = ymin_raw - y_range * 0.05 if ymin_raw < 0 else 0.0

    plot_height = max(200, 18 * len(bars))
    total_height = top + plot_height + bottom_margin

    def map_y(v: float) -> float:
        return top + plot_height - ((v - ymin) / (ymax - ymin)) * plot_height

    zero_y = map_y(0.0)
    bar_count = len(bars)
    bar_spacing = plot_width / bar_count
    bar_w = min(bar_spacing * 0.68, 52.0)

    lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{total_height}' "
        f"viewBox='0 0 {width} {total_height}'>",
        f"<rect width='{width}' height='{total_height}' fill='#f8fafc'/>",
        f"<text x='{left}' y='36' font-size='24' font-weight='700' "
        f"font-family='Segoe UI,Arial,sans-serif' fill='#0f172a'>{escape(title)}</text>",
        f"<text x='{left}' y='58' font-size='12' "
        f"font-family='Segoe UI,Arial,sans-serif' fill='#64748b'>{escape(subtitle)}</text>",
        # Y-axis label
        f"<text x='12' y='{top + plot_height // 2}' font-size='12' "
        f"font-family='Segoe UI,Arial,sans-serif' fill='#475569' "
        f"transform='rotate(-90 12 {top + plot_height // 2})'>{escape(y_label)}</text>",
    ]

    # Y grid lines + tick labels
    for tick in range(6):
        frac = tick / 5.0
        tick_v = ymin + frac * (ymax - ymin)
        tick_y = map_y(tick_v)
        lines += [
            f"<line x1='{left}' y1='{tick_y:.1f}' x2='{right}' y2='{tick_y:.1f}' "
            f"stroke='#e2e8f0' stroke-width='1'/>",
            f"<text x='{left - 5}' y='{tick_y + 4:.1f}' font-size='10' text-anchor='end' "
            f"font-family='Segoe UI,Arial,sans-serif' fill='#94a3b8'>"
            f"{_fmt(tick_v)}</text>",
        ]

    # Zero baseline (only when chart spans positive and negative)
    if ymin < 0 and ymax > 0:
        lines.append(
            f"<line x1='{left}' y1='{zero_y:.1f}' x2='{right}' y2='{zero_y:.1f}' "
            f"stroke='#94a3b8' stroke-width='1.5'/>"
        )

    # Bars
    for i, bar in enumerate(bars):
        bx = left + i * bar_spacing + bar_spacing / 2
        bv = float(bar["value"])
        color = bar.get("color", "#1d4ed8")
        by_top = map_y(bv)
        bar_h = abs(zero_y - by_top)
        bar_y = min(by_top, zero_y)

        lines.append(
            f"<rect x='{bx - bar_w / 2:.1f}' y='{bar_y:.1f}' width='{bar_w:.1f}' "
            f"height='{max(bar_h, 1.0):.1f}' fill='{color}' rx='3'/>"
        )

        # Value label above/below bar
        val_label = _fmt_pct(bv) if pct_labels else _fmt(bv)
        label_y = by_top - 5 if bv >= 0 else by_top + 13
        lines.append(
            f"<text x='{bx:.1f}' y='{label_y:.1f}' font-size='10' text-anchor='middle' "
            f"font-family='Segoe UI,Arial,sans-serif' fill='#1e293b' font-weight='600'>"
            f"{escape(val_label)}</text>"
        )

        # X-axis label (rotated 45°)
        lbl_text = escape(str(bar.get("label", "")))
        lbl_y = top + plot_height + 8
        lines.append(
            f"<text x='{bx:.1f}' y='{lbl_y}' font-size='10' text-anchor='end' "
            f"font-family='Segoe UI,Arial,sans-serif' fill='#475569' "
            f"transform='rotate(-45 {bx:.1f} {lbl_y})'>{lbl_text}</text>"
        )

    lines.append("</svg>")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PNG conversion (best-effort via rsvg-convert)
# ---------------------------------------------------------------------------


def _try_to_png(svg_path: Path) -> None:
    try:
        subprocess.run(
            ["rsvg-convert", "-p", "150", "-o", str(svg_path.with_suffix(".png")), str(svg_path)],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError, subprocess.CalledProcessError:
        pass


# ---------------------------------------------------------------------------
# Chart generation helpers
# ---------------------------------------------------------------------------


def _write_svg(path: Path, content: str, *, skip_png: bool) -> None:
    if not content:
        return
    path.write_text(content, encoding="utf-8")
    print(f"[plot] {path}")
    if not skip_png:
        _try_to_png(path)


# Keys that can serve as the x-axis for a line chart, in priority order.
_SWEEP_X_KEYS = (
    "batch_size",
    "pool_grace_ms",
    "pool_reuse_limit_per_round",
    "pool_expire_rounds",
    "pool_mempool_max",
)


def _detect_x_key(rows: list[dict]) -> str:
    """Return the field that varies most across rows."""
    for key in _SWEEP_X_KEYS:
        vals = {r.get(key) for r in rows if r.get(key) is not None}
        if len(vals) > 1:
            return key
    return "batch_size"


def _series_label(backend: str, reuse_mode: str) -> str:
    reuse = "reuse on" if reuse_mode == "reuse_on" else "reuse off"
    return f"{backend} ({reuse})"


# ---------------------------------------------------------------------------
# Per-experiment chart: line chart (TPS or bytes vs sweep dimension)
# ---------------------------------------------------------------------------


def _make_line_chart(
    summaries: list[dict],
    experiment: str,
    metric: str,
    metric_label: str,
    output_path: Path,
    *,
    skip_png: bool,
) -> None:
    rows = [
        s
        for s in summaries
        if s.get("experiment") == experiment
        and s.get("network_fault_label", "none") in ("none", "", None)
        and s.get("byzantine_label", "none") in ("none", "", None)
    ]
    if not rows:
        return

    x_key = _detect_x_key(rows)

    # Collect sorted unique x values (numeric sort when possible)
    raw_x = sorted(
        {r.get(x_key) for r in rows if r.get(x_key) is not None},
        key=lambda v: float(v) if isinstance(v, (int, float)) else str(v),
    )
    x_labels = [str(v) for v in raw_x]
    x_index: dict[Any, int] = {v: i for i, v in enumerate(raw_x)}

    node_counts = sorted({int(r.get("nodes", 0)) for r in rows})
    series_keys = sorted({(str(r.get("backend", "")), str(r.get("reuse_mode", ""))) for r in rows})

    panels = []
    for nodes in node_counts:
        series_list = []
        for ci, (backend, reuse_mode) in enumerate(series_keys):
            row_index: dict[int, float] = {
                x_index[r[x_key]]: float(r[metric])
                for r in rows
                if int(r.get("nodes", 0)) == nodes
                and r.get("backend") == backend
                and r.get("reuse_mode") == reuse_mode
                and r.get(x_key) in x_index
                and r.get(metric) is not None
            }
            values: list[float | None] = [row_index.get(i) for i in range(len(x_labels))]
            if any(v is not None for v in values):
                series_list.append(
                    {
                        "label": _series_label(backend, reuse_mode),
                        "color": _series_color(backend, reuse_mode, ci),
                        "values": values,
                    }
                )
        if series_list:
            panels.append({"label": f"N = {nodes}", "series": series_list})

    if not panels:
        return

    svg = build_svg_line_chart(
        title=f"{experiment} — {metric_label}",
        subtitle=f"x-axis: {x_key}",
        panels=panels,
        x_labels=x_labels,
        y_label=metric_label,
        x_axis_label=x_key,
    )
    _write_svg(output_path, svg, skip_png=skip_png)


# ---------------------------------------------------------------------------
# Fault / byzantine experiment chart: bar chart (TPS per condition)
# ---------------------------------------------------------------------------


def _make_condition_bar_chart(
    summaries: list[dict],
    experiment: str,
    output_path: Path,
    *,
    skip_png: bool,
) -> None:
    rows = [s for s in summaries if s.get("experiment") == experiment]
    if not rows:
        return

    def _sort_key(r: dict) -> tuple:
        return (
            r.get("network_fault_label") or r.get("byzantine_label") or "",
            r.get("reuse_mode", ""),
            r.get("backend", ""),
        )

    bars = []
    for ci, r in enumerate(sorted(rows, key=_sort_key)):
        fault = r.get("network_fault_label") or r.get("byzantine_label") or "baseline"
        reuse = "on" if r.get("reuse_mode") == "reuse_on" else "off"
        label = f"{fault} | reuse={reuse}"
        backend = str(r.get("backend", "rust_fin"))
        val = r.get("tps_wall_mean")
        if val is not None:
            bars.append(
                {
                    "label": label,
                    "value": float(val),
                    "color": _series_color(backend, str(r.get("reuse_mode", "")), ci),
                }
            )

    if not bars:
        return

    svg = build_svg_bar_chart(
        title=f"{experiment} — TPS by Condition",
        subtitle="tps_wall_mean per (fault / byzantine condition, reuse mode)",
        bars=bars,
        y_label="TPS (wall clock)",
        pct_labels=False,
        force_ymin_zero=True,
    )
    _write_svg(output_path, svg, skip_png=skip_png)


# ---------------------------------------------------------------------------
# Delta charts (from aggregated reuse_deltas / backend_deltas)
# ---------------------------------------------------------------------------


def _make_reuse_delta_chart(
    reuse_deltas: list[dict],
    suite_name: str,
    output_path: Path,
    *,
    skip_png: bool,
) -> None:
    if not reuse_deltas:
        return

    bars = []
    for ci, r in enumerate(
        sorted(
            reuse_deltas,
            key=lambda r: (
                r.get("experiment", ""),
                r.get("backend", ""),
                int(r.get("nodes", 0)),
                int(r.get("batch_size", 0)),
            ),
        )
    ):
        backend = str(r.get("backend", ""))
        exp = r.get("experiment", "?")
        label = f"{exp} | {backend} N={r.get('nodes')} B={r.get('batch_size')}"
        val = r.get("tps_wall_delta_pct")
        if val is not None:
            bars.append(
                {
                    "label": label,
                    "value": float(val),
                    "color": _series_color(backend, "reuse_on", ci),
                }
            )

    svg = build_svg_bar_chart(
        title=f"{suite_name} — Reuse Δ TPS (reuse_on vs reuse_off)",
        subtitle="Positive = reuse_on improves wall-clock TPS",
        bars=bars,
        y_label="TPS Δ %",
        pct_labels=True,
    )
    _write_svg(output_path, svg, skip_png=skip_png)


def _make_backend_delta_chart(
    backend_deltas: list[dict],
    suite_name: str,
    output_path: Path,
    *,
    skip_png: bool,
) -> None:
    if not backend_deltas:
        return

    bars = []
    for ci, r in enumerate(
        sorted(
            backend_deltas,
            key=lambda r: (
                r.get("experiment", ""),
                r.get("candidate_backend", ""),
                r.get("reuse_mode", ""),
                int(r.get("nodes", 0)),
                int(r.get("batch_size", 0)),
            ),
        )
    ):
        candidate = str(r.get("candidate_backend", ""))
        reuse = str(r.get("reuse_mode", ""))
        exp = r.get("experiment", "?")
        label = f"{exp} | {candidate} N={r.get('nodes')} B={r.get('batch_size')} {reuse}"
        val = r.get("candidate_vs_python_tps_wall_delta_pct")
        if val is not None:
            bars.append(
                {
                    "label": label,
                    "value": float(val),
                    "color": _series_color(candidate, reuse, ci),
                }
            )

    svg = build_svg_bar_chart(
        title=f"{suite_name} — Backend Δ TPS (vs python baseline)",
        subtitle="Positive = candidate backend is faster than python",
        bars=bars,
        y_label="TPS Δ % vs python",
        pct_labels=True,
    )
    _write_svg(output_path, svg, skip_png=skip_png)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate SVG charts from a honey-bench suite result."
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument(
        "--results-dir",
        metavar="DIR",
        help="Results directory containing dumbo_paper_suite.json",
    )
    grp.add_argument(
        "--json",
        dest="json_path",
        metavar="FILE",
        help="Direct path to dumbo_paper_suite.json",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default=None,
        help="Where to write SVG files (default: <results-dir>/plots/)",
    )
    parser.add_argument(
        "--experiments",
        metavar="LIST",
        default=None,
        help="Comma-separated experiment names to plot (default: all)",
    )
    parser.add_argument(
        "--skip-png",
        action="store_true",
        help="Emit only SVG; skip rsvg-convert PNG conversion",
    )
    args = parser.parse_args()

    # Resolve input path
    if args.json_path:
        json_path = Path(args.json_path)
        results_dir = json_path.parent
    else:
        results_dir = Path(args.results_dir)
        json_path = results_dir / "dumbo_paper_suite.json"

    if not json_path.exists():
        print(f"error: {json_path} not found", flush=True)
        return 1

    data: dict[str, Any] = json.loads(json_path.read_text(encoding="utf-8"))
    summaries: list[dict] = data.get("summaries", [])
    reuse_deltas: list[dict] = data.get("reuse_deltas", [])
    backend_deltas: list[dict] = data.get("backend_deltas", [])
    suite_name: str = data.get("suite", "suite")

    output_dir = Path(args.output_dir) if args.output_dir else results_dir / "plots"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Optional experiment filter
    if args.experiments:
        selected = set(args.experiments.split(","))
        summaries = [s for s in summaries if s.get("experiment") in selected]
        reuse_deltas = [d for d in reuse_deltas if d.get("experiment") in selected]
        backend_deltas = [d for d in backend_deltas if d.get("experiment") in selected]

    # Discover which experiments are present
    all_experiments = sorted({s.get("experiment", "") for s in summaries} - {""})

    skip_png: bool = args.skip_png

    # Per-experiment charts
    for exp in all_experiments:
        exp_rows = [s for s in summaries if s.get("experiment") == exp]
        has_faults = any(
            s.get("network_fault_label", "none") not in ("none", "", None)
            or s.get("byzantine_label", "none") not in ("none", "", None)
            for s in exp_rows
        )

        if has_faults:
            _make_condition_bar_chart(
                summaries,
                exp,
                output_dir / f"{exp}_tps_by_condition.svg",
                skip_png=skip_png,
            )
        else:
            _make_line_chart(
                summaries,
                exp,
                metric="tps_wall_mean",
                metric_label="TPS (wall clock)",
                output_path=output_dir / f"{exp}_tps.svg",
                skip_png=skip_png,
            )
            _make_line_chart(
                summaries,
                exp,
                metric="tracked_driver_bytes_per_delivered_tx_mean",
                metric_label="Bytes per delivered tx",
                output_path=output_dir / f"{exp}_bytes_per_tx.svg",
                skip_png=skip_png,
            )

    # Cross-experiment delta charts
    _make_reuse_delta_chart(
        reuse_deltas,
        suite_name,
        output_dir / "reuse_delta_tps.svg",
        skip_png=skip_png,
    )
    _make_backend_delta_chart(
        backend_deltas,
        suite_name,
        output_dir / "backend_delta_tps.svg",
        skip_png=skip_png,
    )

    charts_written = len(list(output_dir.glob("*.svg")))
    print(f"[done] {charts_written} SVG chart(s) written to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
