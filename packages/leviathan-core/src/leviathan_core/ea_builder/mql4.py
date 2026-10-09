"""Closed MQL4 renderer for plotted SMA indicators."""

from __future__ import annotations


def render_mql4(
    *,
    build_id: str,
    strategy_hash: str,
    graph_hash: str,
    params_hash: str,
    template_hash: str,
    catalog_digest: str,
    git_commit: str,
    symbol: str,
    timeframe: str,
    declarations: tuple[str, ...],
    sma_periods: tuple[str, ...],
) -> str:
    """Render SMA lines into MQL4 indicator buffers without order functions."""
    suffix = build_id[:12]
    count = len(sma_periods)
    lines = [
        "#property strict",
        '#property version "1.00"',
        "#property indicator_chart_window",
        f"#property indicator_buffers {count}",
        f"#property indicator_plots {count}",
        "// LEVIATHAN SOURCE ONLY; uncompiled, unsigned, and never export-ready.",
        f"// build_id: {build_id}",
        f"// strategy_hash: {strategy_hash}",
        f"// graph_hash: {graph_hash}",
        f"// params_hash: {params_hash}",
        f"// template_hash: {template_hash}",
        f"// catalog_digest: {catalog_digest}",
        f"// git_commit: {git_commit}",
        f"// target: MT4 {symbol} {timeframe}",
    ]
    lines.extend(declarations)
    for index in range(count):
        lines.extend(
            (
                f"#property indicator_type{index + 1} DRAW_LINE",
                f"#property indicator_color{index + 1} clrDodgerBlue",
                f'#property indicator_label{index + 1} "SMA {index + 1}"',
                f"double lv_sma_{index}_{suffix}[];",
            )
        )
    lines.append("int OnInit() {")
    for index in range(count):
        buffer = f"lv_sma_{index}_{suffix}"
        lines.extend(
            (
                f"  if (!SetIndexBuffer({index}, {buffer})) return INIT_FAILED;",
                f"  SetIndexStyle({index}, DRAW_LINE);",
                f'  SetIndexLabel({index}, "SMA {index + 1}");',
                f"  ArraySetAsSeries({buffer}, true);",
            )
        )
    lines.extend(
        (
            "  return INIT_SUCCEEDED;",
            "}",
            "int OnCalculate(const int lv_rates_total_" + suffix + ",",
            "                const int lv_prev_calculated_" + suffix + ",",
            "                const datetime &lv_time_" + suffix + "[],",
            "                const double &lv_open_" + suffix + "[],",
            "                const double &lv_high_" + suffix + "[],",
            "                const double &lv_low_" + suffix + "[],",
            "                const double &lv_close_" + suffix + "[],",
            "                const long &lv_tick_volume_" + suffix + "[],",
            "                const long &lv_volume_" + suffix + "[],",
            "                const int &lv_spread_" + suffix + "[]) {",
            "  if (lv_rates_total_" + suffix + " <= 0) return 0;",
            "  ArraySetAsSeries(lv_close_" + suffix + ", true);",
        )
    )
    for index, period in enumerate(sma_periods):
        buffer = f"lv_sma_{index}_{suffix}"
        limit = f"lv_limit_{index}_{suffix}"
        bar = f"lv_bar_{index}_{suffix}"
        lines.extend(
            (
                f"  int {limit} = lv_rates_total_{suffix} - lv_prev_calculated_{suffix};",
                f"  if (lv_prev_calculated_{suffix} == 0) {limit} = lv_rates_total_{suffix};",
                f"  for (int {bar} = 0; {bar} < {limit}; {bar}++) {{",
                f"    if ({bar} + {period} <= lv_rates_total_{suffix}) {{",
                (
                    f'      {buffer}[{bar}] = iMA("{symbol}", PERIOD_{timeframe}, '
                    f"{period}, 0, MODE_SMA, PRICE_CLOSE, {bar});"
                ),
                "    } else {",
                f"      {buffer}[{bar}] = EMPTY_VALUE;",
                "    }",
                "  }",
            )
        )
    lines.extend((f"  return lv_rates_total_{suffix};", "}"))
    return "\n".join(lines) + "\n"
