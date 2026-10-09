"""Closed MQL5 renderer for plotted SMA indicators."""

from __future__ import annotations


def render_mql5(
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
    """Render SMA lines into MQL5 indicator buffers without order functions."""
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
        f"// target: MT5 {symbol} {timeframe}",
    ]
    lines.extend(declarations)
    for index in range(count):
        lines.extend(
            (
                f"#property indicator_type{index + 1} DRAW_LINE",
                f'#property indicator_label{index + 1} "SMA {index + 1}"',
                f"double lv_sma_{index}_{suffix}[];",
                f"int lv_handle_{index}_{suffix};",
            )
        )
    lines.append("int OnInit() {")
    for index, period in enumerate(sma_periods):
        buffer = f"lv_sma_{index}_{suffix}"
        handle = f"lv_handle_{index}_{suffix}"
        lines.extend(
            (
                f"  if (!SetIndexBuffer({index}, {buffer}, INDICATOR_DATA)) return INIT_FAILED;",
                f"  ArraySetAsSeries({buffer}, true);",
                (
                    f'  {handle} = iMA("{symbol}", PERIOD_{timeframe}, {period}, '
                    "0, MODE_SMA, PRICE_CLOSE);"
                ),
                f"  if ({handle} == INVALID_HANDLE) return INIT_FAILED;",
            )
        )
    lines.extend(("  return INIT_SUCCEEDED;", "}"))
    lines.extend(("void OnDeinit(const int lv_reason_" + suffix + ") {",))
    for index in range(count):
        lines.append(
            f"  if (lv_handle_{index}_{suffix} != INVALID_HANDLE) "
            f"IndicatorRelease(lv_handle_{index}_{suffix});"
        )
    lines.extend(
        (
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
        )
    )
    for index in range(count):
        copied = f"lv_copied_{index}_{suffix}"
        handle = f"lv_handle_{index}_{suffix}"
        buffer = f"lv_sma_{index}_{suffix}"
        lines.extend(
            (
                f"  int {copied} = CopyBuffer({handle}, 0, 0, lv_rates_total_{suffix}, {buffer});",
                f"  if ({copied} < lv_rates_total_{suffix}) return lv_prev_calculated_{suffix};",
            )
        )
    lines.extend((f"  return lv_rates_total_{suffix};", "}"))
    return "\n".join(lines) + "\n"
