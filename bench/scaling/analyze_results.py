#!/usr/bin/env python3
"""
Benchmark results analyzer for Tero Edge.

Loads res-*.csv files and generates log-scale graphs for:
- Memory usage
- CPU usage
- RPS (requests per second)
- P99 latency
- P50 latency

All graphs include standard deviations across runs.

Setup:
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements-analysis.txt
    python analyze_results.py
"""

import glob
from pathlib import Path
from typing import Callable

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# =============================================================================
# Styling Configuration
# =============================================================================


class PlotStyle:
    """Configuration for plot styling. Modify this class to customize appearance."""

    # Figure settings
    figsize: tuple[int, int] = (12, 8)
    dpi: int = 100

    # Font settings
    title_fontsize: int = 14
    label_fontsize: int = 12
    tick_fontsize: int = 10
    legend_fontsize: int = 10

    # Dark mode colors (Tailwind CSS palette)
    bg_color: str = "#0a0a0a"  # neutral-950
    fg_color: str = "#fafafa"  # neutral-50
    axes_color: str = "#171717"  # neutral-900
    grid_color: str = "#404040"  # neutral-700
    text_color: str = "#d4d4d4"  # neutral-300

    # Color palette for binaries (maximally distinct colors for dark bg)
    binary_colors: dict[str, str] = {
        "edge": "#22c55e",  # green-500 - bright green
        "otelcol": "#f97316",  # orange-500 - orange
        "vector": "#a855f7",  # purple-500 - purple
        "tero-collector": "#06b6d4",  # cyan-500 - cyan
    }

    # Marker styles for binaries
    binary_markers: dict[str, str] = {
        "edge": "o",
        "otelcol": "^",
        "vector": "D",
        "tero-collector": "v",
    }

    # Line styles
    line_width: float = 2.5
    marker_size: int = 10
    error_capsize: int = 5
    error_alpha: float = 0.25

    # Grid settings
    grid_alpha: float = 0.3
    grid_style: str = "-"

    @classmethod
    def get_color(cls, binary: str) -> str:
        """Get color for a binary, with fallback."""
        return cls.binary_colors.get(binary, "#a3a3a3")  # neutral-400

    @classmethod
    def get_marker(cls, binary: str) -> str:
        """Get marker for a binary, with fallback."""
        return cls.binary_markers.get(binary, "o")

    @classmethod
    def apply_style(cls) -> None:
        """Apply global matplotlib style settings with dark mode."""
        plt.rcParams.update(
            {
                # Figure
                "figure.figsize": cls.figsize,
                "figure.dpi": cls.dpi,
                "figure.facecolor": cls.bg_color,
                "figure.edgecolor": cls.bg_color,
                # Axes
                "axes.facecolor": cls.axes_color,
                "axes.edgecolor": cls.grid_color,
                "axes.labelcolor": cls.text_color,
                "axes.titlecolor": cls.fg_color,
                "axes.titlesize": cls.title_fontsize,
                "axes.labelsize": cls.label_fontsize,
                # Ticks
                "xtick.color": cls.text_color,
                "ytick.color": cls.text_color,
                "xtick.labelsize": cls.tick_fontsize,
                "ytick.labelsize": cls.tick_fontsize,
                # Grid
                "grid.color": cls.grid_color,
                "grid.alpha": cls.grid_alpha,
                # Legend
                "legend.fontsize": cls.legend_fontsize,
                "legend.facecolor": cls.axes_color,
                "legend.edgecolor": cls.grid_color,
                "legend.labelcolor": cls.text_color,
                # Text
                "font.size": cls.tick_fontsize,
                "text.color": cls.text_color,
                # Savefig
                "savefig.facecolor": cls.bg_color,
                "savefig.edgecolor": cls.bg_color,
            }
        )


# =============================================================================
# Data Loading
# =============================================================================


def load_results(pattern: str = "results/*.results.csv") -> pd.DataFrame:
    """
    Load all CSV files matching pattern and combine into single DataFrame.

    Adds a 'run' column to identify which file each row came from.
    """
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No files matching pattern: {pattern}")

    dfs = []
    for i, f in enumerate(files, start=1):
        df = pd.read_csv(f)
        df["run"] = i
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)

    # Filter out run 1 (warmup run with systematic variance)
    combined = combined[combined["run"] != 1]

    # Combine edge-otlp and edge-datadog into single "edge" binary
    combined["binary"] = combined["binary"].replace(
        {
            "edge-otlp": "edge",
            "edge-datadog": "edge",
        }
    )

    # # Filter out otelcol/tero-collector DD Logs (20x slower than OTLP, skews aggregations)
    # combined = combined[
    #     ~(
    #         (combined["binary"].isin(["otelcol", "tero-collector"]))
    #         & (combined["telemetry_type"] == "DD Logs")
    #     )
    # ]

    # # Filter out tero-collector OTLP Metrics (10x higher memory, skews aggregations)
    # combined = combined[
    #     ~(
    #         (combined["binary"] == "tero-collector")
    #         & (combined["telemetry_type"] == "OTLP Metrics")
    #     )
    # ]

    # Filter out OTLP Traces entirely
    combined = combined[combined["telemetry_type"] != "OTLP Traces"]

    print(f"Loaded {len(files)} files with {len(combined)} total rows")
    print(f"Binaries: {combined['binary'].unique().tolist()}")
    print(f"Telemetry types: {combined['telemetry_type'].unique().tolist()}")
    print(f"Policy counts: {sorted(combined['policy_count'].unique().tolist())}")

    return combined


def aggregate_by_binary(
    df: pd.DataFrame,
    group_cols: list[str],
    value_col: str,
) -> pd.DataFrame:
    """
    Aggregate data by grouping columns, computing mean and std.

    Returns DataFrame with columns: [group_cols..., 'mean', 'std']
    """
    agg = df.groupby(group_cols)[value_col].agg(["mean", "std"]).reset_index()
    return agg


# =============================================================================
# Plotting Functions
# =============================================================================


def plot_metric_by_policy_count(
    df: pd.DataFrame,
    metric_col: str,
    ylabel: str,
    title: str,
    output_path: str | None = None,
    log_x: bool = True,
    log_y: bool = True,
    telemetry_filter: str | None = None,
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Plot a metric vs policy_count for each binary.

    Args:
        df: DataFrame with benchmark results
        metric_col: Column name for the metric to plot
        ylabel: Y-axis label
        title: Plot title
        output_path: Optional path to save the figure
        log_x: Use log scale for x-axis
        log_y: Use log scale for y-axis
        telemetry_filter: Optional filter for specific telemetry type
        style: Style configuration class

    Returns:
        matplotlib Figure object
    """
    style.apply_style()

    # Filter by telemetry type if specified
    plot_df = df.copy()
    if telemetry_filter:
        plot_df = plot_df[plot_df["telemetry_type"] == telemetry_filter]
        title = f"{title} ({telemetry_filter})"

    # Aggregate across runs
    agg = aggregate_by_binary(plot_df, ["binary", "policy_count"], metric_col)

    fig, ax = plt.subplots()

    for binary in sorted(agg["binary"].unique()):
        binary_data = agg[agg["binary"] == binary].sort_values("policy_count")

        x = binary_data["policy_count"].values
        y = binary_data["mean"].values
        yerr = binary_data["std"].values

        # Handle log scale with zero policy count
        if log_x and 0 in x:
            x = np.where(x == 0, 0.5, x)  # Replace 0 with 0.5 for log scale

        color = style.get_color(binary)
        marker = style.get_marker(binary)

        ax.errorbar(
            x,
            y,
            yerr=yerr,
            label=binary,
            color=color,
            marker=marker,
            markersize=style.marker_size,
            linewidth=style.line_width,
            capsize=style.error_capsize,
            capthick=1,
        )

        # Add shaded error region
        ax.fill_between(
            x,
            y - yerr,
            y + yerr,
            color=color,
            alpha=style.error_alpha,
        )

    if log_x:
        ax.set_xscale("log")
        ax.set_xlabel("Policy Count (log scale, 0 shown as 0.5)")
    else:
        ax.set_xlabel("Policy Count")

    if log_y:
        ax.set_yscale("log")
        ax.set_ylabel(f"{ylabel} (log scale)")
    else:
        ax.set_ylabel(ylabel)

    ax.set_title(title)
    ax.legend(loc="best")
    ax.grid(True, alpha=style.grid_alpha, linestyle=style.grid_style)

    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
        print(f"Saved: {output_path}")

    return fig


def plot_metric_grid_by_telemetry(
    df: pd.DataFrame,
    metric_col: str,
    ylabel: str,
    title: str,
    output_path: str | None = None,
    log_x: bool = True,
    log_y: bool = True,
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Plot a metric vs policy_count with subplots for each telemetry type.

    Each subplot shows all binaries that support that telemetry type.
    """
    style.apply_style()

    telemetry_types = sorted(df["telemetry_type"].unique())
    n_types = len(telemetry_types)

    # Determine grid layout (2x2 grid, stretch to screen)
    ncols = min(2, n_types)
    nrows = (n_types + ncols - 1) // ncols

    fig, axes = plt.subplots(nrows, ncols, figsize=(16, 12))
    if n_types == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    for idx, telemetry in enumerate(telemetry_types):
        ax = axes[idx]
        tel_df = df[df["telemetry_type"] == telemetry]
        agg = aggregate_by_binary(tel_df, ["binary", "policy_count"], metric_col)

        for binary in sorted(agg["binary"].unique()):
            binary_data = agg[agg["binary"] == binary].sort_values("policy_count")

            x = binary_data["policy_count"].values
            y = binary_data["mean"].values
            yerr = binary_data["std"].fillna(0).values

            # Handle log scale with zero policy count
            if log_x and 0 in x:
                x = np.where(x == 0, 0.5, x)

            color = style.get_color(binary)
            marker = style.get_marker(binary)

            ax.errorbar(
                x,
                y,
                yerr=yerr,
                label=binary,
                color=color,
                marker=marker,
                markersize=style.marker_size - 2,
                linewidth=style.line_width - 0.5,
                capsize=style.error_capsize - 1,
                capthick=1,
            )

            ax.fill_between(
                x,
                y - yerr,
                y + yerr,
                color=color,
                alpha=style.error_alpha,
            )

        if log_x:
            ax.set_xscale("log")
        if log_y:
            ax.set_yscale("log")

        ax.set_xlabel("Policy Count")
        ax.set_ylabel(ylabel)
        ax.set_title(telemetry)
        ax.legend(loc="best", fontsize=8)
        ax.grid(True, alpha=style.grid_alpha, linestyle=style.grid_style)

    # Hide unused subplots
    for idx in range(n_types, len(axes)):
        axes[idx].set_visible(False)

    plt.suptitle(title, fontsize=style.title_fontsize + 2)
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    if output_path:
        fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
        print(f"Saved: {output_path}")

    return fig


def plot_all_metrics(
    df: pd.DataFrame,
    output_dir: str = "plots",
    telemetry_filter: str | None = None,
    style: type[PlotStyle] = PlotStyle,
) -> dict[str, plt.Figure]:
    """
    Generate all standard metric plots.

    Args:
        df: DataFrame with benchmark results
        output_dir: Directory to save plots
        telemetry_filter: Optional filter for specific telemetry type
        style: Style configuration class

    Returns:
        Dictionary mapping metric names to Figure objects
    """
    Path(output_dir).mkdir(exist_ok=True)

    suffix = (
        f"_{telemetry_filter.replace(' ', '_').lower()}" if telemetry_filter else ""
    )

    metrics = {
        "mem_mb": ("Memory Usage (MB)", "memory_usage"),
        "cpu_pct": ("CPU Usage (%)", "cpu_usage"),
        "rps": ("Requests Per Second", "rps"),
        "p99_ms": ("P99 Latency (ms)", "p99_latency"),
        "p50_ms": ("P50 Latency (ms)", "p50_latency"),
    }

    figures = {}
    for col, (label, name) in metrics.items():
        fig = plot_metric_by_policy_count(
            df,
            metric_col=col,
            ylabel=label,
            title=f"{label} vs Policy Count",
            output_path=f"{output_dir}/{name}{suffix}.png",
            telemetry_filter=telemetry_filter,
            style=style,
        )
        figures[name] = fig

    return figures


def plot_comparison_grid(
    df: pd.DataFrame,
    output_path: str = "plots/comparison_grid.png",
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Create a grid of all metrics for quick comparison.
    """
    style.apply_style()

    metrics = [
        ("mem_mb", "Memory (MB)"),
        ("cpu_pct", "CPU (%)"),
        ("rps", "RPS"),
        ("p99_ms", "P99 (ms)"),
        ("p50_ms", "P50 (ms)"),
    ]

    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    axes = axes.flatten()

    for idx, (col, label) in enumerate(metrics):
        ax = axes[idx]
        agg = aggregate_by_binary(df, ["binary", "policy_count"], col)

        for binary in sorted(agg["binary"].unique()):
            binary_data = agg[agg["binary"] == binary].sort_values("policy_count")
            x = binary_data["policy_count"].values
            y = binary_data["mean"].values
            yerr = binary_data["std"].values

            # Handle log scale with zero
            x_plot = np.where(x == 0, 0.5, x)

            color = style.get_color(binary)
            marker = style.get_marker(binary)

            ax.errorbar(
                x_plot,
                y,
                yerr=yerr,
                label=binary,
                color=color,
                marker=marker,
                markersize=6,
                linewidth=1.5,
                capsize=3,
            )

        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("Policy Count")
        ax.set_ylabel(label)
        ax.set_title(label)
        ax.grid(True, alpha=0.3, linestyle="--")

    # Hide the 6th subplot (empty)
    axes[5].set_visible(False)

    # Add legend to the empty space
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower right", bbox_to_anchor=(0.95, 0.15))

    plt.suptitle("Benchmark Comparison Grid (Log-Log Scale)", fontsize=16)
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    Path(output_path).parent.mkdir(exist_ok=True)
    fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
    print(f"Saved: {output_path}")

    return fig


def create_summary_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create a summary table with mean values across all policy counts.
    """
    summary = (
        df.groupby("binary")
        .agg(
            {
                "rps": ["mean", "std"],
                "p50_ms": ["mean", "std"],
                "p99_ms": ["mean", "std"],
                "cpu_pct": ["mean", "std"],
                "mem_mb": ["mean", "std"],
            }
        )
        .round(2)
    )

    # Flatten column names
    summary.columns = ["_".join(col).strip() for col in summary.columns.values]

    return summary


# =============================================================================
# Advanced Analysis Functions
# =============================================================================


def plot_winner_matrix(
    df: pd.DataFrame,
    output_path: str = "plots/winner_matrix.png",
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Create a heatmap showing which binary wins each metric for each telemetry type.

    "Wins" means: highest RPS, lowest latency, lowest memory, lowest CPU.
    """
    style.apply_style()

    metrics = {
        "rps": ("RPS", "max"),  # Higher is better
        "p50_ms": ("P50 Latency", "min"),  # Lower is better
        "p99_ms": ("P99 Latency", "min"),  # Lower is better
        "mem_mb": ("Memory", "min"),  # Lower is better
        "cpu_pct": ("CPU", "min"),  # Lower is better
    }

    telemetry_types = sorted(df["telemetry_type"].unique())
    binaries = sorted(df["binary"].unique())

    # Build winner matrix: rows = telemetry types, cols = metrics
    # Values = winning binary name
    winner_data = []

    for telemetry in telemetry_types:
        tel_df = df[df["telemetry_type"] == telemetry]
        row = {"telemetry_type": telemetry}

        for metric_col, (metric_label, agg_type) in metrics.items():
            # Aggregate by binary (mean across policy counts and runs)
            agg = tel_df.groupby("binary")[metric_col].mean()

            if agg_type == "max":
                winner = agg.idxmax()
            else:
                winner = agg.idxmin()

            row[metric_label] = winner

        winner_data.append(row)

    winner_df = pd.DataFrame(winner_data).set_index("telemetry_type")

    # Create numeric matrix for heatmap coloring
    binary_to_num = {b: i for i, b in enumerate(binaries)}
    numeric_matrix = winner_df.replace(binary_to_num).values.astype(float)

    fig, ax = plt.subplots(figsize=(10, 6))

    # Create heatmap with binary colors
    cmap_colors = [style.get_color(b) for b in binaries]
    from matplotlib.colors import ListedColormap

    cmap = ListedColormap(cmap_colors)

    im = ax.imshow(
        numeric_matrix, cmap=cmap, aspect="auto", vmin=0, vmax=len(binaries) - 1
    )

    # Set ticks
    ax.set_xticks(range(len(winner_df.columns)))
    ax.set_xticklabels(winner_df.columns, rotation=45, ha="right")
    ax.set_yticks(range(len(winner_df.index)))
    ax.set_yticklabels(winner_df.index)

    # Add text annotations showing winner names
    for i in range(len(winner_df.index)):
        for j in range(len(winner_df.columns)):
            winner = winner_df.iloc[i, j]
            # Use contrasting text color
            text_color = "#0a0a0a" if winner in ["otelcol", "vector"] else "#fafafa"
            ax.text(
                j,
                i,
                winner,
                ha="center",
                va="center",
                color=text_color,
                fontsize=9,
                fontweight="bold",
            )

    ax.set_title("Winner Matrix: Best Binary per Metric & Telemetry Type")

    # Add legend
    from matplotlib.patches import Patch

    legend_patches = [Patch(facecolor=style.get_color(b), label=b) for b in binaries]
    ax.legend(handles=legend_patches, loc="upper left", bbox_to_anchor=(1.02, 1))

    plt.tight_layout()

    Path(output_path).parent.mkdir(exist_ok=True)
    fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
    print(f"Saved: {output_path}")

    return fig


def plot_crossover_analysis(
    df: pd.DataFrame,
    output_path: str = "plots/crossover_analysis.png",
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Analyze at what policy count one binary overtakes another.

    Shows crossover points for key metrics (RPS, memory).
    """
    style.apply_style()

    telemetry_types = sorted(df["telemetry_type"].unique())
    n_types = len(telemetry_types)

    fig, axes = plt.subplots(n_types, 2, figsize=(14, 4 * n_types))
    if n_types == 1:
        axes = axes.reshape(1, -1)

    metrics = [("rps", "RPS (higher=better)"), ("mem_mb", "Memory MB (lower=better)")]

    for row_idx, telemetry in enumerate(telemetry_types):
        tel_df = df[df["telemetry_type"] == telemetry]

        for col_idx, (metric_col, metric_label) in enumerate(metrics):
            ax = axes[row_idx, col_idx]

            # Aggregate by binary and policy_count
            agg = aggregate_by_binary(tel_df, ["binary", "policy_count"], metric_col)
            binaries = sorted(agg["binary"].unique())

            # Plot each binary
            for binary in binaries:
                binary_data = agg[agg["binary"] == binary].sort_values("policy_count")
                x = binary_data["policy_count"].values
                y = binary_data["mean"].values

                # Handle log scale
                x_plot = np.where(x == 0, 0.5, x)

                color = style.get_color(binary)
                ax.plot(
                    x_plot,
                    y,
                    label=binary,
                    color=color,
                    linewidth=2,
                    marker=style.get_marker(binary),
                    markersize=6,
                )

            # Find and annotate crossover points
            crossovers = _find_crossovers(agg, metric_col)
            for (b1, b2), policy_count, value in crossovers:
                x_cross = policy_count if policy_count > 0 else 0.5
                ax.axvline(
                    x=x_cross, color="#ef4444", linestyle="--", alpha=0.5, linewidth=1
                )
                ax.annotate(
                    f"{b1}↔{b2}\n@{policy_count}",
                    xy=(x_cross, value),
                    xytext=(5, 10),
                    textcoords="offset points",
                    fontsize=7,
                    color="#fca5a5",
                    bbox=dict(
                        boxstyle="round,pad=0.2",
                        facecolor="#1f1f1f",
                        edgecolor="#404040",
                    ),
                )

            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_xlabel("Policy Count")
            ax.set_ylabel(metric_label)
            ax.set_title(f"{telemetry}: {metric_label}")
            ax.grid(True, alpha=0.3)
            ax.legend(loc="best", fontsize=8)

    plt.suptitle("Crossover Analysis: Where Binaries Overtake Each Other", fontsize=14)
    plt.tight_layout(rect=[0, 0, 1, 0.97])

    Path(output_path).parent.mkdir(exist_ok=True)
    fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
    print(f"Saved: {output_path}")

    return fig


def _find_crossovers(
    agg: pd.DataFrame,
    metric_col: str,
) -> list[tuple[tuple[str, str], int, float]]:
    """
    Find policy counts where binaries cross over each other.

    Returns list of ((binary1, binary2), policy_count, value) tuples.
    """
    crossovers = []
    binaries = sorted(agg["binary"].unique())
    policy_counts = sorted(agg["policy_count"].unique())

    # Build matrix: binaries x policy_counts -> mean values
    pivot = agg.pivot(index="policy_count", columns="binary", values="mean")

    # Check each pair of binaries
    for i, b1 in enumerate(binaries):
        for b2 in binaries[i + 1 :]:
            if b1 not in pivot.columns or b2 not in pivot.columns:
                continue

            prev_diff = None
            for pc in policy_counts:
                if pc not in pivot.index:
                    continue
                v1 = pivot.loc[pc, b1]
                v2 = pivot.loc[pc, b2]
                if pd.isna(v1) or pd.isna(v2):
                    continue

                curr_diff = v1 - v2

                # Check for sign change (crossover)
                if prev_diff is not None and prev_diff * curr_diff < 0:
                    crossovers.append(((b1, b2), pc, (v1 + v2) / 2))

                prev_diff = curr_diff

    return crossovers


def plot_scaling_exponents(
    df: pd.DataFrame,
    output_path: str = "plots/scaling_exponents.png",
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Calculate log-log slope (scaling exponent) for each binary.

    Fits power law: metric = a * policy_count^b
    The exponent b tells us:
    - b ≈ 0: O(1) constant - metric stays flat as policies increase
    - b ≈ 1: O(n) linear - metric grows proportionally with policies
    - b > 1: superlinear - metric grows faster than policy count

    For "cost" metrics (memory, CPU, latency): lower slope = better scaling
    For "benefit" metrics (RPS): negative slope = degradation with more policies
    """
    style.apply_style()
    from scipy import stats

    # Metrics with their interpretations
    metrics = {
        "mem_mb": ("Memory Growth", "cost"),
        "cpu_pct": ("CPU Growth", "cost"),
        "p99_ms": ("P99 Latency Growth", "cost"),
        "rps": ("RPS Change", "benefit"),
    }

    telemetry_types = sorted(df["telemetry_type"].unique())
    binaries = sorted(df["binary"].unique())

    # Compute scaling exponents with additional context
    results = []
    for telemetry in telemetry_types:
        tel_df = df[df["telemetry_type"] == telemetry]

        for binary in binaries:
            binary_df = tel_df[tel_df["binary"] == binary]

            for metric_col, (metric_label, metric_type) in metrics.items():
                agg = binary_df.groupby("policy_count")[metric_col].mean().reset_index()

                # Filter out zero policy count for log-log fit
                agg = agg[agg["policy_count"] > 0]

                if len(agg) < 2:
                    continue

                x = np.log10(agg["policy_count"].values)
                y = np.log10(agg[metric_col].values)

                # Filter out -inf from log of zeros
                mask = np.isfinite(x) & np.isfinite(y)
                if mask.sum() < 2:
                    continue

                slope, intercept, r_value, p_value, std_err = stats.linregress(
                    x[mask], y[mask]
                )
                r_squared = r_value**2

                # Calculate actual change ratio (last / first)
                change_ratio = agg[metric_col].iloc[-1] / agg[metric_col].iloc[0]

                results.append(
                    {
                        "telemetry_type": telemetry,
                        "binary": binary,
                        "metric": metric_label,
                        "metric_type": metric_type,
                        "exponent": slope,
                        "r_squared": r_squared,
                        "std_err": std_err,
                        "change_ratio": change_ratio,
                        "start_val": agg[metric_col].iloc[0],
                        "end_val": agg[metric_col].iloc[-1],
                    }
                )

    results_df = pd.DataFrame(results)

    # Create a 2x2 grid for the 4 metrics
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    axes = axes.flatten()

    for idx, (metric_col, (metric_label, metric_type)) in enumerate(metrics.items()):
        ax = axes[idx]
        metric_df = results_df[results_df["metric"] == metric_label]

        if metric_df.empty:
            ax.set_visible(False)
            continue

        # Pivot for grouped bar chart
        pivot = metric_df.pivot(
            index="telemetry_type", columns="binary", values="exponent"
        )
        r2_pivot = metric_df.pivot(
            index="telemetry_type", columns="binary", values="r_squared"
        )

        x = np.arange(len(pivot.index))
        width = 0.8 / len(binaries)

        for i, binary in enumerate(binaries):
            if binary not in pivot.columns:
                continue
            values = pivot[binary].values
            r2_values = r2_pivot[binary].values
            offset = (i - len(binaries) / 2 + 0.5) * width
            bars = ax.bar(
                x + offset, values, width, label=binary, color=style.get_color(binary)
            )

            # Add value labels on bars with R² indicator
            for bar, val, r2 in zip(bars, values, r2_values):
                if not np.isnan(val):
                    # Position label above or below bar depending on sign
                    y_pos = val + 0.02 if val >= 0 else val - 0.06
                    va = "bottom" if val >= 0 else "top"
                    # Dim the label if R² is low (poor fit)
                    alpha = 1.0 if r2 > 0.5 else 0.5
                    label = f"{val:.2f}"
                    if r2 < 0.5:
                        label += "*"  # Mark unreliable fits
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        y_pos,
                        label,
                        ha="center",
                        va=va,
                        fontsize=7,
                        color=style.text_color,
                        alpha=alpha,
                    )

        ax.set_xlabel("Telemetry Type")
        ax.set_ylabel("Scaling Exponent")

        # Add interpretation to title
        if metric_type == "cost":
            subtitle = "lower = better scaling"
        else:
            subtitle = "near 0 = stable; negative = degrades"
        ax.set_title(f"{metric_label} ({subtitle})", fontsize=11)

        ax.set_xticks(x)
        ax.set_xticklabels(pivot.index, rotation=30, ha="right")

        # Reference lines
        ax.axhline(y=0, color="#22c55e", linestyle="-", alpha=0.7, linewidth=1.5)
        ax.axhline(y=1, color="#eab308", linestyle="--", alpha=0.7, linewidth=1.5)

        # Set y-axis limits to show context
        y_min, y_max = ax.get_ylim()
        ax.set_ylim(min(y_min, -0.6), max(y_max, 1.1))

        ax.legend(loc="best", fontsize=7)
        ax.grid(True, alpha=0.3, axis="y")

    plt.suptitle(
        "Scaling Exponents: How Metrics Change with Policy Count (1→4000)\n"
        "green=O(1) constant | yellow=O(n) linear | * = low R², unreliable fit",
        fontsize=13,
    )
    plt.tight_layout(rect=[0, 0, 1, 0.94])

    Path(output_path).parent.mkdir(exist_ok=True)
    fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
    print(f"Saved: {output_path}")

    # Print detailed summary table
    print("\nScaling Exponents Summary (slope | R² | start→end):")
    print("-" * 100)
    for metric_label in results_df["metric"].unique():
        print(f"\n{metric_label}:")
        metric_data = results_df[results_df["metric"] == metric_label]
        for _, row in metric_data.iterrows():
            r2_marker = "" if row["r_squared"] > 0.5 else " (unreliable)"
            print(
                f"  {row['telemetry_type']:15} {row['binary']:15} "
                f"slope={row['exponent']:+.3f} R²={row['r_squared']:.2f}{r2_marker:12} "
                f"| {row['start_val']:.1f} → {row['end_val']:.1f} ({row['change_ratio']:.2f}x)"
            )

    return fig


def plot_box_plots_by_binary(
    df: pd.DataFrame,
    output_path: str = "plots/box_plots.png",
    style: type[PlotStyle] = PlotStyle,
) -> plt.Figure:
    """
    Create box plots showing distribution spread and outliers for each binary.
    """
    style.apply_style()

    metrics = [
        ("rps", "RPS"),
        ("mem_mb", "Memory (MB)"),
        ("cpu_pct", "CPU (%)"),
        ("p99_ms", "P99 Latency (ms)"),
        ("p50_ms", "P50 Latency (ms)"),
    ]

    binaries = sorted(df["binary"].unique())

    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    axes = axes.flatten()

    for idx, (metric_col, metric_label) in enumerate(metrics):
        ax = axes[idx]

        # Prepare data for box plot
        data = [df[df["binary"] == b][metric_col].values for b in binaries]
        colors = [style.get_color(b) for b in binaries]

        bp = ax.boxplot(
            data,
            tick_labels=binaries,
            patch_artist=True,
            medianprops=dict(color="#ffffff", linewidth=2),
            whiskerprops=dict(color=style.grid_color),
            capprops=dict(color=style.grid_color),
            flierprops=dict(
                marker="o", markerfacecolor="#ef4444", markersize=4, alpha=0.6
            ),
        )

        # Color the boxes
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)

        ax.set_ylabel(metric_label)
        ax.set_title(f"{metric_label} Distribution")
        ax.grid(True, alpha=0.3, axis="y")

        # Use log scale for metrics that vary widely
        if metric_col in ["rps", "mem_mb", "p99_ms"]:
            ax.set_yscale("log")

    # Hide the 6th subplot
    axes[5].set_visible(False)

    plt.suptitle("Distribution by Binary (Box Plots)", fontsize=14)
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    Path(output_path).parent.mkdir(exist_ok=True)
    fig.savefig(output_path, dpi=style.dpi, bbox_inches="tight")
    print(f"Saved: {output_path}")

    return fig


# =============================================================================
# Main Entry Point
# =============================================================================


def main():
    """Main entry point for the analysis script."""
    # Load data
    df = load_results("results/*/results.csv")

    # Print summary
    print("\n" + "=" * 60)
    print("Summary Statistics")
    print("=" * 60)
    summary = create_summary_table(df)
    print(summary.to_string())

    # Generate all plots
    print("\n" + "=" * 60)
    print("Generating Plots")
    print("=" * 60)

    Path("plots").mkdir(exist_ok=True)

    # Generate grid plots by telemetry type for each metric
    metrics = {
        "mem_mb": ("Memory Usage (MB)", "memory_usage"),
        "cpu_pct": ("CPU Usage (%)", "cpu_usage"),
        "rps": ("Requests Per Second", "rps"),
        "p99_ms": ("P99 Latency (ms)", "p99_latency"),
        "p50_ms": ("P50 Latency (ms)", "p50_latency"),
    }

    for col, (label, name) in metrics.items():
        plot_metric_grid_by_telemetry(
            df,
            metric_col=col,
            ylabel=label,
            title=f"{label} by Telemetry Type",
            output_path=f"plots/{name}_by_telemetry.png",
        )

    # Generate advanced analysis plots
    print("\n" + "=" * 60)
    print("Generating Advanced Analysis Plots")
    print("=" * 60)

    plot_winner_matrix(df)
    plot_crossover_analysis(df)
    plot_box_plots_by_binary(df)

    print("\nDone! Check the 'plots' directory for output.")

    # Show plots interactively
    try:
        plt.show()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
