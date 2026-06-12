"""Shared matplotlib visualizations for the toolkit."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path


def password_strength_chart(score: int, label: str, breakdown: list[dict], output: str = "password_strength.png") -> str:
    """Generate a password strength visualization."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), facecolor="#0d1117")

    # Gauge chart
    ax = axes[0]
    ax.set_facecolor("#0d1117")
    colors_map = {"Very Weak": "#f85149", "Weak": "#d29922", "Fair": "#d29922",
                  "Strong": "#3fb950", "Very Strong": "#3fb950"}
    color = colors_map.get(label, "#8b949e")
    ax.barh([0], [score], height=0.5, color=color, alpha=0.8)
    ax.barh([0], [100 - score], left=[score], height=0.5, color="#21262d")
    ax.set_xlim(0, 100)
    ax.set_yticks([])
    ax.set_xlabel("Score", color="#c9d1d9")
    ax.set_title(f"{label} — {score}/100", color="#c9d1d9", fontsize=16, fontweight="bold")
    ax.tick_params(colors="#8b949e")
    for spine in ax.spines.values():
        spine.set_color("#30363d")

    # Breakdown bar chart
    ax2 = axes[1]
    ax2.set_facecolor("#0d1117")
    factors = [b["factor"] for b in breakdown]
    points = [b["points"] for b in breakdown]
    bar_colors = ["#3fb950" if p > 0 else "#f85149" for p in points]
    ax2.barh(factors, points, color=bar_colors, alpha=0.8)
    ax2.set_xlabel("Points", color="#c9d1d9")
    ax2.set_title("Score Breakdown", color="#c9d1d9", fontsize=14)
    ax2.tick_params(colors="#8b949e")
    for spine in ax2.spines.values():
        spine.set_color("#30363d")

    plt.tight_layout()
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close(fig)
    return output


def handshake_flow_diagram(stages: list[dict], output: str = "handshake_flow.png") -> str:
    """Visualize the WPA 4-way handshake packet flow."""
    fig, ax = plt.subplots(figsize=(10, 8), facecolor="#0d1117")
    ax.set_facecolor("#0d1117")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis("off")

    # Draw AP and Client columns
    ax.text(2, 11.2, "Access Point", ha="center", fontsize=13, fontweight="bold", color="#58a6ff")
    ax.text(8, 11.2, "Client", ha="center", fontsize=13, fontweight="bold", color="#58a6ff")
    ax.plot([2, 2], [0.5, 11], color="#30363d", linewidth=2, linestyle="--")
    ax.plot([8, 8], [0.5, 11], color="#30363d", linewidth=2, linestyle="--")

    y_positions = [9.5, 7.5, 5.5, 3.5]
    for stage in stages:
        num = stage["stage"]
        captured = stage.get("captured", False)
        y = y_positions[num - 1]
        color = "#3fb950" if captured else "#f8514980"

        if num in (1, 3):  # AP → Client
            ax.annotate("", xy=(7.8, y), xytext=(2.2, y),
                        arrowprops=dict(arrowstyle="->", color=color, lw=2))
            ax.text(5, y + 0.3, stage["title"].split(":")[0], ha="center", fontsize=9,
                    color=color, fontweight="bold")
            ax.text(5, y - 0.3, stage["summary"][:50], ha="center", fontsize=7, color="#8b949e")
        else:  # Client → AP
            ax.annotate("", xy=(2.2, y), xytext=(7.8, y),
                        arrowprops=dict(arrowstyle="->", color=color, lw=2))
            ax.text(5, y + 0.3, stage["title"].split(":")[0], ha="center", fontsize=9,
                    color=color, fontweight="bold")
            ax.text(5, y - 0.3, stage["summary"][:50], ha="center", fontsize=7, color="#8b949e")

    captured_patch = mpatches.Patch(color="#3fb950", label="Captured")
    missing_patch = mpatches.Patch(color="#f8514980", label="Missing")
    ax.legend(handles=[captured_patch, missing_patch], loc="lower center",
              facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")

    ax.set_title("WPA 4-Way Handshake", color="#c9d1d9", fontsize=15, fontweight="bold", pad=20)
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close(fig)
    return output
