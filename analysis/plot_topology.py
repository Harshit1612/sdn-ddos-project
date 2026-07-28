#!/usr/bin/env python3
"""
analysis/plot_topology.py

Draws the SDN testbed topology diagram: Ryu controller -> s1 (root) ->
s2, s3 (leaves) -> 6 hosts each. Matches topology/topo.py exactly.

Run:
    python3 analysis/plot_topology.py
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from matplotlib.lines import Line2D

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "plots", "figure0_topology.png")


def draw_box(ax, x, y, w, h, text, color, fontsize=10, fontweight="bold"):
    box = FancyBboxPatch((x - w/2, y - h/2), w, h,
                          boxstyle="round,pad=0.02,rounding_size=0.05",
                          facecolor=color, edgecolor="black", linewidth=1.2, zorder=3)
    ax.add_patch(box)
    ax.text(x, y, text, ha="center", va="center", fontsize=fontsize,
             fontweight=fontweight, zorder=4)


def main():
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 8)
    ax.axis("off")

    ax.set_title("SDN Testbed Topology -- 3 Switches (Tree), 12 Hosts\nMatches proposal Section 3.2, Step 1",
                 fontsize=13, fontweight="bold")

    # controller
    draw_box(ax, 6, 7, 2.6, 0.7, "Ryu Controller", "#8B7FD6", fontsize=11)

    # s1 root
    draw_box(ax, 6, 5.6, 2.0, 0.7, "S1 (root)", "#6FCF97", fontsize=11)

    # s2, s3 leaves
    draw_box(ax, 3, 4.2, 2.0, 0.7, "S2 (leaf)", "#6FCF97", fontsize=11)
    draw_box(ax, 9, 4.2, 2.0, 0.7, "S3 (leaf)", "#6FCF97", fontsize=11)

    # control plane links (dashed, controller -> switches)
    for sx, sy in [(6, 5.6), (3, 4.2), (9, 4.2)]:
        ax.add_line(Line2D([6, sx], [6.65, sy + 0.35], color="#9B9BE0",
                            linestyle="--", linewidth=1, zorder=1))

    # data plane links: s1 -> s2, s1 -> s3
    ax.add_line(Line2D([6, 3], [5.25, 4.55], color="#2E7D46", linewidth=2, zorder=1))
    ax.add_line(Line2D([6, 9], [5.25, 4.55], color="#2E7D46", linewidth=2, zorder=1))

    # hosts under s2 (h1-h6) and s3 (h7-h12)
    host_y = 2.2
    host_w, host_h = 0.85, 0.55
    s2_host_xs = [1, 1.9, 2.8, 3.2, 4.1, 5.0]
    s3_host_xs = [7, 7.9, 8.8, 9.2, 10.1, 11.0]

    for i, x in enumerate(s2_host_xs, start=1):
        draw_box(ax, x, host_y, host_w, host_h, f"h{i}", "#D9D9D9", fontsize=9, fontweight="normal")
        ax.add_line(Line2D([3, x], [3.85, host_y + 0.28], color="black", linewidth=0.8, zorder=1))

    for i, x in enumerate(s3_host_xs, start=7):
        draw_box(ax, x, host_y, host_w, host_h, f"h{i}", "#D9D9D9", fontsize=9, fontweight="normal")
        ax.add_line(Line2D([9, x], [3.85, host_y + 0.28], color="black", linewidth=0.8, zorder=1))

    # legend
    legend_elements = [
        Line2D([0], [0], color="#9B9BE0", linestyle="--", lw=1.5, label="Control plane (OpenFlow: packet-in / flow-mod)"),
        Line2D([0], [0], color="#2E7D46", lw=2, label="Data plane (root-to-leaf switch link)"),
        Line2D([0], [0], color="black", lw=1, label="Data plane (leaf-to-host link)"),
    ]
    ax.legend(handles=legend_elements, loc="lower center", fontsize=8, ncol=1, frameon=False)

    fig.tight_layout()
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    plt.savefig(OUT_PATH, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
