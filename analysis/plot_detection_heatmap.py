#!/usr/bin/env python3
"""
analysis/plot_detection_heatmap.py

Generates Figure 8: detection rate heatmap by intensity x poll interval,
one panel per attack type (SYN / UDP).

Run:
    python3 analysis/plot_detection_heatmap.py
"""
import csv
import os
import statistics
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

SUMMARY_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "experiment_summary.csv")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "plots", "fig8_detection_heatmap.png")


def main():
    with open(SUMMARY_PATH) as f:
        rows = list(csv.DictReader(f))

    groups = defaultdict(list)
    for r in rows:
        key = (r["attack_type"], r["intensity"], int(r["poll_interval"]))
        groups[key].append(float(r["detection_rate_pct"]))

    atypes = ["syn", "udp"]
    intensities = ["low", "medium", "high"]
    polls = [1, 2, 5]

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    for ai, at in enumerate(atypes):
        matrix = np.zeros((len(intensities), len(polls)))
        for ii, intensity in enumerate(intensities):
            for pi, poll in enumerate(polls):
                vals = groups.get((at, intensity, poll), [0])
                matrix[ii][pi] = statistics.mean(vals)

        ax = axes[ai]
        im = ax.imshow(matrix, cmap="RdYlGn", aspect="auto", vmin=70, vmax=100)
        plt.colorbar(im, ax=ax, label="Detection Rate (%)")

        for ii in range(len(intensities)):
            for pi in range(len(polls)):
                ax.text(pi, ii, f"{matrix[ii][pi]:.1f}%", ha="center", va="center",
                         fontsize=10, fontweight="bold",
                         color="white" if matrix[ii][pi] < 80 else "black")

        ax.set_xticks(range(len(polls)))
        ax.set_xticklabels([f"{p}s" for p in polls])
        ax.set_yticks(range(len(intensities)))
        ax.set_yticklabels([i.capitalize() for i in intensities])
        ax.set_xlabel("Poll Interval")
        ax.set_ylabel("Attack Intensity")
        ax.set_title(f"{at.upper()} Flood", fontweight="bold")

    fig.suptitle("Detection Rate by Attack Type, Intensity, and Poll Interval", fontweight="bold")
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    plt.savefig(OUT_PATH, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
