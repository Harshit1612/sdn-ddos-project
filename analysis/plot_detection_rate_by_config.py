#!/usr/bin/env python3
"""
analysis/plot_detection_rate_by_config.py

Generates Figure 7: Detection Rate by Attack Type, Intensity, and Poll
Interval -- three panels (Poll=1s, 2s, 5s), each showing grouped bars
(SYN flood vs UDP flood) across Low/Medium/High intensity, with error
bars for standard deviation across the n reps per configuration.

Run:
    python3 analysis/plot_detection_rate_by_config.py
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
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "plots", "fig7_detection_rate_by_config.png")


def main():
    with open(SUMMARY_PATH) as f:
        rows = list(csv.DictReader(f))

    groups = defaultdict(list)
    n_reps = 0
    for r in rows:
        key = (r["attack_type"], r["intensity"], int(r["poll_interval"]))
        groups[key].append(float(r["detection_rate_pct"]))
        n_reps = max(n_reps, len(groups[key]))

    intensities = ["low", "medium", "high"]
    intensity_labels = ["Low", "Medium", "High"]
    polls = [1, 2, 5]
    atypes = ["syn", "udp"]
    atype_colors = {"syn": "#2563EB", "udp": "#22c55e"}
    atype_labels = {"syn": "SYN flood", "udp": "UDP flood"}

    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2), sharey=True)
    x = np.arange(len(intensities))
    bar_width = 0.35

    for pi, poll in enumerate(polls):
        ax = axes[pi]
        for ai, at in enumerate(atypes):
            means, stds = [], []
            for intensity in intensities:
                vals = groups.get((at, intensity, poll), [0])
                means.append(statistics.mean(vals))
                stds.append(statistics.stdev(vals) if len(vals) > 1 else 0)
            offset = (ai - 0.5) * bar_width
            ax.bar(x + offset, means, bar_width, yerr=stds, capsize=4,
                   color=atype_colors[at], alpha=0.85, edgecolor="white",
                   label=atype_labels[at] if pi == 0 else None)

        ax.set_xticks(x)
        ax.set_xticklabels(intensity_labels)
        ax.set_title(f"Poll = {poll}s", fontweight="bold")
        ax.set_ylim(0, 110)
        ax.grid(True, alpha=0.3, axis="y")
        if pi == 0:
            ax.set_ylabel("Detection Rate (%)")

    fig.legend(loc="upper center", bbox_to_anchor=(0.5, 1.04), ncol=2, frameon=True)
    fig.suptitle(
        f"Detection Rate by Attack Type, Intensity, Poll Interval "
        f"(mean +/- std, n={n_reps} reps, simulated data)",
        fontsize=12, y=1.12,
    )
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    plt.savefig(OUT_PATH, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
