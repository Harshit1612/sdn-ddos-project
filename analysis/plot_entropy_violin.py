#!/usr/bin/env python3
"""
analysis/plot_entropy_violin.py

Generates Figure 9: violin plot of average entropy per run, grouped by
attack intensity, with the detection threshold marked.

Run:
    python3 analysis/plot_entropy_violin.py
"""
import csv
import os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SUMMARY_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "experiment_summary.csv")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "plots", "fig9_entropy_violin.png")
THRESHOLD = 2.5


def main():
    with open(SUMMARY_PATH) as f:
        rows = list(csv.DictReader(f))

    groups = defaultdict(list)
    for r in rows:
        groups[r["intensity"]].append(float(r["avg_entropy"]))

    categories = ["low", "medium", "high"]
    data = [groups[c] for c in categories]

    fig, ax = plt.subplots(figsize=(8, 5))
    parts = ax.violinplot(data, positions=range(len(categories)), showmeans=True, showmedians=True)
    for pc in parts["bodies"]:
        pc.set_facecolor("#2563EB")
        pc.set_alpha(0.6)
    parts["cmeans"].set_color("#22c55e")
    parts["cmedians"].set_color("orange")

    ax.axhline(THRESHOLD, color="red", linestyle="--", label=f"Detection threshold ({THRESHOLD} bits)")
    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels([c.capitalize() for c in categories])
    ax.set_xlabel("Attack Intensity")
    ax.set_ylabel("Avg. Shannon Entropy per run (bits)")
    ax.set_title("Entropy Distribution Across Experiment Runs, by Intensity", fontweight="bold")
    ax.legend()
    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    plt.savefig(OUT_PATH, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
