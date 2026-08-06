#!/usr/bin/env python3
"""
analysis/plot_anova.py
Generates Figure 12: box plot of detection rate by intensity, with the
real ANOVA F-statistic and p-value shown in the plot title.

Run:
    python3 analysis/plot_anova.py --summary results/experiment_summary.csv
"""
import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(__file__))
from stats_analysis import load_summary, anova_by_intensity  # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "results", "plots")


def main():
    parser = argparse.ArgumentParser(description="Generate ANOVA box plot (Figure 12)")
    parser.add_argument("--summary", required=True, help="path to experiment_summary.csv")
    parser.add_argument("--metric", default="detection_rate_pct")
    args = parser.parse_args()

    rows = load_summary(args.summary)
    f_stat, p_value, groups = anova_by_intensity(rows, args.metric)

    os.makedirs(OUT_DIR, exist_ok=True)
    intensities = [i for i in ["low", "medium", "high"] if i in groups]
    data = [groups[i] for i in intensities]

    plt.figure(figsize=(8, 6))
    box = plt.boxplot(data, tick_labels=[i.capitalize() for i in intensities],
                       patch_artist=True)
    colors = ["#a6cee3", "#1f78b4", "#08306b"]
    for patch, color in zip(box["boxes"], colors):
        patch.set_facecolor(color)

    sig_str = "significant" if p_value < 0.05 else "not significant"
    plt.title(f"Detection Rate Distribution by Intensity\n"
              f"One-way ANOVA: F={f_stat:.2f}, p={p_value:.6f} ({sig_str})")
    plt.xlabel("Attack Intensity")
    plt.ylabel("Detection Rate (%)")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()

    out_path = os.path.join(OUT_DIR, "figure12_anova_boxplot.png")
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
