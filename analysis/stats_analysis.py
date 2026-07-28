#!/usr/bin/env python3
"""
analysis/stats_analysis.py

Runs the one-way ANOVA test required by proposal Section 3.4:
"Where applicable, a one-way ANOVA test will be conducted to determine if
there were statistically significant differences between intensities."

This was NOT implemented anywhere in the original build guide -- Figure 12
(ANOVA box plots) only drew a picture, it never actually ran the test or
reported an F-statistic / p-value. This module fixes that.

Run:
    python3 analysis/stats_analysis.py --summary results/experiment_summary.csv
"""
import argparse
import csv
from collections import defaultdict
from scipy import stats


def load_summary(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def anova_by_intensity(rows, metric_col="detection_rate_pct"):
    """One-way ANOVA: does attack intensity (low/medium/high) produce a
    statistically significant difference in the given metric?"""
    groups = defaultdict(list)
    for r in rows:
        groups[r["intensity"]].append(float(r[metric_col]))

    intensities = ["low", "medium", "high"]
    samples = [groups[i] for i in intensities if groups.get(i)]

    if len(samples) < 2:
        raise ValueError(
            f"Need at least 2 intensity groups with data to run ANOVA, "
            f"found {len(samples)}. Run more experiment configurations first."
        )

    f_stat, p_value = stats.f_oneway(*samples)
    return f_stat, p_value, {i: groups[i] for i in intensities if groups.get(i)}


def main():
    parser = argparse.ArgumentParser(description="Run ANOVA on experiment_summary.csv")
    parser.add_argument("--summary", required=True, help="path to experiment_summary.csv")
    parser.add_argument("--metric", default="detection_rate_pct",
                         help="column to test (default: detection_rate_pct)")
    parser.add_argument("--out", default=None, help="optional path to write result as text")
    args = parser.parse_args()

    rows = load_summary(args.summary)
    print(f"Loaded {len(rows)} experiment runs from {args.summary}")

    f_stat, p_value, groups = anova_by_intensity(rows, args.metric)

    print()
    print(f"One-way ANOVA on '{args.metric}' across intensity levels:")
    for intensity, vals in groups.items():
        n = len(vals)
        mean = sum(vals) / n if n else 0
        print(f"  {intensity:8s} n={n:3d}  mean={mean:6.2f}")

    print()
    print(f"F-statistic = {f_stat:.4f}")
    print(f"p-value     = {p_value:.6f}")
    significant = p_value < 0.05
    print(f"Result: {'STATISTICALLY SIGNIFICANT' if significant else 'NOT significant'} "
          f"difference between intensities (alpha=0.05)")

    if args.out:
        with open(args.out, "w") as f:
            f.write(f"One-way ANOVA on '{args.metric}' across intensity levels\n")
            f.write(f"F-statistic = {f_stat:.4f}\n")
            f.write(f"p-value = {p_value:.6f}\n")
            f.write(f"Significant at alpha=0.05: {significant}\n")
        print(f"\nSaved: {args.out}")


if __name__ == "__main__":
    main()
