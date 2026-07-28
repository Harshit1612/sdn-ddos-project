#!/usr/bin/env python3
"""
analysis/plot_entropy_timeline.py

Generates Figure 1: entropy timeline showing baseline -> attack -> recovery,
reading the most recent results/metrics_*.csv produced by the live
controller (controller/ddos_controller.py).

Run:
    python3 analysis/plot_entropy_timeline.py
    python3 analysis/plot_entropy_timeline.py --file results/metrics_20260728_120000.csv
"""
import argparse
import csv
import glob
import os
import sys
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # no GUI needed -- just saves PNG to disk
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
OUT_DIR = os.path.join(RESULTS_DIR, "plots")
THRESHOLD = 2.5


def main():
    parser = argparse.ArgumentParser(description="Plot entropy timeline (Figure 1)")
    parser.add_argument("--file", default=None,
                         help="specific metrics_*.csv to plot (default: most recent)")
    args = parser.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)

    if args.file:
        target = args.file
        if not os.path.exists(target):
            sys.exit(f"ERROR: file not found: {target}")
    else:
        files = sorted(glob.glob(os.path.join(RESULTS_DIR, "metrics_*.csv")))
        if not files:
            sys.exit(
                "ERROR: no results/metrics_*.csv files found.\n"
                "This file is only created when controller/ddos_controller.py has\n"
                "actually run during a live Mininet session. Run the controller +\n"
                "topology + traffic_gen.py first, then try this script again."
            )
        target = files[-1]

    print(f"Reading: {target}")
    with open(target) as f:
        rows = list(csv.DictReader(f))

    if not rows:
        sys.exit(f"ERROR: {target} exists but has no data rows. Let the controller run longer first.")

    try:
        times = [datetime.fromisoformat(r["timestamp"]) for r in rows]
        entropies = [float(r["entropy"]) for r in rows]
    except (KeyError, ValueError) as e:
        sys.exit(f"ERROR: unexpected CSV format in {target}: {e}")

    fig, ax = plt.subplots(figsize=(11, 4))
    ax.plot(times, entropies, color="#2563EB", linewidth=1.4, label="H(src_ip)")
    ax.axhline(THRESHOLD, color="#E2A73A", linestyle="--", label=f"Threshold = {THRESHOLD} bits")
    ax.fill_between(times, entropies, THRESHOLD,
                     where=[e < THRESHOLD for e in entropies],
                     alpha=0.15, color="red", label="Below threshold (attack detected)")
    ax.set_xlabel("Time")
    ax.set_ylabel("Shannon Entropy (bits)")
    ax.set_title("Source-IP Entropy: Baseline -> SYN Flood -> Mitigation Recovery", fontweight="bold")
    ax.legend(loc="lower right")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.set_ylim(0, 4)
    ax.grid(True, alpha=0.3, linestyle="--")
    fig.autofmt_xdate()
    fig.tight_layout()

    out_path = os.path.join(OUT_DIR, "fig1_entropy_timeline.png")
    plt.savefig(out_path, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
