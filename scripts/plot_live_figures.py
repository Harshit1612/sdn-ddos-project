#!/usr/bin/env python3
"""
scripts/plot_live_figures.py

Run this AFTER scripts/run_experiment_matrix.py and
analysis/aggregate_live_results.py have produced a real
results/experiment_summary.csv and real results/metrics_poll*s_*.csv files
on your testbed. Produces genuine (non-simulated) versions of:
  fig5_detection_latency.png   -- real detection_latency_ms per config
  fig6_throughput_comparison.png -- real iperf3 Mbps baseline/during/post
  fig11_controller_resources.png -- real psutil CPU/mem trace (one poll config)
  fig13_summary_dashboard.png  -- all 6 metrics, all real

FIXED: each figure function now checks that the CSV actually has the
columns it needs before touching them, and prints a clear skip-reason
instead of crashing with a KeyError. This matters because
results/experiment_summary.csv can come from two different generators:
  - analysis/gen_intensity_traces_real.py -> only has
    run_id, attack_type, intensity, poll_interval, rep,
    detection_rate_pct, avg_entropy   (no throughput/latency/cpu/mem)
  - analysis/aggregate_live_results.py -> has the FULL column set
    (detection_latency_ms, avg_cpu_pct, avg_mem_mb,
    throughput_baseline_mbps, throughput_during_mbps, throughput_post_mbps)
Only the second one has everything fig5/fig6/fig11/fig13 need.

Run:
  python3 scripts/plot_live_figures.py
"""
import csv
import glob
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.path.insert(0, "detection")
from entropy_detector import load_rows, confusion_at_threshold, metrics as calc_metrics  # noqa: E402


def load_summary(path="results/experiment_summary.csv"):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit(f"{path} is empty -- nothing to plot.")
    print(f"Loaded {len(rows)} rows from {path}")
    print(f"Columns present: {list(rows[0].keys())}")
    return rows


def has_cols(rows, cols):
    """Returns True only if every column in `cols` exists in the CSV header."""
    present = set(rows[0].keys())
    missing = [c for c in cols if c not in present]
    if missing:
        print(f"  SKIPPING -- missing column(s) {missing} in experiment_summary.csv "
              f"(this file was probably not produced by aggregate_live_results.py)")
        return False
    return True


def fig5_detection_latency(rows):
    print("Figure 5 -- detection latency")
    if not has_cols(rows, ["attack_type", "intensity", "detection_latency_ms"]):
        return

    groups = defaultdict(list)
    for r in rows:
        if r.get("detection_latency_ms"):
            groups[(r["attack_type"], r["intensity"])].append(float(r["detection_latency_ms"]))

    if not groups:
        print("  SKIPPING -- detection_latency_ms column exists but every value is empty "
              "(no run in this file ever triggered a detection)")
        return

    atypes = ["syn", "udp"]; intensities = ["low", "medium", "high"]
    labels = [f"{at.upper()}\n{it.capitalize()}" for at in atypes for it in intensities]
    means, errs = [], []
    for at in atypes:
        for it in intensities:
            vals = groups.get((at, it), [0])
            means.append(statistics.mean(vals))
            errs.append(statistics.stdev(vals) if len(vals) > 1 else 0)

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(labels))
    bars = ax.bar(x, means, yerr=errs, capsize=4, color="#2563EB", alpha=0.85, edgecolor="white")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Detection Latency (ms)")
    ax.set_title("Detection Latency by Attack Configuration -- REAL (live Mininet/Ryu capture)")
    ax.grid(True, alpha=0.3, axis="y")
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 20, f"{m:.0f}ms", ha="center", fontsize=8)
    fig.tight_layout()
    plt.savefig("results/plots/fig5_detection_latency.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Saved fig5 (REAL)")


def fig6_throughput(rows):
    print("Figure 6 -- throughput")
    required = ["attack_type", "intensity", "throughput_baseline_mbps",
                "throughput_during_mbps", "throughput_post_mbps"]
    if not has_cols(rows, required):
        return

    scenarios, baseline_vals, during_vals, after_vals = [], [], [], []
    groups = defaultdict(lambda: defaultdict(list))
    for r in rows:
        key = (r["attack_type"], r["intensity"])
        for phase, col in [("baseline", "throughput_baseline_mbps"),
                            ("during", "throughput_during_mbps"),
                            ("post", "throughput_post_mbps")]:
            if r.get(col):
                groups[key][phase].append(float(r[col]))

    if not groups:
        print("  SKIPPING -- throughput columns exist but every value is empty")
        return

    for at in ["syn", "udp"]:
        for it in ["low", "medium", "high"]:
            scenarios.append(f"{at.upper()} {it.capitalize()}")
            g = groups[(at, it)]
            baseline_vals.append(statistics.mean(g["baseline"]) if g["baseline"] else 0)
            during_vals.append(statistics.mean(g["during"]) if g["during"] else 0)
            after_vals.append(statistics.mean(g["post"]) if g["post"] else 0)

    x = np.arange(len(scenarios)); w = 0.25
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar(x - w, baseline_vals, w, label="Baseline (no attack)", color="#22c55e", alpha=0.85)
    ax.bar(x, during_vals, w, label="During attack", color="#ef4444", alpha=0.85)
    ax.bar(x + w, after_vals, w, label="Post-mitigation", color="#2563EB", alpha=0.85)
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title("Legitimate Host Throughput -- REAL (iperf3 --json captures)")
    ax.set_xticks(x); ax.set_xticklabels(scenarios, fontsize=8.5)
    ax.legend(loc="lower left"); ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    plt.savefig("results/plots/fig6_throughput_comparison.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Saved fig6 (REAL)")


def fig11_controller_resources(poll=2):
    print(f"Figure 11 -- controller resources (poll={poll}s)")
    files = sorted(glob.glob(f"results/metrics_poll{poll}s_*.csv"))
    if not files:
        print(f"  SKIPPING -- no results/metrics_poll{poll}s_*.csv found "
              f"(run scripts/run_experiment_matrix.py first)")
        return

    with open(files[-1]) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print(f"  SKIPPING -- {files[-1]} is empty")
        return

    required = ["timestamp", "cpu_pct", "mem_mb", "detection_flag"]
    missing = [c for c in required if c not in rows[0]]
    if missing:
        print(f"  SKIPPING -- {files[-1]} is missing column(s) {missing}")
        return

    times = [datetime.fromisoformat(r["timestamp"]) for r in rows]
    cpus = [float(r["cpu_pct"]) for r in rows]
    mems = [float(r["mem_mb"]) for r in rows]
    flags = [int(r["detection_flag"]) for r in rows]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 5.5), sharex=True)
    for ax in [ax1, ax2]:
        for i, fl in enumerate(flags):
            if fl and i < len(times) - 1:
                ax.axvspan(times[i], times[min(i+1, len(times)-1)], alpha=0.12, color="red")
    ax1.plot(times, cpus, color="#2563EB"); ax1.fill_between(times, cpus, alpha=0.12, color="#2563EB")
    ax1.set_ylabel("Controller CPU (%)")
    ax1.set_title(f"Ryu Controller Resource Overhead -- REAL psutil samples (poll={poll}s)")
    ax2.plot(times, mems, color="#22c55e"); ax2.fill_between(times, mems, alpha=0.12, color="#22c55e")
    ax2.set_ylabel("Controller Memory (MB)"); ax2.set_xlabel("Time")
    red_patch = mpatches.Patch(color="red", alpha=0.3, label="Attack/detection window")
    ax2.legend(handles=[red_patch])
    fig.autofmt_xdate(); fig.tight_layout()
    plt.savefig("results/plots/fig11_controller_resources.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Saved fig11 (REAL)")


def fig13_dashboard(rows):
    print("Figure 13 -- summary dashboard")
    required = ["attack_type", "intensity", "detection_rate_pct",
                "avg_cpu_pct", "avg_mem_mb", "detection_latency_ms",
                "throughput_during_mbps"]
    if not has_cols(rows, required):
        return
    if not os.path.exists("data/CICDDoS2019_subset.csv"):
        print("  SKIPPING -- data/CICDDoS2019_subset.csv not found (needed for FPR/FNR panel)")
        return

    configs, det_means, cpu_means, mem_means, lat_means = [], [], [], [], []
    for at in ["syn", "udp"]:
        for it in ["low", "medium", "high"]:
            vals = [r for r in rows if r["attack_type"] == at and r["intensity"] == it]
            configs.append(f"{at.upper()}\n{it.capitalize()}")
            det_means.append(statistics.mean(float(r["detection_rate_pct"]) for r in vals) if vals else 0)
            cpu_vals = [float(r["avg_cpu_pct"]) for r in vals if r["avg_cpu_pct"]]
            mem_vals = [float(r["avg_mem_mb"]) for r in vals if r["avg_mem_mb"]]
            lat_vals = [float(r["detection_latency_ms"]) for r in vals if r["detection_latency_ms"]]
            cpu_means.append(statistics.mean(cpu_vals) if cpu_vals else 0)
            mem_means.append(statistics.mean(mem_vals) if mem_vals else 0)
            lat_means.append(statistics.mean(lat_vals) if lat_vals else 0)

    cal_rows, _ = load_rows("data/CICDDoS2019_subset.csv")
    TP, FP, TN, FN = confusion_at_threshold(cal_rows, 2.5)
    acc, prec, rec, f1, fpr, fnr = calc_metrics(TP, FP, TN, FN)

    x = np.arange(len(configs))
    colors_b = ["#2563EB", "#3B82F6", "#60A5FA", "#22c55e", "#4ADE80", "#86EFAC"]
    fig = plt.figure(figsize=(14, 8.5))
    fig.suptitle("Complete Performance Evaluation -- All 6 Metrics (REAL, live testbed)", fontsize=14, fontweight="bold")

    ax1 = fig.add_subplot(2, 3, 1)
    ax1.bar(x, det_means, color=colors_b); ax1.set_title("Detection Rate (%)")
    ax1.set_xticks(x); ax1.set_xticklabels(configs, fontsize=7); ax1.set_ylim(0, 110)

    ax2 = fig.add_subplot(2, 3, 2)
    ax2.bar([0, 1], [fpr*100, fnr*100], color=["#ef4444", "#f59e0b"])
    ax2.set_xticks([0, 1]); ax2.set_xticklabels(["FPR", "FNR"])
    ax2.set_title("False Positive / Negative Rate (%)\n(CICDDoS2019 sweep @ 2.5 bits)")

    ax3 = fig.add_subplot(2, 3, 3)
    ax3.bar(x, lat_means, color=colors_b); ax3.set_title("Detection Latency (ms) -- REAL")
    ax3.set_xticks(x); ax3.set_xticklabels(configs, fontsize=7)

    ax4 = fig.add_subplot(2, 3, 4)
    tp_means = []
    for at in ["syn", "udp"]:
        for it in ["low", "medium", "high"]:
            vals = [float(r["throughput_during_mbps"]) for r in rows
                     if r["attack_type"] == at and r["intensity"] == it and r["throughput_during_mbps"]]
            tp_means.append(statistics.mean(vals) if vals else 0)
    ax4.bar(x, tp_means, color=colors_b); ax4.set_title("Throughput During Attack (Mbps) -- REAL")
    ax4.set_xticks(x); ax4.set_xticklabels(configs, fontsize=7)

    ax5 = fig.add_subplot(2, 3, 5)
    ax5.bar(x, cpu_means, color=colors_b); ax5.set_title("Controller CPU Overhead (%) -- REAL")
    ax5.set_xticks(x); ax5.set_xticklabels(configs, fontsize=7)

    ax6 = fig.add_subplot(2, 3, 6)
    ax6.bar(x, mem_means, color=colors_b); ax6.set_title("Controller Memory (MB) -- REAL")
    ax6.set_xticks(x); ax6.set_xticklabels(configs, fontsize=7)

    fig.tight_layout()
    plt.savefig("results/plots/fig13_summary_dashboard.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  Saved fig13 (REAL)")


if __name__ == "__main__":
    os.makedirs("results/plots", exist_ok=True)
    rows = load_summary()
    fig5_detection_latency(rows)
    fig6_throughput(rows)
    fig11_controller_resources(poll=2)
    fig13_dashboard(rows)
