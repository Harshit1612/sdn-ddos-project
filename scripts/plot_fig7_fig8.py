import csv, statistics
from collections import defaultdict
import numpy as np
import matplotlib.pyplot as plt
with open("results/experiment_summary_real.csv") as f:
    rows = list(csv.DictReader(f))
groups = defaultdict(list)
for r in rows:
    groups[(r["attack_type"], r["intensity"], int(r["poll_interval"]))].append(float(r["detection_rate_pct"]))
atypes = ["syn", "udp"]; intensities = ["low", "medium", "high"]; polls = [1, 2, 5]
# ---- Figure 7: bar chart by poll interval ----
fig, axes = plt.subplots(1, 3, figsize=(13, 4), sharey=True)
for pi, poll in enumerate(polls):
    ax = axes[pi]
    x = np.arange(3); width = 0.35
    syn_means = [statistics.mean(groups[("syn", it, poll)]) for it in intensities]
    syn_stds  = [statistics.stdev(groups[("syn", it, poll)]) for it in intensities]
    udp_means = [statistics.mean(groups[("udp", it, poll)]) for it in intensities]
    udp_stds  = [statistics.stdev(groups[("udp", it, poll)]) for it in intensities]
    ax.bar(x - width/2, syn_means, width, yerr=syn_stds, label="SYN flood", color="#2563EB", capsize=3)
    ax.bar(x + width/2, udp_means, width, yerr=udp_stds, label="UDP flood", color="#22c55e", capsize=3)
    ax.set_xticks(x); ax.set_xticklabels([i.capitalize() for i in intensities])
    ax.set_title(f"Poll = {poll}s"); ax.set_ylim(0, 105)
    if pi == 0:
        ax.set_ylabel("Detection Rate (%)"); ax.legend(fontsize=8)
fig.suptitle("Detection Rate by Attack Type, Intensity, Poll Interval\n(REAL -- computed from shannon_entropy())", fontweight="bold")
fig.tight_layout()
plt.savefig("results/plots/fig7_detection_rate_config.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved fig7")
# ---- Figure 8: heatmap ----
fig, axes = plt.subplots(1, 2, figsize=(12, 4))
for ai, at in enumerate(atypes):
    matrix = np.zeros((len(intensities), len(polls)))
    for ii, intensity in enumerate(intensities):
        for pj, poll in enumerate(polls):
            vals = groups.get((at, intensity, poll), [0])
            matrix[ii][pj] = statistics.mean(vals)
    ax = axes[ai]
    im = ax.imshow(matrix, cmap="RdYlGn", aspect="auto", vmin=50, vmax=100)
    plt.colorbar(im, ax=ax, label="Detection Rate (%)")
    for ii in range(len(intensities)):
        for pj in range(len(polls)):
            ax.text(pj, ii, f"{matrix[ii][pj]:.1f}%", ha="center", va="center", fontsize=10,
                     fontweight="bold", color="white" if matrix[ii][pj] < 75 else "black")
    ax.set_xticks(range(len(polls))); ax.set_xticklabels([f"{p}s" for p in polls])
    ax.set_yticks(range(len(intensities))); ax.set_yticklabels([i.capitalize() for i in intensities])
    ax.set_xlabel("Poll Interval"); ax.set_ylabel("Attack Intensity")
    ax.set_title(f"{at.upper()} Flood", fontweight="bold")
fig.suptitle("Detection Rate Heatmap (%) -- REAL", fontsize=13, fontweight="bold")
fig.tight_layout()
plt.savefig("results/plots/fig8_detection_heatmap.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved fig8")
