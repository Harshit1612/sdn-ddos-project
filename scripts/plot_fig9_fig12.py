import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from scipy import stats as spstats
with open("results/experiment_summary_real.csv") as f:
    rows = list(csv.DictReader(f))
categories = ["low", "medium", "high"]
# ---- Figure 9: violin of avg_entropy by intensity ----
groups = defaultdict(list)
for r in rows:
    groups[r["intensity"]].append(float(r["avg_entropy"]))
data = [groups[c] for c in categories]
fig, ax = plt.subplots(figsize=(8, 5))
parts = ax.violinplot(data, positions=range(len(categories)), showmeans=True, showmedians=True)
for pc in parts["bodies"]:
    pc.set_facecolor("#2563EB"); pc.set_alpha(0.6)
parts["cmeans"].set_color("#22c55e")
parts["cmedians"].set_color("orange")
ax.axhline(2.5, color="red", linestyle="--", label="Detection threshold (2.5 bits)")
ax.set_xticks(range(len(categories))); ax.set_xticklabels([c.capitalize() for c in categories])
ax.set_xlabel("Attack Intensity"); ax.set_ylabel("Avg. Shannon Entropy per run (bits)")
ax.set_title("Entropy Distribution by Intensity (REAL)", fontweight="bold")
ax.legend(); ax.grid(True, alpha=0.3, axis="y")
fig.tight_layout()
plt.savefig("results/plots/fig9_entropy_violin.png", dpi=150, bbox_inches="tight")
plt.close()
print("Saved fig9")
# ---- Figure 12: ANOVA box plot on detection_rate_pct ----
groups2 = defaultdict(list)
for r in rows:
    groups2[r["intensity"]].append(float(r["detection_rate_pct"]))
data2 = [groups2[c] for c in categories]
f_stat, p_value = spstats.f_oneway(*data2)
fig, ax = plt.subplots(figsize=(7, 5.5))
bp = ax.boxplot(data2, tick_labels=[c.capitalize() for c in categories], patch_artist=True,
                 medianprops=dict(color="orange"))
for patch, c in zip(bp["boxes"], ["#93c5fd", "#60a5fa", "#2563EB"]):
    patch.set_facecolor(c)
ax.set_ylabel("Detection Rate (%)"); ax.set_xlabel("Attack Intensity")
ax.set_title(f"Detection Rate Distribution by Intensity (REAL)\nOne-way ANOVA: F={f_stat:.2f}, "
             f"p<{max(p_value,1e-6):.6f} ({'significant' if p_value<0.05 else 'not significant'})",
             fontweight="bold")
ax.grid(True, alpha=0.3, axis="y")
fig.tight_layout()
plt.savefig("results/plots/fig12_anova_boxplot.png", dpi=150, bbox_inches="tight")
plt.close()
print(f"F={f_stat:.4f} p={p_value:.6f}")
print("Saved fig12")
