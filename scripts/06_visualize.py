#!/usr/bin/env python3
"""
06_visualize.py — Generate training result visualizations from xgb_report.json.

Outputs:
  output/figures/fig_metrics_runs.png        — per-run metric bars (default threshold)
  output/figures/fig_threshold_tradeoff.png  — precision/recall at two thresholds
  output/figures/fig_confusion_matrices.png  — confusion matrix grids (3 runs + fileless)
  output/figures/fig_model_comparison.png    — XGBoost vs ResNet50, file-based vs fileless
"""

import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

ROOT        = Path(__file__).parent.parent
REPORT_JSON = ROOT / "output" / "xgb_report.json"
FIG_DIR     = ROOT / "output" / "figures"

PALETTE = ["#4C72B0", "#DD8452", "#55A868", "#C44E52"]


def save(fig, name, dpi=150):
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    path = FIG_DIR / name
    fig.savefig(path, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  Saved → {path}")


def annotate_bars(ax, bars, fmt="{:.3f}", offset=0.005, fontsize=8):
    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + offset,
                fmt.format(h), ha="center", va="bottom", fontsize=fontsize)


# ---------------------------------------------------------------------------
# Figure 1 — Per-run metrics at default threshold
# ---------------------------------------------------------------------------
def plot_metrics_per_run(runs):
    keys   = ["precision", "recall", "f1", "auc_roc"]
    labels = ["Precision", "Recall", "F1", "AUC-ROC"]
    x      = np.arange(len(keys))
    width  = 0.22

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, run in enumerate(runs):
        vals = [run["test"][k] for k in keys]
        bars = ax.bar(x + i * width, vals, width,
                      label=f"Run {run['run']} (seed {run['seed']})",
                      color=PALETTE[i], alpha=0.85, edgecolor="white")
        annotate_bars(ax, bars)

    ax.set_xticks(x + width)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 1.13)
    ax.set_ylabel("Score", fontsize=11)
    ax.set_title("Per-Run Metrics — Default Threshold (0.50)", fontsize=13, fontweight="bold")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 2 — Precision/Recall tradeoff across two thresholds
# ---------------------------------------------------------------------------
def plot_threshold_tradeoff(report):
    avg_def = report["average"]
    avg_opt = report["average_opt"]
    thr_opt = report["inference_threshold"]

    keys   = ["precision", "recall", "f1", "auc_roc"]
    labels = ["Precision", "Recall", "F1", "AUC-ROC"]
    x      = np.arange(len(keys))
    width  = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    b1 = ax.bar(x - width / 2, [avg_def[k] for k in keys], width,
                label="Default (0.50)", color=PALETTE[0], alpha=0.85, edgecolor="white")
    b2 = ax.bar(x + width / 2, [avg_opt[k] for k in keys], width,
                label=f"High-recall ({thr_opt:.2f})", color=PALETTE[1], alpha=0.85, edgecolor="white")
    annotate_bars(ax, b1)
    annotate_bars(ax, b2)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score (3-run average)", fontsize=11)
    ax.set_title("Precision–Recall Trade-off by Detection Threshold", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 3 — Confusion matrices: 3 runs (default) + fileless
# ---------------------------------------------------------------------------
def plot_confusion_matrices(runs, fileless):
    fig, axes = plt.subplots(1, 4, figsize=(14, 3.8))

    titles = [f"Run {r['run']} — default thr." for r in runs] + ["Fileless (held-out)"]
    cms    = [r["confusion_matrix"] for r in runs] + [fileless["confusion_matrix"]]
    cls_labels = [["Benign", "Webshell"]] * 3 + [["—", "Fileless"]]

    for ax, cm_raw, title, cls in zip(axes, cms, titles, cls_labels):
        cm = np.array(cm_raw)
        ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title(title, fontsize=9.5, fontweight="bold", pad=8)
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(cls, fontsize=9)
        ax.set_yticklabels(cls, fontsize=9)
        ax.set_xlabel("Predicted", fontsize=9)
        ax.set_ylabel("Actual", fontsize=9)

        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]),
                        ha="center", va="center", fontsize=13, fontweight="bold",
                        color="white" if cm[i, j] > thresh else "black")

    fig.suptitle("Confusion Matrices — Default Threshold (0.50)", fontsize=13, fontweight="bold", y=1.04)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 4 — Model comparison: ResNet50 baseline vs XGBoost variants
# ---------------------------------------------------------------------------
def plot_model_comparison(report):
    avg_def = report["average"]
    avg_opt = report["average_opt"]
    fl      = report["fileless_generalisation"]

    categories = [
        "ResNet50\n(baseline)",
        "XGBoost\nfile-based\n(default 0.50)",
        "XGBoost\nfile-based\n(high-recall)",
        "XGBoost\nfileless\n(never trained)",
    ]
    precs = [0.53, avg_def["precision"], avg_opt["precision"], fl["precision"]]
    recs  = [0.78, avg_def["recall"],    avg_opt["recall"],    fl["recall"]]
    f1s   = [0.62, avg_def["f1"],        avg_opt["f1"],        fl["f1"]]

    x     = np.arange(len(categories))
    width = 0.24

    fig, ax = plt.subplots(figsize=(11, 5.5))
    b1 = ax.bar(x - width, precs, width, label="Precision", color=PALETTE[0], alpha=0.85, edgecolor="white")
    b2 = ax.bar(x,         recs,  width, label="Recall",    color=PALETTE[1], alpha=0.85, edgecolor="white")
    b3 = ax.bar(x + width, f1s,   width, label="F1",        color=PALETTE[2], alpha=0.85, edgecolor="white")
    for bars in (b1, b2, b3):
        annotate_bars(ax, bars, fmt="{:.2f}")

    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=9.5)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score", fontsize=11)
    ax.set_title("Model Comparison & Cross-Type Generalisation", fontsize=13, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)
    # Separator between ResNet50 and XGBoost columns
    ax.axvline(0.5, color="gray", linestyle="--", alpha=0.4, linewidth=1)
    ax.text(0.5, 1.08, "← baseline │ XGBoost →",
            ha="center", va="center", fontsize=8, color="gray",
            transform=ax.get_xaxis_transform())
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=== Step 06: Generate Visualizations ===\n")

    if not REPORT_JSON.exists():
        raise FileNotFoundError(f"{REPORT_JSON} not found. Run 04b_train_xgboost.py first.")

    with open(REPORT_JSON) as f:
        report = json.load(f)

    runs     = report["runs"]
    fileless = report["fileless_generalisation"]

    print("Generating figures...")
    save(plot_metrics_per_run(runs),               "fig_metrics_runs.png")
    save(plot_threshold_tradeoff(report),          "fig_threshold_tradeoff.png")
    save(plot_confusion_matrices(runs, fileless),  "fig_confusion_matrices.png")
    save(plot_model_comparison(report),            "fig_model_comparison.png")

    print(f"\n  All figures → {FIG_DIR}")
    print("\nNext step: run scripts/05_inference_api.py")


if __name__ == "__main__":
    main()
