#!/usr/bin/env python3
"""
06_visualize.py — Training visualizations + ML vs Hybrid held-out evaluation.

Existing outputs (from xgb_report.json — no model reload):
  output/figures/fig_metrics_runs.png        — per-run metric bars
  output/figures/fig_threshold_tradeoff.png  — precision/recall at two thresholds
  output/figures/fig_confusion_matrices.png  — confusion matrix grids
  output/figures/fig_model_comparison.png    — XGBoost vs ResNet50

ML vs Hybrid outputs (needs dataset/compiled/benign_test/ to exist):
  output/figures/fig_mlhybrid_metrics.png    — bar chart: ML vs Hybrid metrics
  output/figures/fig_mlhybrid_confusion.png  — confusion matrices: ML vs Hybrid
  output/figures/fig_roc_pr.png              — ROC + PR curves (ML score)
  output/figures/fig_score_dist.png          — ML score histogram by class
"""

import importlib.util
import json
import sys

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from scipy.sparse import csr_matrix
from sklearn.metrics import (
    confusion_matrix, roc_auc_score, roc_curve, precision_recall_curve,
)
from tqdm import tqdm

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
        # Pad to 2×2 if single-class (e.g. fileless test with perfect recall)
        if cm.shape == (1, 1):
            padded = np.zeros((2, 2), dtype=cm.dtype)
            padded[1, 1] = cm[0, 0]
            cm = padded
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
                val = cm[i, j]
                label = str(val) if val > 0 else "—"
                ax.text(j, i, label,
                        ha="center", va="center", fontsize=13, fontweight="bold",
                        color="white" if val > thresh else "black")

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
    ax.axvline(0.5, color="gray", linestyle="--", alpha=0.4, linewidth=1)
    ax.text(0.5, 1.08, "← baseline │ XGBoost →",
            ha="center", va="center", fontsize=8, color="gray",
            transform=ax.get_xaxis_transform())
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# ML vs Hybrid evaluation
# ---------------------------------------------------------------------------

def _load_inference_mod():
    spec = importlib.util.spec_from_file_location(
        "inference_api", Path(__file__).parent / "05_inference_api.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _metrics(preds, labels):
    preds  = np.asarray(preds)
    labels = np.asarray(labels)
    tp = int(((preds == 1) & (labels == 1)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    tn = int(((preds == 0) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def evaluate_ml_vs_hybrid():
    """
    Load the saved model and evaluate on the held-out test set:
        webshell_fileless/ (label=1) + benign_test/ (label=0).

    Uses threshold=0.50 (default, not the optimised value which is calibrated
    on in-domain validation data and would be unreliable here).

    Returns None if benign_test/ does not exist yet.
    """
    benign_test_dir = ROOT / "dataset" / "compiled" / "benign_test"
    fileless_dir    = ROOT / "dataset" / "compiled" / "webshell_fileless"
    model_path      = ROOT / "output" / "xgb_model.pkl"
    vocab_path      = ROOT / "output" / "vocab.json"

    if not benign_test_dir.exists() or not any(benign_test_dir.glob("*.class")):
        print(f"\n  benign_test/ not found or empty: {benign_test_dir}")
        print("  Run 01b_collect_benign_test.sh then 02c_extract_benign_test.py first.")
        print("  Skipping ML vs Hybrid figures.\n")
        return None

    print("\n=== ML vs Hybrid Evaluation (held-out test) ===")
    mod   = _load_inference_mod()
    model = joblib.load(model_path)
    vocab = json.loads(vocab_path.read_text())

    THRESHOLD = 0.50

    ws_files  = sorted(fileless_dir.glob("*.class"))
    bn_files  = sorted(benign_test_dir.glob("*.class"))
    all_files = [(p, 1) for p in ws_files] + [(p, 0) for p in bn_files]

    print(f"  Fileless webshells : {len(ws_files)}")
    print(f"  Benign test        : {len(bn_files)}")
    print(f"  Total              : {len(all_files)}")
    print(f"  Threshold          : {THRESHOLD}\n")

    labels_list: list[int] = []
    ml_scores_list: list[float] = []
    ml_preds_list: list[int] = []
    hyb_preds_list: list[int] = []
    skipped = 0

    for path, label in tqdm(all_files, desc="  Evaluating"):
        result = mod.extract_features(path, vocab)
        feats, javap_text = result if isinstance(result, tuple) else (result, "")
        if feats is None:
            skipped += 1
            continue

        X        = csr_matrix(feats.reshape(1, -1))
        ml_score = float(model.predict_proba(X)[0, 1])
        rule     = mod.rule_check(path, javap_text)
        verdict, _ = mod.combined_verdict(ml_score, rule, THRESHOLD)

        labels_list.append(label)
        ml_scores_list.append(ml_score)
        ml_preds_list.append(1 if ml_score >= THRESHOLD else 0)
        hyb_preds_list.append(1 if verdict == "WEBSHELL" else 0)

    if skipped:
        print(f"  Skipped {skipped} files (javap failed or too few opcodes)")

    labels    = np.array(labels_list)
    ml_scores = np.array(ml_scores_list)
    ml_preds  = np.array(ml_preds_list)
    hyb_preds = np.array(hyb_preds_list)

    ml_m  = _metrics(ml_preds,  labels)
    hyb_m = _metrics(hyb_preds, labels)

    print(f"\n  ML-only  — P={ml_m['precision']:.3f}  R={ml_m['recall']:.3f}  "
          f"F1={ml_m['f1']:.3f}  FPR={ml_m['fpr']:.3f}")
    print(f"  Hybrid   — P={hyb_m['precision']:.3f}  R={hyb_m['recall']:.3f}  "
          f"F1={hyb_m['f1']:.3f}  FPR={hyb_m['fpr']:.3f}")

    return {
        "ml":       ml_m,
        "hybrid":   hyb_m,
        "labels":   labels,
        "ml_scores": ml_scores,
        "ml_preds": ml_preds,
        "hyb_preds": hyb_preds,
        "threshold": THRESHOLD,
        "n_pos": int((labels == 1).sum()),
        "n_neg": int((labels == 0).sum()),
    }


# ---------------------------------------------------------------------------
# Figure 5 — ML vs Hybrid: metric bar chart
# ---------------------------------------------------------------------------
def plot_mlhybrid_metrics(ev):
    keys   = ["precision", "recall", "f1", "fpr"]
    xlabels = ["Precision", "Recall", "F1", "FPR"]
    x = np.arange(len(keys))
    width = 0.32

    fig, ax = plt.subplots(figsize=(9, 5))
    ml_vals  = [ev["ml"][k]     for k in keys]
    hyb_vals = [ev["hybrid"][k] for k in keys]

    b1 = ax.bar(x - width / 2, ml_vals,  width, label="ML only (thr=0.50)",
                color=PALETTE[0], alpha=0.85, edgecolor="white")
    b2 = ax.bar(x + width / 2, hyb_vals, width, label="Hybrid (ML + rules)",
                color=PALETTE[2], alpha=0.85, edgecolor="white")
    annotate_bars(ax, b1)
    annotate_bars(ax, b2)

    ax.set_xticks(x)
    ax.set_xticklabels(xlabels, fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score", fontsize=11)
    ax.set_title(
        f"ML-only vs Hybrid — Held-out Test\n"
        f"({ev['n_pos']} fileless webshells + {ev['n_neg']} benign, threshold=0.50)",
        fontsize=12, fontweight="bold",
    )
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 6 — Confusion matrices: ML vs Hybrid
# ---------------------------------------------------------------------------
def plot_mlhybrid_confusion(ev):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))

    for ax, preds, title in zip(
        axes,
        [ev["ml_preds"], ev["hyb_preds"]],
        ["ML only (threshold = 0.50)", "Hybrid (ML + rule layer)"],
    ):
        cm = confusion_matrix(ev["labels"], preds)
        ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title(title, fontsize=11, fontweight="bold", pad=10)
        ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign", "Webshell"], fontsize=10)
        ax.set_yticklabels(["Benign", "Webshell"], fontsize=10)
        ax.set_xlabel("Predicted", fontsize=10)
        ax.set_ylabel("Actual", fontsize=10)
        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]),
                        ha="center", va="center", fontsize=15, fontweight="bold",
                        color="white" if cm[i, j] > thresh else "black")

    fig.suptitle("Confusion Matrices — Held-out Test Set", fontsize=13, fontweight="bold", y=1.04)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 7 — ROC + PR curves (ML continuous score)
# ---------------------------------------------------------------------------
def plot_roc_pr(ev):
    labels = ev["labels"]
    scores = ev["ml_scores"]

    fpr_pts, tpr_pts, _ = roc_curve(labels, scores)
    auc_val = roc_auc_score(labels, scores)
    prec_pts, rec_pts, _ = precision_recall_curve(labels, scores)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    ax1.plot(fpr_pts, tpr_pts, color=PALETTE[0], lw=2, label=f"AUC = {auc_val:.4f}")
    ax1.plot([0, 1], [0, 1], "k--", alpha=0.3, linewidth=1)
    ax1.scatter([ev["ml"]["fpr"]], [ev["ml"]["recall"]],
                color=PALETTE[0], s=90, zorder=5,
                label=f"ML thr=0.50  (FPR={ev['ml']['fpr']:.3f}, TPR={ev['ml']['recall']:.3f})")
    ax1.scatter([ev["hybrid"]["fpr"]], [ev["hybrid"]["recall"]],
                color=PALETTE[2], s=90, marker="s", zorder=5,
                label=f"Hybrid       (FPR={ev['hybrid']['fpr']:.3f}, TPR={ev['hybrid']['recall']:.3f})")
    ax1.set_xlabel("False Positive Rate", fontsize=11)
    ax1.set_ylabel("True Positive Rate", fontsize=11)
    ax1.set_title("ROC Curve", fontsize=12, fontweight="bold")
    ax1.legend(fontsize=8.5)
    ax1.grid(alpha=0.3)

    ax2.plot(rec_pts, prec_pts, color=PALETTE[1], lw=2, label="ML PR curve")
    ax2.scatter([ev["ml"]["recall"]], [ev["ml"]["precision"]],
                color=PALETTE[0], s=90, zorder=5,
                label=f"ML thr=0.50  (P={ev['ml']['precision']:.3f}, R={ev['ml']['recall']:.3f})")
    ax2.scatter([ev["hybrid"]["recall"]], [ev["hybrid"]["precision"]],
                color=PALETTE[2], s=90, marker="s", zorder=5,
                label=f"Hybrid       (P={ev['hybrid']['precision']:.3f}, R={ev['hybrid']['recall']:.3f})")
    ax2.set_xlabel("Recall", fontsize=11)
    ax2.set_ylabel("Precision", fontsize=11)
    ax2.set_title("Precision-Recall Curve", fontsize=12, fontweight="bold")
    ax2.legend(fontsize=8.5)
    ax2.grid(alpha=0.3)

    fig.suptitle("Held-out Test — ROC & PR Curves (ML score)", fontsize=13, fontweight="bold")
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 8 — ML score distribution histogram
# ---------------------------------------------------------------------------
def plot_score_distribution(ev):
    scores = ev["ml_scores"]
    labels = ev["labels"]
    ws_sc  = scores[labels == 1]
    bn_sc  = scores[labels == 0]

    fig, ax = plt.subplots(figsize=(9, 4.5))
    bins = np.linspace(0, 1, 30)
    ax.hist(bn_sc, bins=bins, color=PALETTE[0], alpha=0.70,
            label=f"Benign (n={len(bn_sc)})", edgecolor="white")
    ax.hist(ws_sc, bins=bins, color=PALETTE[3], alpha=0.70,
            label=f"Fileless Webshell (n={len(ws_sc)})", edgecolor="white")
    ax.axvline(0.50, color="black", linestyle="--", linewidth=1.5, label="Threshold = 0.50")
    ax.set_xlabel("ML Score (XGBoost P(webshell))", fontsize=11)
    ax.set_ylabel("Count", fontsize=11)
    ax.set_title("ML Score Distribution — Held-out Test Set", fontsize=12, fontweight="bold")
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Figure 9 — Fileless test-set composition by memshell type
# ---------------------------------------------------------------------------
def _classify_sample(sig: str, data: bytes) -> str:
    s = sig.lower()
    if "classfiletransformer" in s or "transformer" in sig:
        return "Agent /\nClassFileTransformer"
    if "websocket" in s or "endpoint" in s:
        return "WebSocket\nEndpoint"
    if "handlerinterceptor" in s or "interceptor" in s:
        return "Spring\nInterceptor"
    if "controller" in s:
        return "Spring\nController"
    if "valve" in s or "valvebase" in s:
        return "Tomcat\nValve"
    if "filter" in s and "listener" not in s:
        return "Filter"
    if "listener" in s:
        return "Listener"
    if "servlet" in s or "httpservlet" in s:
        return "Servlet"
    return "ClassLoader /\ndefineClass"


def plot_fileless_type_breakdown():
    import subprocess
    from collections import Counter

    fileless_dir = ROOT / "dataset" / "compiled" / "webshell_fileless"
    counts: Counter = Counter()
    for cf in sorted(fileless_dir.glob("*.class")):
        data = cf.read_bytes()
        r = subprocess.run(["javap", "-p", str(cf)], capture_output=True, text=True)
        lines = [l.strip() for l in r.stdout.splitlines()
                 if "class" in l.lower() or "interface" in l.lower()]
        sig = lines[0] if lines else ""
        counts[_classify_sample(sig, data)] += 1

    labels = [t for t, _ in counts.most_common()]
    values = [counts[t] for t in labels]
    total  = sum(values)

    fig, (ax_bar, ax_pie) = plt.subplots(1, 2, figsize=(13, 5))

    # Bar chart
    bars = ax_bar.barh(labels[::-1], values[::-1], color=PALETTE * 4, alpha=0.85, edgecolor="white")
    for bar, val in zip(bars, values[::-1]):
        ax_bar.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", fontsize=10, fontweight="bold")
    ax_bar.set_xlabel("Number of .class samples", fontsize=11)
    ax_bar.set_title(f"Fileless Webshell Test Set — Type Distribution\n(n={total} samples, never seen in training)",
                     fontsize=11, fontweight="bold")
    ax_bar.set_xlim(0, max(values) + 4)
    ax_bar.grid(axis="x", alpha=0.3, linestyle="--")
    ax_bar.set_axisbelow(True)

    # Pie chart
    wedge_colors = (PALETTE * 4)[:len(labels)]
    wedges, texts, autotexts = ax_pie.pie(
        values, labels=labels, autopct="%1.0f%%",
        colors=wedge_colors, startangle=140,
        pctdistance=0.78, labeldistance=1.12,
    )
    for t in texts:
        t.set_fontsize(8.5)
    for at in autotexts:
        at.set_fontsize(8)
        at.set_fontweight("bold")
    ax_pie.set_title("Proportion by Type", fontsize=11, fontweight="bold")

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

    print("Generating training report figures (from xgb_report.json)...")
    save(plot_metrics_per_run(runs),               "fig_metrics_runs.png")
    save(plot_threshold_tradeoff(report),          "fig_threshold_tradeoff.png")
    save(plot_confusion_matrices(runs, fileless),  "fig_confusion_matrices.png")
    save(plot_model_comparison(report),            "fig_model_comparison.png")

    print("\nGenerating fileless type breakdown figure...")
    save(plot_fileless_type_breakdown(), "fig_fileless_types.png")

    # ML vs Hybrid evaluation on proper two-class held-out test
    ev = evaluate_ml_vs_hybrid()
    if ev is not None:
        print("\nGenerating ML vs Hybrid figures...")
        save(plot_mlhybrid_metrics(ev),    "fig_mlhybrid_metrics.png")
        save(plot_mlhybrid_confusion(ev),  "fig_mlhybrid_confusion.png")
        save(plot_roc_pr(ev),              "fig_roc_pr.png")
        save(plot_score_distribution(ev),  "fig_score_dist.png")

    print(f"\n  All figures → {FIG_DIR}")
    if ev is None:
        print("\n  Note: ML vs Hybrid figures skipped.")
        print("  To generate them:")
        print("    bash scripts/01b_collect_benign_test.sh")
        print("    .venv/bin/python scripts/02c_extract_benign_test.py")
        print("    .venv/bin/python scripts/06_visualize.py")


if __name__ == "__main__":
    main()
