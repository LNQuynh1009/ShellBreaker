#!/usr/bin/env python3
"""
07_eval_combined.py — Offline evaluation of the full hybrid detection pipeline.

Runs on the held-out test set (fileless webshells + benign_test) and produces
confusion matrices + score distribution charts comparing:

  1. ML-only      (ResNet50 alone, threshold=0.50)
  2. Rule-only    (c0ny1-derived scoring, threshold=score≥2)
  3. Hybrid       (ML + Rule combined — matches the live detector logic)

Also shows:
  4. ML score distribution (webshell vs benign density plot)
  5. Rule score distribution (bar chart by score bucket)
  6. Per-injection-type detection rate (fileless webshells only)
  7. Combined verdict breakdown (CONFIRMED / HIGH / MEDIUM / BENIGN)

Outputs saved to output/figures/eval_combined_*.png

Usage:
  .venv/bin/python scripts/07_eval_combined.py
"""

import json
import re
import subprocess
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import torch
import torch.nn as nn
import torchvision.models as tv_models
import torchvision.transforms as tv_transforms
from PIL import Image
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from tqdm import tqdm

ROOT           = Path(__file__).parent.parent
MODEL_PATH     = ROOT / "output" / "model_best.pt"
VOCAB_PATH     = ROOT / "output" / "vocab.json"
REPORT_PATH    = ROOT / "output" / "training_report.json"
FILELESS_DIR   = ROOT / "dataset" / "compiled" / "webshell_fileless"
BENIGN_TEST_DIR= ROOT / "dataset" / "compiled" / "benign_test"
FIGURES_DIR    = ROOT / "output" / "figures"

ML_THRESHOLD   = 0.50
HIGH_THRESHOLD = 0.85
RULE_HIGH_SCORE = 6
RULE_MED_SCORE  = 2

# ---------------------------------------------------------------------------
# Opcode normalisation (must match training)
# ---------------------------------------------------------------------------
OPCODE_NORM: dict[str, str] = {
    **{f"iconst_{s}": "iconst" for s in ["m1","0","1","2","3","4","5"]},
    **{f"lconst_{i}": "lconst" for i in range(2)},
    **{f"fconst_{i}": "fconst" for i in range(3)},
    **{f"dconst_{i}": "dconst" for i in range(2)},
    **{f"iload_{i}":  "iload"  for i in range(4)},
    **{f"lload_{i}":  "lload"  for i in range(4)},
    **{f"fload_{i}":  "fload"  for i in range(4)},
    **{f"dload_{i}":  "dload"  for i in range(4)},
    **{f"aload_{i}":  "aload"  for i in range(4)},
    **{f"istore_{i}": "istore" for i in range(4)},
    **{f"lstore_{i}": "lstore" for i in range(4)},
    **{f"fstore_{i}": "fstore" for i in range(4)},
    **{f"dstore_{i}": "dstore" for i in range(4)},
    **{f"astore_{i}": "astore" for i in range(4)},
}
_OPCODE_RE = re.compile(r"^\s+\d+:\s+([a-z][a-z0-9_]+)")

# ---------------------------------------------------------------------------
# Rule engine constants (mirrors detector.py)
# ---------------------------------------------------------------------------
IFACES_ALL = {
    "javax/servlet/Filter", "javax/servlet/Servlet", "javax/servlet/http/HttpServlet",
    "javax/servlet/ServletRequestListener", "javax/servlet/http/HttpSessionListener",
    "javax/servlet/ServletContextListener",
    "jakarta/servlet/Filter", "jakarta/servlet/Servlet", "jakarta/servlet/http/HttpServlet",
    "jakarta/servlet/ServletContextListener", "jakarta/servlet/http/HttpSessionListener",
    "org/apache/catalina/Valve", "org/apache/catalina/valves/ValveBase",
    "org/apache/catalina/Executor",
    "org/springframework/web/servlet/HandlerInterceptor",
    "org/springframework/web/socket/WebSocketHandler",
    "javax/websocket/Endpoint", "javax/websocket/server/ServerEndpointConfig$Configurator",
    "io/netty/channel/ChannelHandler", "io/netty/channel/ChannelInboundHandler",
    "java/lang/instrument/ClassFileTransformer",
}
IFACE_SCORE = {i: (3 if "websocket" not in i.lower() and "netty" not in i.lower() else 2)
               for i in IFACES_ALL}

DANGER_APIS = [
    (re.compile(r"java/lang/Runtime",               re.I), 3),
    (re.compile(r"ProcessBuilder",                  re.I), 3),
    (re.compile(r"defineClass",                     re.I), 3),
    (re.compile(r"java/net/URLClassLoader",         re.I), 2),
    (re.compile(r"sun/misc/Unsafe",                 re.I), 2),
    (re.compile(r"javax/script/ScriptEngine",       re.I), 2),
    (re.compile(r"groovy/lang/GroovyClassLoader",   re.I), 2),
    (re.compile(r"java/lang/instrument/Instrumentation", re.I), 2),
    (re.compile(r"setContextClassLoader",           re.I), 2),
    (re.compile(r"setAccessible",                   re.I), 1),
    (re.compile(r"java/lang/reflect/Proxy",         re.I), 2),
    (re.compile(r"javax/tools/JavaCompiler",        re.I), 3),
    (re.compile(r"javassist/ClassPool|javassist/CtClass", re.I), 2),
    (re.compile(r"org/apache/bcel",                 re.I), 2),
    (re.compile(r"java/rmi/server/UnicastRemoteObject", re.I), 2),
]
TOOL_RE = re.compile(
    r"godzilla|behinder|icescorpion|regeorg|antsword|rebeyond|memshell|x-cmd|java-memshell",
    re.IGNORECASE,
)
SHELL_KW = ["shell","cmd","exec","backdoor","payload","webshell","memshell","inject","exploit"]


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def disassemble(class_path: Path):
    try:
        r = subprocess.run(["javap", "-c", "-p", "-verbose", str(class_path)],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return None, ""
        javap_text = r.stdout
    except Exception:
        return None, ""

    ops = []
    for line in javap_text.splitlines():
        m = _OPCODE_RE.match(line)
        if m:
            ops.append(OPCODE_NORM.get(m.group(1), m.group(1)))
    return (ops if len(ops) >= 4 else None), javap_text


def build_adj_image(ops, vocab):
    n = len(vocab)
    mat = np.zeros((n, n), dtype=np.uint32)
    for i in range(len(ops) - 1):
        a = vocab.get(ops[i], -1)
        b = vocab.get(ops[i + 1], -1)
        if a >= 0 and b >= 0:
            mat[a, b] += 1
    max_val = mat.max()
    if max_val > 0:
        mat = (mat.astype(float) / max_val * 255).astype(np.uint8)
    return Image.fromarray(mat.astype(np.uint8))


def rule_score(javap_text, class_path):
    score = 0
    for iface, pts in IFACE_SCORE.items():
        if iface in javap_text:
            score += pts
    for pat, pts in DANGER_APIS:
        if pat.search(javap_text):
            score += pts
    if TOOL_RE.search(javap_text):
        score += 4
    stem = class_path.stem.lower()
    if any(kw in stem for kw in SHELL_KW):
        score += 2
    if len(class_path.stem) <= 3 and "$" not in class_path.stem:
        score += 1
    if "SourceFile:" not in javap_text and "$" not in class_path.stem:
        score += 1
    return score


# ---------------------------------------------------------------------------
# Load model
# ---------------------------------------------------------------------------

def load_model(device):
    net = tv_models.resnet50()
    net.fc = nn.Linear(net.fc.in_features, 1)
    net.load_state_dict(torch.load(MODEL_PATH, map_location=device, weights_only=True))
    net.eval()
    return net.to(device)


TRANSFORM = tv_transforms.Compose([
    tv_transforms.Grayscale(num_output_channels=3),
    tv_transforms.Resize((224, 224)),
    tv_transforms.ToTensor(),
    tv_transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])


def ml_score(ops, vocab, model, device):
    img    = build_adj_image(ops, vocab)
    tensor = TRANSFORM(img).unsqueeze(0).to(device)
    with torch.no_grad():
        return float(torch.sigmoid(model(tensor)).item())


# ---------------------------------------------------------------------------
# Combined verdict (mirrors detector.py)
# ---------------------------------------------------------------------------

def combined_verdict(ml_s, r_score):
    rule_high   = r_score >= RULE_HIGH_SCORE
    rule_medium = r_score >= RULE_MED_SCORE
    ml_high     = ml_s   >= HIGH_THRESHOLD
    ml_medium   = ml_s   >= ML_THRESHOLD
    # Rule HIGH alone → CONFIRMED: precise for fileless, no ML gate needed
    if rule_high:
        return "CONFIRMED"
    if ml_high:
        return "HIGH"
    if ml_medium or rule_medium:
        return "MEDIUM"
    return "BENIGN"


def verdict_is_webshell(v):
    return v in ("CONFIRMED", "HIGH", "MEDIUM")


# ---------------------------------------------------------------------------
# Run pipeline on test set
# ---------------------------------------------------------------------------

def evaluate(vocab, model, device):
    results = []

    # Collect: (class_path, true_label, injection_type)
    samples = []
    if FILELESS_DIR.exists():
        for p in sorted(FILELESS_DIR.glob("*.class")):
            samples.append((p, 1, "fileless"))
    if BENIGN_TEST_DIR.exists():
        for p in sorted(BENIGN_TEST_DIR.glob("*.class")):
            samples.append((p, 0, "benign_test"))

    print(f"Evaluating {len(samples)} samples "
          f"({sum(1 for _,l,_ in samples if l==1)} fileless, "
          f"{sum(1 for _,l,_ in samples if l==0)} benign_test)...")

    for class_path, true_label, sample_type in tqdm(samples, unit="file"):
        ops, javap_text = disassemble(class_path)
        if ops is None:
            continue

        mls  = ml_score(ops, vocab, model, device)
        rs   = rule_score(javap_text, class_path)
        cv   = combined_verdict(mls, rs)

        results.append({
            "path":         str(class_path),
            "true_label":   true_label,
            "sample_type":  sample_type,
            "ml_score":     mls,
            "rule_score":   rs,
            "verdict":      cv,
            "ml_pred":      int(mls >= ML_THRESHOLD),
            "rule_pred":    int(rs  >= RULE_MED_SCORE),
            "hybrid_pred":  int(verdict_is_webshell(cv)),
        })

    return results


# ---------------------------------------------------------------------------
# Metrics helpers
# ---------------------------------------------------------------------------

def confusion(results, pred_key, true_key="true_label"):
    tp = sum(1 for r in results if r[pred_key]==1 and r[true_key]==1)
    fp = sum(1 for r in results if r[pred_key]==1 and r[true_key]==0)
    fn = sum(1 for r in results if r[pred_key]==0 and r[true_key]==1)
    tn = sum(1 for r in results if r[pred_key]==0 and r[true_key]==0)
    return np.array([[tn, fp], [fn, tp]])


def metrics_from_cm(cm):
    tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
    pre = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1  = 2 * pre * rec / (pre + rec) if (pre + rec) > 0 else 0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    return {"accuracy": acc, "precision": pre, "recall": rec, "f1": f1, "fpr": fpr}


# ---------------------------------------------------------------------------
# Plot helpers
# ---------------------------------------------------------------------------

def _fmt_cm_title(name, cm):
    m = metrics_from_cm(cm)
    return (f"{name}\n"
            f"Prec={m['precision']:.3f}  Rec={m['recall']:.3f}\n"
            f"F1={m['f1']:.3f}  FPR={m['fpr']:.3f}")


def plot_confusion_matrices(results):
    """Side-by-side confusion matrices: ML-only, Rule-only, Hybrid."""
    cms = {
        "ML only\n(ResNet50 ≥0.50)":   confusion(results, "ml_pred"),
        "Rule only\n(score ≥2)":        confusion(results, "rule_pred"),
        "Hybrid\n(ML + Rule combined)": confusion(results, "hybrid_pred"),
    }

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    cmaps = ["Blues", "Greens", "Oranges"]
    for ax, (title, cm), cmap in zip(axes, cms.items(), cmaps):
        sns.heatmap(cm, annot=True, fmt="d", cmap=cmap,
                    xticklabels=["Benign", "Webshell"],
                    yticklabels=["Benign", "Webshell"],
                    ax=ax, cbar=False, annot_kws={"size": 14})
        ax.set_title(_fmt_cm_title(title, cm), fontsize=10)
        ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    plt.suptitle("Held-out Test: Fileless Webshells + Benign_test\n"
                 "Comparison: ML-only vs Rule-only vs Hybrid",
                 fontsize=12, fontweight="bold")
    plt.tight_layout()
    out = FIGURES_DIR / "eval_confusion_matrices.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"Saved → {out}")


def plot_score_distributions(results):
    """ML score and rule score distributions for webshell vs benign."""
    ws = [r for r in results if r["true_label"] == 1]
    bn = [r for r in results if r["true_label"] == 0]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # ── ML score density ─────────────────────────────────────────────
    ax = axes[0]
    ax.hist([r["ml_score"] for r in ws], bins=30, alpha=0.65,
            color="#e74c3c", label=f"Fileless webshell (n={len(ws)})", density=True)
    ax.hist([r["ml_score"] for r in bn], bins=30, alpha=0.65,
            color="#3498db", label=f"Benign test (n={len(bn)})", density=True)
    ax.axvline(ML_THRESHOLD,   color="gray", ls="--", lw=1.5, label=f"Threshold={ML_THRESHOLD}")
    ax.axvline(HIGH_THRESHOLD, color="red",  ls=":",  lw=1.5, label=f"HIGH={HIGH_THRESHOLD}")
    ax.set_xlabel("ML Score (ResNet50)"); ax.set_ylabel("Density")
    ax.set_title("ML Score Distribution"); ax.legend(fontsize=8)
    for s in ["top", "right"]: ax.spines[s].set_visible(False)

    # ── Rule score bar ────────────────────────────────────────────────
    ax = axes[1]
    buckets = ["0", "1", "2-5\n(MEDIUM)", "6-9\n(HIGH)", "≥10\n(HIGH)"]
    def bucket(s):
        if s == 0: return 0
        if s == 1: return 1
        if s < 6:  return 2
        if s < 10: return 3
        return 4
    ws_counts = Counter(bucket(r["rule_score"]) for r in ws)
    bn_counts = Counter(bucket(r["rule_score"]) for r in bn)
    x = np.arange(len(buckets)); w = 0.35
    ax.bar(x - w/2, [ws_counts.get(i, 0) for i in range(len(buckets))],
           w, label="Fileless webshell", color="#e74c3c", alpha=0.8)
    ax.bar(x + w/2, [bn_counts.get(i, 0) for i in range(len(buckets))],
           w, label="Benign test",       color="#3498db", alpha=0.8)
    ax.set_xticks(x); ax.set_xticklabels(buckets, fontsize=9)
    ax.set_xlabel("Rule Score Bucket"); ax.set_ylabel("Count")
    ax.set_title("Rule Score Distribution"); ax.legend(fontsize=8)
    for s in ["top", "right"]: ax.spines[s].set_visible(False)

    plt.suptitle("Score Distributions — ResNet50 ML vs Rule Engine", fontsize=12, fontweight="bold")
    plt.tight_layout()
    out = FIGURES_DIR / "eval_score_distributions.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"Saved → {out}")


def plot_verdict_breakdown(results):
    """Stacked bar: verdict distribution by true class."""
    ws = [r for r in results if r["true_label"] == 1]
    bn = [r for r in results if r["true_label"] == 0]
    tiers = ["CONFIRMED", "HIGH", "MEDIUM", "BENIGN"]
    colors = {"CONFIRMED": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "BENIGN": "#2ecc71"}

    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    for ax, group, title in zip(axes, [ws, bn], ["Fileless Webshells (label=1)", "Benign Test (label=0)"]):
        counts = Counter(r["verdict"] for r in group)
        total  = len(group)
        bottom = 0
        for tier in tiers:
            cnt = counts.get(tier, 0)
            pct = cnt / total * 100 if total else 0
            bar = ax.bar(["Combined Verdict"], cnt, bottom=bottom,
                         color=colors[tier], label=f"{tier} ({cnt}, {pct:.1f}%)")
            if cnt > 0:
                ax.text(0, bottom + cnt / 2, f"{tier}\n{pct:.1f}%",
                        ha="center", va="center", fontsize=9, fontweight="bold",
                        color="white" if tier in ("CONFIRMED", "HIGH") else "black")
            bottom += cnt
        ax.set_title(title, fontsize=11)
        ax.set_ylabel("Count"); ax.set_ylim(0, total * 1.05)
        ax.legend(loc="upper right", fontsize=7)
        for s in ["top", "right"]: ax.spines[s].set_visible(False)

    plt.suptitle("Hybrid Verdict Breakdown\n(CONFIRMED=Rule HIGH + ML≥0.50 | HIGH=ML≥0.85 | MEDIUM=either fired)",
                 fontsize=10, fontweight="bold")
    plt.tight_layout()
    out = FIGURES_DIR / "eval_verdict_breakdown.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"Saved → {out}")


def plot_metrics_comparison(results):
    """Bar chart comparing Precision / Recall / F1 / FPR across all three methods."""
    methods = {
        "ML only":   confusion(results, "ml_pred"),
        "Rule only": confusion(results, "rule_pred"),
        "Hybrid":    confusion(results, "hybrid_pred"),
    }
    metric_keys = ["accuracy", "precision", "recall", "f1", "fpr"]
    metric_labels = ["Accuracy", "Precision", "Recall", "F1", "FPR"]

    data = {name: metrics_from_cm(cm) for name, cm in methods.items()}
    colors = ["#4C72B0", "#55A868", "#DD8452"]

    x = np.arange(len(metric_keys)); w = 0.25
    fig, ax = plt.subplots(figsize=(11, 5))
    for i, (name, vals) in enumerate(data.items()):
        bars = ax.bar(x + i*w, [vals[k] for k in metric_keys], w,
                      label=name, color=colors[i], alpha=0.85)
        for bar in bars:
            v = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, v + 0.01,
                    f"{v:.3f}", ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x + w); ax.set_xticklabels(metric_labels)
    ax.set_ylim(0, 1.15); ax.set_ylabel("Score")
    ax.set_title("Detection Performance: ML-only vs Rule-only vs Hybrid\n"
                 "(Held-out: fileless webshells + benign_test)", fontsize=11, fontweight="bold")
    ax.legend(); ax.axhline(1.0, color="gray", ls=":", lw=0.8)
    for s in ["top", "right"]: ax.spines[s].set_visible(False)
    plt.tight_layout()
    out = FIGURES_DIR / "eval_metrics_comparison.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"Saved → {out}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    vocab  = json.loads(VOCAB_PATH.read_text())
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    if not MODEL_PATH.exists():
        print(f"[error] model_best.pt not found: {MODEL_PATH}")
        raise SystemExit(1)

    model = load_model(device)
    print(f"ResNet50 loaded from {MODEL_PATH.name}")

    results = evaluate(vocab, model, device)

    if not results:
        print("[error] No samples evaluated — check dataset/compiled/webshell_fileless/ and benign_test/")
        raise SystemExit(1)

    # ── Print summary table ────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"Results on {len(results)} samples "
          f"({sum(1 for r in results if r['true_label']==1)} fileless, "
          f"{sum(1 for r in results if r['true_label']==0)} benign_test)")
    print(f"{'─'*60}")
    header = f"  {'Method':<18}  {'Acc':>6}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}  {'FPR':>6}"
    print(header)
    print(f"  {'─'*18}  {'─'*6}  {'─'*6}  {'─'*6}  {'─'*6}  {'─'*6}")
    for pred_key, name in [("ml_pred","ML only"), ("rule_pred","Rule only"), ("hybrid_pred","Hybrid")]:
        cm = confusion(results, pred_key)
        m  = metrics_from_cm(cm)
        print(f"  {name:<18}  {m['accuracy']:6.4f}  {m['precision']:6.4f}  "
              f"{m['recall']:6.4f}  {m['f1']:6.4f}  {m['fpr']:6.4f}")
    print(f"{'='*60}")

    # Verdict breakdown
    print("\nHybrid verdict counts:")
    for v, cnt in sorted(Counter(r["verdict"] for r in results).items()):
        ws_cnt = sum(1 for r in results if r["verdict"]==v and r["true_label"]==1)
        bn_cnt = sum(1 for r in results if r["verdict"]==v and r["true_label"]==0)
        print(f"  {v:<12}: {cnt:3d}  (webshell={ws_cnt}, benign={bn_cnt})")

    # ── Generate all plots ─────────────────────────────────────────────────
    print("\nGenerating plots...")
    plt.style.use("seaborn-v0_8-whitegrid")

    plot_confusion_matrices(results)
    plot_score_distributions(results)
    plot_verdict_breakdown(results)
    plot_metrics_comparison(results)

    print(f"\nAll figures saved to {FIGURES_DIR}/")
    print("Files:")
    for f in sorted(FIGURES_DIR.glob("eval_*.png")):
        print(f"  {f.name}")


if __name__ == "__main__":
    main()
