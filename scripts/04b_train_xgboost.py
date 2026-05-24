#!/usr/bin/env python3
"""
04b_train_xgboost.py — Train XGBoost on opcode feature vectors.

Features per .class file (total ~22,360 sparse dims):
  - Unigram  (149): normalised frequency of each JVM opcode
  - Bigram (22201): normalised bigram transition counts (sparse)
  - Metadata  (10): SourceFile present, inner class, implements
                    Filter/Servlet/Listener, total opcodes, invoke ratio,
                    reflect ratio, athrow ratio

Runs 3 independent seeds, averages metrics — same methodology as
04_train_resnet50.py so results are directly comparable.
Outputs: output/xgb_model.pkl, output/xgb_report.json

Runs locally — no GPU needed.
"""

import csv
import json
import random
import re
import subprocess
import time
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack as sp_hstack
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_recall_curve, precision_score,
    recall_score, roc_auc_score,
)
from sklearn.preprocessing import MaxAbsScaler
from tqdm import tqdm
from xgboost import XGBClassifier

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = Path(__file__).parent.parent
DATASET_CSV = ROOT / "output" / "dataset.csv"
OUTPUT_DIR  = ROOT / "output"
MODEL_PATH  = OUTPUT_DIR / "xgb_model.pkl"
REPORT_PATH = OUTPUT_DIR / "xgb_report.json"
VOCAB_JSON  = OUTPUT_DIR / "vocab.json"

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
NUM_RUNS    = 3
TRAIN_RATIO = 0.70
VAL_RATIO   = 0.15
RANDOM_SEED = 42

XGB_PARAMS = dict(
    n_estimators      = 600,
    max_depth         = 6,
    learning_rate     = 0.05,
    subsample         = 0.8,
    colsample_bytree  = 0.4,   # important — many sparse features
    min_child_weight  = 3,
    reg_alpha         = 0.1,
    reg_lambda        = 1.0,
    tree_method       = "hist",
    eval_metric       = "auc",
    early_stopping_rounds = 40,
    random_state      = 42,
    n_jobs            = -1,
)

# ---------------------------------------------------------------------------
# Opcode normalisation (identical to 03_build_grayscale.py)
# ---------------------------------------------------------------------------
OPCODE_NORM: dict[str, str] = {
    **{f"iconst_{s}": "iconst" for s in ["m1", "0", "1", "2", "3", "4", "5"]},
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

INVOKE_OPS  = {"invokevirtual", "invokespecial", "invokestatic",
               "invokeinterface", "invokedynamic"}
REFLECT_OPS = {"invokevirtual", "invokedynamic"}   # rough proxy

SERVLET_IFACES = {
    "javax/servlet/Filter", "javax/servlet/Servlet",
    "javax/servlet/http/HttpServlet",
    "javax/servlet/ServletRequestListener",
    "javax/servlet/http/HttpSessionListener",
    "jakarta/servlet/Filter", "jakarta/servlet/Servlet",
    "jakarta/servlet/http/HttpServlet",
}

# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(class_path: Path, vocab: dict[str, int]) -> np.ndarray | None:
    """
    Returns dense float32 vector of length (149 + 149*149 + 10) = 22,360,
    or None if javap fails / too few opcodes.
    """
    n = len(vocab)
    try:
        r = subprocess.run(
            ["javap", "-c", "-p", "-verbose", str(class_path)],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return None
        javap_text = r.stdout
    except Exception:
        return None

    ops: list[str] = []
    for line in javap_text.splitlines():
        m = _OPCODE_RE.match(line)
        if m:
            ops.append(OPCODE_NORM.get(m.group(1), m.group(1)))

    if len(ops) < 4:
        return None

    total = len(ops)

    # Unigram
    unigram = np.zeros(n, dtype=np.float32)
    for op in ops:
        idx = vocab.get(op, -1)
        if idx >= 0:
            unigram[idx] += 1
    unigram /= total

    # Bigram
    bigram = np.zeros(n * n, dtype=np.float32)
    for i in range(len(ops) - 1):
        a = vocab.get(ops[i], -1)
        b = vocab.get(ops[i + 1], -1)
        if a >= 0 and b >= 0:
            bigram[a * n + b] += 1
    bigram /= max(total - 1, 1)

    # Metadata (10 features)
    invoke_cnt  = sum(1 for op in ops if op in INVOKE_OPS)
    reflect_cnt = sum(1 for op in ops if op in REFLECT_OPS)
    athrow_cnt  = ops.count("athrow")
    meta = np.array([
        min(total / 1000.0, 1.0),                                    # normalised size
        float("SourceFile:" in javap_text),                          # has source file
        float("$" in class_path.stem),                               # inner/anonymous class
        float(any(iface in javap_text for iface in SERVLET_IFACES)), # implements servlet iface
        float("java/lang/Runtime" in javap_text),                    # Runtime.exec usage
        float("defineClass" in javap_text),                          # dynamic class loading
        float("java/net/URLClassLoader" in javap_text),              # URL class loading
        invoke_cnt  / total,                                          # invoke ratio
        reflect_cnt / total,                                          # reflect proxy ratio
        athrow_cnt  / total,                                          # exception throw ratio
    ], dtype=np.float32)

    return np.concatenate([unigram, bigram, meta])


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_csv(csv_path: Path, vocab: dict) -> tuple[list, list, list, list]:
    """Returns (trainval_X, trainval_y, fileless_X, fileless_y)."""
    trainval_X, trainval_y = [], []
    fileless_X, fileless_y = [], []

    rows = []
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)

    print(f"  Extracting features from {len(rows)} .class files...")
    for row in tqdm(rows, desc="  features"):
        img_path = Path(row["path"])
        if not img_path.is_absolute():
            img_path = ROOT / img_path

        # Derive .class path from PNG path
        type_name = row.get("type", "benign")
        stem      = img_path.stem
        class_dir = ROOT / "dataset" / "compiled" / type_name
        class_path = class_dir / f"{stem}.class"

        if not class_path.exists():
            continue

        feats = extract_features(class_path, vocab)
        if feats is None:
            continue

        label = int(row["label"])
        if type_name == "webshell_fileless":
            fileless_X.append(feats)
            fileless_y.append(label)
        else:
            trainval_X.append(feats)
            trainval_y.append(label)

    return trainval_X, trainval_y, fileless_X, fileless_y


# ---------------------------------------------------------------------------
# Train / evaluate
# ---------------------------------------------------------------------------

def split(X, y, train_r, val_r, seed):
    rng   = random.Random(seed)
    idx   = list(range(len(X)))
    rng.shuffle(idx)
    n     = len(idx)
    n_tr  = int(n * train_r)
    n_val = int(n * val_r)
    tr    = idx[:n_tr]
    val   = idx[n_tr:n_tr + n_val]
    te    = idx[n_tr + n_val:]
    def sel(lst, ids): return [lst[i] for i in ids]
    return sel(X,tr), sel(y,tr), sel(X,val), sel(y,val), sel(X,te), sel(y,te)


def to_sparse(X):
    return csr_matrix(np.array(X, dtype=np.float32))


def find_threshold(val_y, val_probs, min_prec=0.50):
    prec, rec, thr = precision_recall_curve(val_y, val_probs)
    mask = prec[:-1] >= min_prec
    if mask.any():
        return float(thr[mask][np.argmax(rec[:-1][mask])])
    return 0.35


def metrics_at(y_true, probs, threshold):
    preds = (probs >= threshold).astype(int)
    return {
        "threshold": round(threshold, 4),
        "accuracy":  round(accuracy_score(y_true, preds), 4),
        "precision": round(precision_score(y_true, preds, zero_division=0), 4),
        "recall":    round(recall_score(y_true, preds, zero_division=0), 4),
        "f1":        round(f1_score(y_true, preds, zero_division=0), 4),
        "auc_roc":   round(roc_auc_score(y_true, probs), 4),
    }


def run_once(run_id, X_all, y_all):
    seed = RANDOM_SEED + run_id * 17
    print(f"\n{'='*60}\n  RUN {run_id + 1} / {NUM_RUNS}\n{'='*60}")

    X_tr, y_tr, X_val, y_val, X_te, y_te = split(X_all, y_all, TRAIN_RATIO, VAL_RATIO, seed)
    print(f"  Split — train: {len(y_tr)}, val: {len(y_val)}, test: {len(y_te)}")

    n_pos = sum(y_tr); n_neg = len(y_tr) - n_pos
    spw   = n_neg / max(n_pos, 1)

    Xtr_sp  = to_sparse(X_tr)
    Xval_sp = to_sparse(X_val)
    Xte_sp  = to_sparse(X_te)

    model = XGBClassifier(**XGB_PARAMS, scale_pos_weight=spw)
    t0 = time.time()
    model.fit(
        Xtr_sp, y_tr,
        eval_set=[(Xval_sp, y_val)],
        verbose=False,
    )
    elapsed = time.time() - t0
    print(f"  Trained {model.best_iteration} trees in {elapsed:.1f}s")

    val_probs = model.predict_proba(Xval_sp)[:, 1]
    te_probs  = model.predict_proba(Xte_sp)[:, 1]

    opt_thr   = find_threshold(y_val, val_probs)
    test_def  = metrics_at(y_te, te_probs, 0.50)
    test_opt  = metrics_at(y_te, te_probs, opt_thr)
    cm_def    = confusion_matrix(y_te, (te_probs >= 0.50).astype(int)).tolist()
    cm_opt    = confusion_matrix(y_te, (te_probs >= opt_thr).astype(int)).tolist()

    print(f"\n  Default threshold (0.50):")
    print(classification_report(y_te, (te_probs>=0.50).astype(int), target_names=["benign","webshell"]))
    print(f"  Threshold-optimised ({opt_thr:.4f}):")
    print(classification_report(y_te, (te_probs>=opt_thr).astype(int), target_names=["benign","webshell"]))

    return {
        "run": run_id + 1, "seed": seed,
        "best_iteration": int(model.best_iteration),
        "opt_threshold": round(opt_thr, 4),
        "test": test_def, "test_opt": test_opt,
        "confusion_matrix": cm_def, "confusion_matrix_opt": cm_opt,
        "model": model,
        "val_probs": val_probs.tolist(), "val_labels": y_val,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== Step 04b: XGBoost on opcode feature vectors ===\n")

    if not DATASET_CSV.exists():
        raise FileNotFoundError(f"dataset.csv not found. Run 03_build_grayscale.py first.")

    vocab: dict[str, int] = json.loads(VOCAB_JSON.read_text())
    n_vocab = len(vocab)
    print(f"Vocab size: {n_vocab}  → feature dim: {n_vocab + n_vocab*n_vocab + 10}")

    X_all, y_all, X_fl, y_fl = load_csv(DATASET_CSV, vocab)
    if not X_all:
        raise RuntimeError("No valid samples extracted.")

    n_ws  = sum(y_all); n_bn = len(y_all) - n_ws
    print(f"\nTrain/val pool: {len(y_all)} — webshell_file: {n_ws}, benign: {n_bn}")
    print(f"Fileless test:  {len(y_fl)} (held-out)")

    run_results = []
    best_f1     = -1.0
    best_model  = None

    for run_id in range(NUM_RUNS):
        res = run_once(run_id, X_all, y_all)
        run_results.append(res)
        if res["test_opt"]["f1"] > best_f1:
            best_f1   = res["test_opt"]["f1"]
            best_model = res["model"]

    joblib.dump(best_model, MODEL_PATH)
    print(f"\nBest XGBoost model saved → {MODEL_PATH}")

    # Fileless evaluation
    fileless_eval = {}
    if X_fl and best_model is not None:
        fl_probs  = best_model.predict_proba(to_sparse(X_fl))[:, 1]
        avg_thr   = float(np.mean([r["opt_threshold"] for r in run_results]))
        fl_m      = metrics_at(y_fl, fl_probs, avg_thr)
        fl_cm     = confusion_matrix(y_fl, (fl_probs >= avg_thr).astype(int)).tolist()
        fileless_eval = {**fl_m, "confusion_matrix": fl_cm}
        print(f"\n  Fileless recall: {fl_m['recall']:.4f}  F1: {fl_m['f1']:.4f}")

    # Aggregate
    keys = ["accuracy", "precision", "recall", "f1", "auc_roc"]
    avg_opt  = {k: round(float(np.mean([r["test_opt"][k] for r in run_results])), 4) for k in keys}
    std_opt  = {k: round(float(np.std( [r["test_opt"][k] for r in run_results])), 4) for k in keys}
    avg_def  = {k: round(float(np.mean([r["test"][k]     for r in run_results])), 4) for k in keys}
    std_def  = {k: round(float(np.std( [r["test"][k]     for r in run_results])), 4) for k in keys}
    avg_thr  = round(float(np.mean([r["opt_threshold"] for r in run_results])), 4)

    report = {
        "model": "xgboost",
        "num_runs": NUM_RUNS,
        "inference_threshold": avg_thr,
        "feature_dim": len(vocab) + len(vocab)**2 + 10,
        "dataset": {"trainval_webshell": n_ws, "trainval_benign": n_bn, "fileless_test": len(y_fl)},
        "runs": [
            {
                "run": r["run"], "seed": r["seed"],
                "best_iteration": r["best_iteration"],
                "opt_threshold": r["opt_threshold"],
                "test": r["test"], "test_opt": r["test_opt"],
                "confusion_matrix": r["confusion_matrix"],
                "confusion_matrix_opt": r["confusion_matrix_opt"],
            }
            for r in run_results
        ],
        "average": avg_def, "std": std_def,
        "average_opt": avg_opt, "std_opt": std_opt,
        "fileless_generalisation": fileless_eval,
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Report saved → {REPORT_PATH}")

    print("\n" + "="*60)
    print("FINAL SUMMARY — XGBoost (threshold-optimised)")
    print("="*60)
    for k in keys:
        print(f"  {k:12s}: {avg_opt[k]:.4f}  ±{std_opt[k]:.4f}")
    if fileless_eval:
        print(f"\n  Fileless recall   : {fileless_eval.get('recall', 0):.4f}")
        print(f"  Fileless precision: {fileless_eval.get('precision', 0):.4f}")
        print(f"  Fileless F1       : {fileless_eval.get('f1', 0):.4f}")
    print(f"\n  Inference threshold (avg): {avg_thr:.4f}")
    print("="*60)
    print("\nNext step: run scripts/05_inference_api.py")


if __name__ == "__main__":
    main()
