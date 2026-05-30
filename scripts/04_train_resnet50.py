#!/usr/bin/env python3
"""
04_train_resnet50.py — Train ResNet50 on opcode-adjacency grayscale PNGs.

Paper: GAShellBreaker (Electronics MDPI 2025)
  Input  : 149×149 grayscale PNG (opcode bigram adjacency matrix, from 03_build_grayscale.py)
  Model  : ResNet50 (ImageNet pretrained, fine-tuned for binary classification)
  Training: 20 epochs, Adam lr=0.001, batch_size=32
  Protocol: 3 independent runs, averaged metrics (matches paper Table 7)
  Split  : 80/20 train/test stratified on webshell_file + benign
  Held-out: webshell_fileless (+ benign_test if PNGs exist) — never in training

Outputs (all under output/):
  model_best.pt          — state dict of the run with the highest test F1
  training_report.json   — per-run metrics + 3-run averages + fileless generalisation
  training_curves.png    — loss + F1 curves across all runs

Usage:
  # Local (CPU — slow, expect ~4h for 20 epochs on ~5k samples)
  .venv/bin/python scripts/04_train_resnet50.py

  # Colab (recommended — T4 GPU, ~20-40 min)
  Upload output.zip + this script to Drive, then open notebooks/colab_train.ipynb.
"""

import csv
import json
import os
import random
import time
from pathlib import Path

import numpy as np

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, Dataset
    import torchvision.models as models
    import torchvision.transforms as transforms
    from PIL import Image
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                  f1_score, roc_auc_score, confusion_matrix)
    from tqdm import tqdm
except ImportError as e:
    print(f"[error] Missing dependency: {e}")
    print("Install: pip install torch torchvision scikit-learn pillow tqdm")
    raise SystemExit(1)

# ---------------------------------------------------------------------------
# Paths — patched by colab_train.ipynb when running in Colab
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent

DATASET_CSV     = ROOT / "output" / "dataset.csv"
MODEL_PATH      = ROOT / "output" / "model_best.pt"
REPORT_PATH     = ROOT / "output" / "training_report.json"
CURVES_PATH     = ROOT / "output" / "training_curves.png"
FILELESS_DIR    = ROOT / "output" / "webshell_fileless"
BENIGN_TEST_DIR = ROOT / "output" / "benign_test"

# ---------------------------------------------------------------------------
# Hyperparameters (from paper Section 5.2)
# ---------------------------------------------------------------------------
EPOCHS      = 20
LR          = 1e-3
BATCH_SIZE  = 32
N_RUNS      = 3
SEED        = 42

# ResNet50 expects 224×224 RGB; our grayscale 149×149 is converted to 3-channel and resized.
TRANSFORM_TRAIN = transforms.Compose([
    transforms.Grayscale(num_output_channels=3),
    transforms.Resize((224, 224)),
    transforms.RandomHorizontalFlip(),       # light augmentation — doesn't change opcode semantics
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225]),
])

TRANSFORM_EVAL = transforms.Compose([
    transforms.Grayscale(num_output_channels=3),
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406],
                         std=[0.229, 0.224, 0.225]),
])


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class PNGDataset(Dataset):
    def __init__(self, rows: list[tuple[str, int]], transform=None):
        self.rows = rows
        self.transform = transform

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, idx):
        path, label = self.rows[idx]
        img = Image.open(path).convert("L")
        if self.transform:
            img = self.transform(img)
        return img, torch.tensor(label, dtype=torch.float32)


def load_trainval_rows() -> list[tuple[str, int]]:
    """Load webshell_file + benign rows from dataset.csv (fileless excluded)."""
    rows: list[tuple[str, int]] = []
    with open(DATASET_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["type"] == "webshell_fileless":
                continue
            path = Path(row["path"])
            if not path.is_absolute():
                path = ROOT / path
            if path.exists():
                rows.append((str(path), int(row["label"])))
    return rows


def load_held_out_rows() -> list[tuple[str, int]]:
    """Held-out test: fileless webshells + benign_test (if PNGs exist)."""
    rows: list[tuple[str, int]] = []
    if FILELESS_DIR.exists():
        for p in sorted(FILELESS_DIR.glob("*.png")):
            rows.append((str(p), 1))
    if BENIGN_TEST_DIR.exists():
        for p in sorted(BENIGN_TEST_DIR.glob("*.png")):
            rows.append((str(p), 0))
    return rows


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def make_resnet50(device: torch.device) -> nn.Module:
    model = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V1)
    model.fc = nn.Linear(model.fc.in_features, 1)  # binary classification head
    return model.to(device)


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

def train_epoch(model, loader, optimizer, criterion, device) -> float:
    model.train()
    total_loss = 0.0
    for imgs, labels in loader:
        imgs   = imgs.to(device)
        labels = labels.to(device).unsqueeze(1)
        optimizer.zero_grad()
        loss = criterion(model(imgs), labels)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(imgs)
    return total_loss / len(loader.dataset)


@torch.no_grad()
def evaluate(model, loader, device) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    model.eval()
    all_labels, all_preds, all_probs = [], [], []
    for imgs, labels in loader:
        probs = torch.sigmoid(model(imgs.to(device))).squeeze(1).cpu().numpy()
        preds = (probs >= 0.5).astype(int)
        all_probs.extend(probs.tolist())
        all_preds.extend(preds.tolist())
        all_labels.extend(labels.int().tolist())
    return np.array(all_labels), np.array(all_preds), np.array(all_probs)


def metrics(labels, preds, probs) -> dict:
    cm = confusion_matrix(labels, preds).tolist()
    return {
        "accuracy":         float(accuracy_score(labels, preds)),
        "precision":        float(precision_score(labels, preds, average="macro", zero_division=0)),
        "recall":           float(recall_score(labels, preds, average="macro", zero_division=0)),
        "f1":               float(f1_score(labels, preds, average="macro", zero_division=0)),
        "auc_roc":          float(roc_auc_score(labels, probs)) if len(set(labels)) > 1 else 0.0,
        "confusion_matrix": cm,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"{'='*60}")
    print(f"ShellBreaker — ResNet50 Training")
    print(f"  Device     : {device}" + (f" ({torch.cuda.get_device_name(0)})" if device.type == "cuda" else ""))
    if device.type == "cpu":
        print("  [warn] No GPU — each epoch will be slow. Colab T4 recommended.")
    print(f"  Epochs     : {EPOCHS}  |  LR: {LR}  |  Batch: {BATCH_SIZE}  |  Runs: {N_RUNS}")
    print(f"{'='*60}")

    all_rows    = load_trainval_rows()
    held_rows   = load_held_out_rows()
    n_ws  = sum(1 for _, l in all_rows if l == 1)
    n_bn  = sum(1 for _, l in all_rows if l == 0)
    n_fl  = sum(1 for _, l in held_rows if l == 1)
    n_bt  = sum(1 for _, l in held_rows if l == 0)

    print(f"Train/val pool : {len(all_rows)}  ({n_ws} webshell, {n_bn} benign)")
    print(f"Held-out       : {len(held_rows)}  ({n_fl} fileless, {n_bt} benign_test)")

    if len(all_rows) < 100:
        print("[error] Too few samples. Run scripts/03_build_grayscale.py first.")
        raise SystemExit(1)

    criterion = nn.BCEWithLogitsLoss()
    run_results: list[dict] = []
    best_global_f1 = -1.0
    best_global_state: dict | None = None

    for run in range(1, N_RUNS + 1):
        seed = SEED + run
        random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)

        # Stratified 80/20 split
        pos = [r for r in all_rows if r[1] == 1]
        neg = [r for r in all_rows if r[1] == 0]
        random.shuffle(pos); random.shuffle(neg)
        sp, sn = int(0.8 * len(pos)), int(0.8 * len(neg))
        train_rows = pos[:sp] + neg[:sn]
        test_rows  = pos[sp:] + neg[sn:]
        random.shuffle(train_rows)

        print(f"\n{'─'*60}")
        print(f"Run {run}/{N_RUNS}  |  train={len(train_rows)}  test={len(test_rows)}")

        num_workers = min(4, os.cpu_count() or 1)
        train_loader = DataLoader(PNGDataset(train_rows, TRANSFORM_TRAIN),
                                  batch_size=BATCH_SIZE, shuffle=True,
                                  num_workers=num_workers, pin_memory=(device.type == "cuda"))
        test_loader  = DataLoader(PNGDataset(test_rows, TRANSFORM_EVAL),
                                  batch_size=BATCH_SIZE, shuffle=False,
                                  num_workers=num_workers, pin_memory=(device.type == "cuda"))

        model     = make_resnet50(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)

        history: list[dict] = []
        best_run_f1    = -1.0
        best_run_state: dict | None = None

        for epoch in range(1, EPOCHS + 1):
            t0 = time.time()
            train_loss = train_epoch(model, train_loader, optimizer, criterion, device)
            scheduler.step()

            labels, preds, probs = evaluate(model, test_loader, device)
            m = metrics(labels, preds, probs)

            history.append({
                "epoch":      epoch,
                "train_loss": round(train_loss, 5),
                "accuracy":   round(m["accuracy"], 5),
                "precision":  round(m["precision"], 5),
                "recall":     round(m["recall"], 5),
                "f1":         round(m["f1"], 5),
                "auc_roc":    round(m["auc_roc"], 5),
            })

            dt = time.time() - t0
            print(f"  E{epoch:02d}  loss={train_loss:.4f}  "
                  f"acc={m['accuracy']:.4f}  pre={m['precision']:.4f}  "
                  f"rec={m['recall']:.4f}  f1={m['f1']:.4f}  auc={m['auc_roc']:.4f}  "
                  f"({dt:.0f}s)")

            if m["f1"] > best_run_f1:
                best_run_f1   = m["f1"]
                best_run_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

        # Eval best checkpoint on test set
        model.load_state_dict(best_run_state)
        labels, preds, probs = evaluate(model, test_loader, device)
        test_m = metrics(labels, preds, probs)

        print(f"\n  Best test — acc={test_m['accuracy']:.4f}  pre={test_m['precision']:.4f}  "
              f"rec={test_m['recall']:.4f}  f1={test_m['f1']:.4f}  auc={test_m['auc_roc']:.4f}")
        cm = test_m["confusion_matrix"]
        print(f"  CM: TN={cm[0][0]}  FP={cm[0][1]} | FN={cm[1][0]}  TP={cm[1][1]}")

        # Fileless held-out evaluation
        held_m = None
        if held_rows:
            held_loader = DataLoader(PNGDataset(held_rows, TRANSFORM_EVAL),
                                     batch_size=BATCH_SIZE, shuffle=False,
                                     num_workers=num_workers)
            hl, hp, hprob = evaluate(model, held_loader, device)
            held_m = metrics(hl, hp, hprob)
            hcm = held_m["confusion_matrix"]
            print(f"  Held-out — acc={held_m['accuracy']:.4f}  pre={held_m['precision']:.4f}  "
                  f"rec={held_m['recall']:.4f}  f1={held_m['f1']:.4f}")
            print(f"  Held CM: TN={hcm[0][0]}  FP={hcm[0][1]} | FN={hcm[1][0]}  TP={hcm[1][1]}")

        run_results.append({
            "run": run, "test": test_m, "fileless": held_m, "history": history,
        })

        if test_m["f1"] > best_global_f1:
            best_global_f1   = test_m["f1"]
            best_global_state = best_run_state

    # ── Save best model ──────────────────────────────────────────────────────
    torch.save(best_global_state, MODEL_PATH)
    print(f"\nSaved model_best.pt  (best run F1={best_global_f1:.4f}) → {MODEL_PATH}")

    # ── 3-run averages ───────────────────────────────────────────────────────
    keys = ["accuracy", "precision", "recall", "f1", "auc_roc"]
    avg = {k: float(np.mean([r["test"][k] for r in run_results])) for k in keys}
    std = {k: float(np.std ([r["test"][k] for r in run_results])) for k in keys}

    fl_avg = fl_std = None
    if all(r["fileless"] for r in run_results):
        fl_avg = {k: float(np.mean([r["fileless"][k] for r in run_results])) for k in keys}
        fl_std = {k: float(np.std ([r["fileless"][k] for r in run_results])) for k in keys}

    report = {
        "model": "ResNet50",
        "epochs": EPOCHS, "lr": LR, "batch_size": BATCH_SIZE,
        "train_samples": len(all_rows),
        "held_out_samples": len(held_rows),
        "runs": run_results,
        "average": avg, "std": std,
        "fileless_generalisation": {"average": fl_avg, "std": fl_std} if fl_avg else None,
        "inference_threshold": 0.50,
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2, default=str))
    print(f"Saved training_report.json → {REPORT_PATH}")

    print(f"\n{'='*60}")
    print("3-Run Average:")
    for k in keys:
        print(f"  {k:12s}: {avg[k]:.4f}  ±{std[k]:.4f}")

    if fl_avg:
        print("\nFileless Generalisation (held-out):")
        for k in keys:
            print(f"  {k:12s}: {fl_avg[k]:.4f}  ±{fl_std[k]:.4f}")

    # ── Training curves ──────────────────────────────────────────────────────
    try:
        import matplotlib.pyplot as plt
        colors = ["#4C72B0", "#DD8452", "#55A868"]
        fig, axes = plt.subplots(1, 2, figsize=(13, 4))
        for i, r in enumerate(run_results):
            epochs = [h["epoch"] for h in r["history"]]
            axes[0].plot(epochs, [h["train_loss"] for h in r["history"]],
                         color=colors[i], label=f"Run {r['run']}")
            axes[1].plot(epochs, [h["f1"] for h in r["history"]],
                         color=colors[i], label=f"Run {r['run']}")
        for ax, title, ylabel in zip(axes, ["Train Loss", "Val F1 (macro)"], ["Loss", "F1"]):
            ax.set_xlabel("Epoch"); ax.set_ylabel(ylabel); ax.set_title(title)
            ax.legend(); ax.grid(alpha=0.3)
            for s in ["top", "right"]: ax.spines[s].set_visible(False)
        plt.tight_layout()
        plt.savefig(CURVES_PATH, dpi=150, bbox_inches="tight")
        print(f"Saved training_curves.png → {CURVES_PATH}")
    except Exception as e:
        print(f"[warn] Could not plot curves: {e}")

    print(f"\nNext step: run python3 scripts/05_inference_api.py [path/to/file.class]")


if __name__ == "__main__":
    main()
