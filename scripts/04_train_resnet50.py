#!/usr/bin/env python3
"""
04_train_resnet50.py — Fine-tune ResNet50 on grayscale opcode-matrix PNGs.

Runs 3 independent training sessions and averages metrics (paper methodology).
Outputs: output/model_best.pt, output/training_report.json
"""

import json
import random
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler
from torchvision import models, transforms
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
DATASET_CSV = ROOT / "output" / "dataset.csv"
OUTPUT_DIR = ROOT / "output"
MODEL_PATH = OUTPUT_DIR / "model_best.pt"
REPORT_PATH = OUTPUT_DIR / "training_report.json"

# ---------------------------------------------------------------------------
# Hyper-parameters (change freely — these match paper defaults)
# ---------------------------------------------------------------------------
NUM_CLASSES = 2
NUM_RUNS = 3
NUM_EPOCHS = 60        # more epochs needed for small/imbalanced dataset
BATCH_SIZE = 32
LR_HEAD = 1e-3
LR_BACKBONE = 1e-4
WEIGHT_DECAY = 1e-4
PATIENCE = 15          # more patience for imbalanced data
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
# TEST_RATIO = 0.15


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------
# ImageNet normalisation — used even though input is grayscale converted to RGB
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD = [0.229, 0.224, 0.225]

TRAIN_TRANSFORMS = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.Grayscale(num_output_channels=1),
    transforms.RandomHorizontalFlip(),
    transforms.RandomVerticalFlip(),
    transforms.RandomRotation(10),
    transforms.ToTensor(),
    transforms.Lambda(lambda x: x.repeat(3, 1, 1)),   # 1ch → 3ch
    transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
])

EVAL_TRANSFORMS = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.Grayscale(num_output_channels=1),
    transforms.ToTensor(),
    transforms.Lambda(lambda x: x.repeat(3, 1, 1)),
    transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
])


class OpcodeMatrixDataset(Dataset):
    def __init__(self, samples: list[tuple[Path, int]], transform=None):
        self.samples = samples
        self.transform = transform

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        img_path, label = self.samples[idx]
        img = Image.open(img_path).convert("L")   # load as grayscale
        if self.transform:
            img = self.transform(img)
        return img, label


def load_dataset_csv(csv_path: Path) -> tuple[list, list]:
    """
    Return (trainval_samples, fileless_test_samples).

    trainval_samples: (path, label) for webshell_file + benign  → used for train/val/test splits
    fileless_test_samples: (path, label=1) for webshell_fileless → evaluated separately

    CSV columns: path, label, type, class
    Old CSVs without a 'type' column are treated as having type=webshell_file for label=1.
    """
    import csv as _csv
    trainval, fileless = [], []
    with open(csv_path, newline="") as f:
        reader = _csv.DictReader(f)
        has_type = "type" in (reader.fieldnames or [])
        for row in reader:
            img_path = Path(row["path"])
            label = int(row["label"])
            type_name = row.get("type", "webshell_file" if label == 1 else "benign") if has_type else (
                "webshell_file" if label == 1 else "benign"
            )
            if not img_path.is_absolute():
                img_path = ROOT / img_path
            if not img_path.exists():
                print(f"  [warn] missing PNG: {img_path}")
                continue
            sample = (img_path, label)
            if type_name == "webshell_fileless":
                fileless.append(sample)
            else:
                trainval.append(sample)
    return trainval, fileless


def split_dataset(samples, train_r, val_r, seed):
    rng = random.Random(seed)
    data = list(samples)
    rng.shuffle(data)
    n = len(data)
    n_train = int(n * train_r)
    n_val = int(n * val_r)
    train = data[:n_train]
    val = data[n_train:n_train + n_val]
    test = data[n_train + n_val:]
    return train, val, test


def make_sampler(samples):
    labels = [s[1] for s in samples]
    class_counts = np.bincount(labels)
    class_weights = 1.0 / class_counts
    sample_weights = [class_weights[l] for l in labels]
    return WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(sample_weights),
        replacement=True,
    )


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def build_model(device):
    model = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V2)
    # Freeze all backbone layers first
    for param in model.parameters():
        param.requires_grad = False
    # Replace the classification head
    in_features = model.fc.in_features
    model.fc = nn.Sequential(
        nn.Dropout(0.5),
        nn.Linear(in_features, 256),
        nn.ReLU(),
        nn.Dropout(0.3),
        nn.Linear(256, NUM_CLASSES),
    )
    # Unfreeze layer3, layer4, and the new head for fine-tuning
    for name, param in model.named_parameters():
        if any(name.startswith(p) for p in ("layer3", "layer4", "fc")):
            param.requires_grad = True
    return model.to(device)


def make_optimizer(model):
    backbone_params = [
        p for n, p in model.named_parameters()
        if p.requires_grad and not n.startswith("fc")
    ]
    head_params = [
        p for n, p in model.named_parameters()
        if p.requires_grad and n.startswith("fc")
    ]
    return torch.optim.AdamW([
        {"params": backbone_params, "lr": LR_BACKBONE},
        {"params": head_params, "lr": LR_HEAD},
    ], weight_decay=WEIGHT_DECAY)


# ---------------------------------------------------------------------------
# Train / eval loops
# ---------------------------------------------------------------------------

def compute_class_weights(samples, device):
    labels = [s[1] for s in samples]
    counts = np.bincount(labels, minlength=NUM_CLASSES).astype(float)
    weights = 1.0 / (counts / counts.sum())
    weights /= weights.sum()
    return torch.tensor(weights, dtype=torch.float32, device=device)


def train_one_epoch(model, loader, criterion, optimizer, device, scaler):
    model.train()
    total_loss, correct, total = 0.0, 0, 0
    for imgs, labels in tqdm(loader, desc="  train", leave=False):
        imgs, labels = imgs.to(device), labels.to(device)
        optimizer.zero_grad()
        with torch.autocast(device_type=device.type, enabled=scaler is not None):
            logits = model(imgs)
            loss = criterion(logits, labels)
        if scaler:
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            optimizer.step()
        total_loss += loss.item() * len(labels)
        correct += (logits.argmax(1) == labels).sum().item()
        total += len(labels)
    return total_loss / total, correct / total


@torch.no_grad()
def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss, all_preds, all_labels, all_probs = 0.0, [], [], []
    for imgs, labels in tqdm(loader, desc="  eval ", leave=False):
        imgs, labels = imgs.to(device), labels.to(device)
        logits = model(imgs)
        loss = criterion(logits, labels)
        probs = torch.softmax(logits, dim=1)[:, 1]
        total_loss += loss.item() * len(labels)
        all_preds.extend(logits.argmax(1).cpu().numpy())
        all_labels.extend(labels.cpu().numpy())
        all_probs.extend(probs.cpu().numpy())
    n = len(all_labels)
    metrics = {
        "loss": total_loss / n,
        "accuracy": accuracy_score(all_labels, all_preds),
        "precision": precision_score(all_labels, all_preds, zero_division=0),
        "recall": recall_score(all_labels, all_preds, zero_division=0),
        "f1": f1_score(all_labels, all_preds, zero_division=0),
        "auc_roc": roc_auc_score(all_labels, all_probs),
    }
    return metrics, all_preds, all_labels, all_probs


# ---------------------------------------------------------------------------
# Single run
# ---------------------------------------------------------------------------

def run_once(run_id: int, all_samples, device) -> dict:
    print(f"\n{'='*60}")
    print(f"  RUN {run_id + 1} / {NUM_RUNS}")
    print(f"{'='*60}")

    seed = 42 + run_id * 17
    torch.manual_seed(seed)
    np.random.seed(seed)

    train_s, val_s, test_s = split_dataset(all_samples, TRAIN_RATIO, VAL_RATIO, seed)
    print(f"  Split — train: {len(train_s)}, val: {len(val_s)}, test: {len(test_s)}")

    train_loader = DataLoader(
        OpcodeMatrixDataset(train_s, TRAIN_TRANSFORMS),
        batch_size=BATCH_SIZE,
        sampler=make_sampler(train_s),
        num_workers=2,
        pin_memory=True,
    )
    val_loader = DataLoader(
        OpcodeMatrixDataset(val_s, EVAL_TRANSFORMS),
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=2,
        pin_memory=True,
    )
    test_loader = DataLoader(
        OpcodeMatrixDataset(test_s, EVAL_TRANSFORMS),
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=2,
        pin_memory=True,
    )

    model = build_model(device)
    class_weights = compute_class_weights(train_s, device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = make_optimizer(model)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=NUM_EPOCHS)
    scaler = torch.GradScaler() if device.type == "cuda" else None

    best_val_f1 = -1.0
    best_state = None
    patience_counter = 0
    history = []

    for epoch in range(1, NUM_EPOCHS + 1):
        t0 = time.time()
        train_loss, train_acc = train_one_epoch(model, train_loader, criterion, optimizer, device, scaler)
        val_metrics, _, _, _ = evaluate(model, val_loader, criterion, device)
        scheduler.step()

        elapsed = time.time() - t0
        print(
            f"  Epoch {epoch:02d}/{NUM_EPOCHS} | "
            f"train_loss={train_loss:.4f} acc={train_acc:.3f} | "
            f"val_loss={val_metrics['loss']:.4f} f1={val_metrics['f1']:.3f} "
            f"auc={val_metrics['auc_roc']:.3f} | {elapsed:.1f}s"
        )

        history.append({
            "epoch": epoch,
            "train_loss": round(train_loss, 4),
            "train_acc": round(train_acc, 4),
            **{f"val_{k}": round(v, 4) for k, v in val_metrics.items()},
        })

        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_counter = 0
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"  Early stop at epoch {epoch} (no val-F1 improvement for {PATIENCE} epochs)")
                break

    # Evaluate best checkpoint on test set
    model.load_state_dict(best_state)
    test_metrics, test_preds, test_labels, test_probs = evaluate(model, test_loader, criterion, device)
    cm = confusion_matrix(test_labels, test_preds).tolist()

    print(f"\n  Test results (run {run_id + 1}, default threshold=0.50):")
    print(classification_report(test_labels, test_preds, target_names=["benign", "webshell"]))
    print(f"  AUC-ROC: {test_metrics['auc_roc']:.4f}")
    print(f"  Confusion matrix:\n    TN={cm[0][0]}  FP={cm[0][1]}\n    FN={cm[1][0]}  TP={cm[1][1]}")

    # Find optimal threshold on validation set: maximize recall s.t. precision >= 0.50
    _, _, val_labels_t, val_probs_t = evaluate(model, val_loader, criterion, device)
    prec_curve, rec_curve, thresh_curve = precision_recall_curve(val_labels_t, val_probs_t)
    mask = prec_curve[:-1] >= 0.50
    if mask.any():
        opt_threshold = float(thresh_curve[mask][np.argmax(rec_curve[:-1][mask])])
    else:
        opt_threshold = 0.35  # fall back low to keep recall high

    test_preds_opt = (np.array(test_probs) >= opt_threshold).astype(int)
    cm_opt = confusion_matrix(test_labels, test_preds_opt).tolist()
    test_metrics_opt = {
        "threshold": round(opt_threshold, 4),
        "accuracy":  round(accuracy_score(test_labels, test_preds_opt), 4),
        "precision": round(precision_score(test_labels, test_preds_opt, zero_division=0), 4),
        "recall":    round(recall_score(test_labels, test_preds_opt, zero_division=0), 4),
        "f1":        round(f1_score(test_labels, test_preds_opt, zero_division=0), 4),
        "auc_roc":   round(roc_auc_score(test_labels, test_probs), 4),
    }

    print(f"\n  Threshold-optimised results (threshold={opt_threshold:.4f}, precision>=0.50 constraint):")
    print(classification_report(test_labels, test_preds_opt, target_names=["benign", "webshell"]))
    print(f"  CM: TN={cm_opt[0][0]}  FP={cm_opt[0][1]}\n    FN={cm_opt[1][0]}  TP={cm_opt[1][1]}")

    return {
        "run": run_id + 1,
        "seed": seed,
        "best_val_f1": round(best_val_f1, 4),
        "opt_threshold": round(opt_threshold, 4),
        "test": {k: round(v, 4) for k, v in test_metrics.items()},
        "test_opt": test_metrics_opt,
        "confusion_matrix": cm,
        "confusion_matrix_opt": cm_opt,
        "best_model_state": best_state,
        "history": history,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")
    if device.type == "cuda":
        print(f"  GPU: {torch.cuda.get_device_name(0)}")

    if not DATASET_CSV.exists():
        raise FileNotFoundError(
            f"dataset.csv not found at {DATASET_CSV}\n"
            "Run scripts/03_build_grayscale.py first."
        )

    print(f"\nLoading dataset from {DATASET_CSV}...")
    trainval_samples, fileless_samples = load_dataset_csv(DATASET_CSV)
    if not trainval_samples:
        raise RuntimeError("No valid train/val samples found in dataset.csv")

    labels = [s[1] for s in trainval_samples]
    n_webshell = sum(1 for l in labels if l == 1)
    n_benign = len(labels) - n_webshell
    print(f"  Train/val pool: {len(trainval_samples)} samples — webshell_file: {n_webshell}, benign: {n_benign}")
    print(f"  Fileless test:  {len(fileless_samples)} samples (held-out, not used for training)")

    run_results = []
    best_overall_f1 = -1.0
    best_overall_state = None

    for run_id in range(NUM_RUNS):
        result = run_once(run_id, trainval_samples, device)
        run_results.append(result)

        if result["test"]["f1"] > best_overall_f1:
            best_overall_f1 = result["test"]["f1"]
            best_overall_state = result["best_model_state"]

        # Save best model so far after each run (safe checkpoint)
        torch.save(best_overall_state, MODEL_PATH)
        print(f"  Saved best model → {MODEL_PATH}")

    # Evaluate best model on fileless test set (cross-type generalisation)
    fileless_eval = {}
    if fileless_samples and best_overall_state is not None:
        print(f"\n  Evaluating cross-type generalisation on {len(fileless_samples)} fileless samples...")
        from torch.utils.data import DataLoader as _DL
        model_eval = build_model(device)
        model_eval.load_state_dict(best_overall_state)
        fl_loader = _DL(
            OpcodeMatrixDataset(fileless_samples, EVAL_TRANSFORMS),
            batch_size=BATCH_SIZE, shuffle=False, num_workers=2,
        )
        dummy_labels_trainval = [s[1] for s in trainval_samples]
        dummy_counts = np.bincount(dummy_labels_trainval, minlength=NUM_CLASSES).astype(float)
        dummy_weights = torch.tensor(
            1.0 / (dummy_counts / dummy_counts.sum()),
            dtype=torch.float32, device=device,
        )
        fl_criterion = nn.CrossEntropyLoss(weight=dummy_weights)
        fl_metrics, fl_preds, fl_labels, _ = evaluate(model_eval, fl_loader, fl_criterion, device)
        from sklearn.metrics import confusion_matrix as _cm
        fl_cm = _cm(fl_labels, fl_preds).tolist()
        fileless_eval = {k: round(v, 4) for k, v in fl_metrics.items()}
        fileless_eval["confusion_matrix"] = fl_cm
        print(f"  Fileless recall (webshell detection rate): {fl_metrics['recall']:.4f}")
        print(f"  Fileless confusion: {fl_cm}")

    # Aggregate metrics over 3 runs (both default-threshold and optimised-threshold)
    metric_keys = ["accuracy", "precision", "recall", "f1", "auc_roc", "loss"]
    opt_metric_keys = ["accuracy", "precision", "recall", "f1", "auc_roc"]
    averages, stdevs, averages_opt, stdevs_opt = {}, {}, {}, {}
    for k in metric_keys:
        vals = [r["test"][k] for r in run_results]
        averages[k] = round(float(np.mean(vals)), 4)
        stdevs[k]   = round(float(np.std(vals)),  4)
    for k in opt_metric_keys:
        vals = [r["test_opt"][k] for r in run_results]
        averages_opt[k] = round(float(np.mean(vals)), 4)
        stdevs_opt[k]   = round(float(np.std(vals)),  4)
    avg_threshold = round(float(np.mean([r["opt_threshold"] for r in run_results])), 4)

    report = {
        "num_runs": NUM_RUNS,
        "num_epochs_max": NUM_EPOCHS,
        "batch_size": BATCH_SIZE,
        "patience": PATIENCE,
        "inference_threshold": avg_threshold,
        "dataset": {
            "trainval_file_webshell": n_webshell,
            "trainval_benign": n_benign,
            "fileless_test": len(fileless_samples),
        },
        "runs": [
            {
                "run": r["run"],
                "seed": r["seed"],
                "best_val_f1": r["best_val_f1"],
                "opt_threshold": r["opt_threshold"],
                "test": r["test"],
                "test_opt": r["test_opt"],
                "confusion_matrix": r["confusion_matrix"],
                "confusion_matrix_opt": r["confusion_matrix_opt"],
                "epochs_trained": len(r["history"]),
                "history": r["history"],
            }
            for r in run_results
        ],
        "average": averages,
        "std": stdevs,
        "average_opt": averages_opt,
        "std_opt": stdevs_opt,
        "fileless_generalisation": fileless_eval,
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nTraining report saved → {REPORT_PATH}")

    # Final summary
    print("\n" + "=" * 60)
    print("FINAL SUMMARY (average across 3 runs — file-based test set)")
    print("=" * 60)
    print("  Default threshold (0.50):")
    for k in metric_keys:
        print(f"    {k:12s}: {averages[k]:.4f}  ±{stdevs[k]:.4f}")
    print(f"\n  Threshold-optimised (avg threshold={avg_threshold:.4f}, precision>=0.50):")
    for k in opt_metric_keys:
        print(f"    {k:12s}: {averages_opt[k]:.4f}  ±{stdevs_opt[k]:.4f}")
    if fileless_eval:
        print("\n  Cross-type generalisation (fileless webshells, never seen in training):")
        for k in ["recall", "precision", "f1", "auc_roc"]:
            v = fileless_eval.get(k, float("nan"))
            print(f"  fileless {k:8s}: {v:.4f}")
    print("=" * 60)
    print(f"Best model (by test F1={best_overall_f1:.4f}) saved to {MODEL_PATH}")
    print("\nNext step: run scripts/05_inference_api.py")


if __name__ == "__main__":
    main()
