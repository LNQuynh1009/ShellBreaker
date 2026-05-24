# ShellBreaker — Model Training Guide

This guide walks you through training the ResNet50 detector on Google Colab (free T4 GPU).
Claude cannot access Colab/Kaggle, so you run these steps yourself.

---

## Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Python | 3.11+ | `python3 --version` |
| Java JDK | 21 | `javac -version` |
| pip packages | see below | `pip install ...` |
| Google account | any | for Drive + Colab |

```bash
pip install torch torchvision pillow tqdm scikit-learn fastapi uvicorn python-multipart requests
```

---

## Overview of the full pipeline

```
Step 1  bash scripts/01_collect_dataset.sh     # clone repos from GitHub
Step 2  python3 scripts/02_compile_and_filter.py  # compile → .class files
Step 3  python3 scripts/03_build_grayscale.py     # .class → 149×149 PNG
Step 4  *** COLAB *** notebooks/colab_train.ipynb # fine-tune ResNet50
Step 5  python3 scripts/05_inference_api.py        # serve the model
```

Steps 1–3 run locally. Step 4 runs on Colab. Step 5 runs locally after you download the model.

---

## Step-by-step

### 1. Prepare data locally (Steps 1–3)

```bash
cd /path/to/ShellBreaker

# Collect dataset (~10-30 min depending on GitHub rate limit)
bash scripts/01_collect_dataset.sh

# Compile benign repos → .class, dedup by MD5, augment with Maven Central JARs
python3 scripts/02_compile_and_filter.py

# Separate webshell repos into file-based and fileless categories
# Downloads ysoserial-all.jar from GitHub releases if file-based count < 383
python3 scripts/02b_categorize.py

# Generate 149×149 PNGs + dataset.csv + vocab.json
python3 scripts/03_build_grayscale.py
```

After Step 3 you should have:
```
output/
  webshell_file/    ← 485 PNG files  (label=1, type=webshell_file)   — 383 in CSV (train/val)
  webshell_fileless/←  83 PNG files  (label=1, type=webshell_fileless)—  56 in CSV (test only)
  benign/           ← 3923 PNG files (label=0)                        — 968 in CSV (train/val)
  dataset.csv                         (1407 rows: 383+56+968)
  vocab.json                          (149 opcodes → 149×149 matrix)
```

**Three-category dataset design:**
- **webshell_file** (file-based webshells): ysoserial, marshalsec, learnjavabug, etc.  
  Used for training and validation. Model learns to detect file-based attack patterns.
- **webshell_fileless** (memory/fileless webshells): java-memshell-generator, copagent, etc.  
  Held out as a separate test set. Measures cross-type generalisation — can a model trained
  on file-based shells detect fileless/memory shells it was never trained on?
- **benign**: Apache Commons, Guava, Jackson, Spring, etc.  
  Provides negative examples for training.

**Current dataset stats (in dataset.csv, after sampling):**
- 383 file-based webshell PNGs (sampled from 485 generated — ysoserial, marshalsec, learnjavabug, etc.)
- 56 fileless webshell PNGs (sampled from 83 valid memory-webshell PNGs)
- 968 benign PNGs (sampled from 3923 available PNGs)
- **Total: 1,407 rows in dataset.csv — exactly matching the GAShellBreaker paper**
- Matrix size: exactly 149×149, matching the GAShellBreaker paper

Maven-compiled repos: ysoserial (+61 classes), marshalsec (+63), learnjavabug (+160).

**To improve results:** Collect more webshell repos in step 01 to increase webshell count.

---

### 2. Package output/ for upload

```bash
cd /path/to/ShellBreaker

# Zip the output folder (PNGs + CSV + vocab)
zip -r output.zip output/

# Also copy the training script
cp scripts/04_train_resnet50.py .
```

Upload both files to **Google Drive** in a folder called `ShellBreaker/`:
```
MyDrive/
  ShellBreaker/
    output.zip          ← ~50-500 MB depending on dataset size
    04_train_resnet50.py
```

---

### 3. Train on Google Colab

1. Go to **https://colab.research.google.com**
2. File → Upload notebook → select `notebooks/colab_train.ipynb`
3. Runtime → Change runtime type → **T4 GPU** → Save
4. Edit the `DRIVE_BASE` variable in Cell 1 if your Drive path differs
5. **Run all cells** (Runtime → Run all, or Shift+Enter through each cell)

#### What the notebook does

| Cell | Action |
|------|--------|
| Step 1 | Mount Google Drive |
| Step 2 | Install scikit-learn, tqdm (torch is pre-installed) |
| Step 3 | Unzip output.zip to /content/ShellBreaker |
| Step 4 | Show 8 sample PNGs so you can sanity-check |
| Step 5 | Patch script path, then run `04_train_resnet50.py` |
| Step 6 | Print per-run metrics + plot training curves + confusion matrix |
| Step 7 | Copy `model_best.pt` and `training_report.json` back to Drive |

#### Training time estimate (T4 GPU)

| Dataset size | Estimated time |
|-------------|---------------|
| 500 images | ~5–10 min |
| 2,000 images | ~15–25 min |
| 10,000 images | ~60–90 min |

---

### 4. Download results

After the notebook finishes, go to `MyDrive/ShellBreaker/results/` and download:
- `model_best.pt` → put in `output/model_best.pt` locally
- `training_report.json` → put in `output/training_report.json` locally

---

### 5. Verify the model locally

```bash
python3 scripts/05_inference_api.py
# → open http://localhost:8080/docs
# → POST a .class file and check the verdict
```

---

## Alternative: Kaggle (if Colab is too slow)

Kaggle gives you **30 hours/week** of free P100 GPU, which is faster than T4.

1. Go to **https://www.kaggle.com/code** → New Notebook
2. Settings → Accelerator → **GPU P100**
3. Add dataset: Upload `output.zip` as a Kaggle dataset
4. In the notebook:
```python
import os, zipfile

# Kaggle dataset is mounted at /kaggle/input/
with zipfile.ZipFile('/kaggle/input/shellbreaker-output/output.zip') as z:
    z.extractall('/kaggle/working/ShellBreaker')

os.chdir('/kaggle/working/ShellBreaker')
!python 04_train_resnet50.py
```
5. Download output files from the "Output" tab after the run

---

## Evaluation Criteria

### Target metrics (from the GAShellBreaker paper)

| Metric | Paper result | Acceptable minimum | Meaning |
|--------|-----------|--------------------|---------|
| **Accuracy** | ≥ 97% | ≥ 90% | Overall correct predictions |
| **Precision** | ≥ 95% | ≥ 85% | Of predicted webshells, how many are real |
| **Recall** | ≥ 96% | ≥ 85% | Of real webshells, how many are caught |
| **F1** | ≥ 96% | ≥ 88% | Harmonic mean of precision and recall |
| **AUC-ROC** | ≥ 0.98 | ≥ 0.92 | Ranking quality across thresholds |

### What each metric means for security

**Precision (False Positive Rate)**
- Low precision = many benign classes flagged as webshells = alert fatigue
- If precision < 85%, security team will ignore the alerts

**Recall (False Negative Rate)**
- Low recall = real webshells are missed = dangerous
- Recall is more important than precision for a security tool
- Target: recall ≥ 95% (missing 1 in 20 webshells is the acceptable floor)

**F1**
- Primary metric used for early stopping and model selection in the training script
- Balances precision and recall — use this as the single headline number

**AUC-ROC**
- Threshold-independent: good to verify the model actually learns signal
- If AUC-ROC < 0.85, the model is barely better than random regardless of threshold

### Reading training_report.json

```json
{
  "runs": [
    {
      "run": 1,
      "test": {
        "accuracy": 0.9712,
        "precision": 0.9634,
        "recall": 0.9801,
        "f1": 0.9717,
        "auc_roc": 0.9901
      },
      "confusion_matrix": [[TN, FP], [FN, TP]]
    }
  ],
  "average": { "f1": 0.9698, ... },
  "std":     { "f1": 0.0021, ... }
}
```

**Confusion matrix interpretation:**
```
               Predicted
               benign   webshell
Actual benign   [TN]     [FP]    ← FP = false alarms
       webshell [FN]     [TP]    ← FN = missed webshells (most dangerous)
```

**Std deviation across 3 runs:**
- std F1 < 0.01 → training is stable, results are reliable
- std F1 > 0.05 → high variance; collect more data or tune hyperparameters

### Decision checklist before deploying the model

- [ ] Average F1 ≥ 0.88 across 3 runs
- [ ] Average recall ≥ 0.90 (FN rate ≤ 10%)
- [ ] AUC-ROC ≥ 0.92
- [ ] Std F1 < 0.03 (stable training)
- [ ] Confusion matrix: FN count ≤ 10% of actual webshell samples
- [ ] Ran inference on at least 5 known webshell .class files manually and got "webshell" verdict

### If results are below target

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| Recall < 85% | Too few webshell training samples | Collect more webshell repos (step 01) |
| Precision < 80% | Too few benign samples | Add more benign Java projects |
| F1 not improving after epoch 5 | LR too high or frozen too many layers | Lower `LR_HEAD` to 5e-4 |
| val_f1 oscillates wildly | Batch size too small | Increase `BATCH_SIZE` to 64 |
| AUC-ROC < 0.85 but F1 ok | Threshold 0.70 is wrong for your data | Tune threshold in 05_inference_api.py |
| std > 0.05 | Not enough data | Collect more; or increase `NUM_EPOCHS` |

---

## Hyperparameter tuning (optional)

To change training settings, edit these constants at the top of `04_train_resnet50.py`:

```python
NUM_EPOCHS = 30      # increase if val_f1 still improving at epoch 30
BATCH_SIZE = 32      # T4 can handle 64 if you have >2k images
LR_HEAD    = 1e-3    # reduce to 5e-4 if loss oscillates
LR_BACKBONE= 1e-4    # reduce to 5e-5 to slow backbone updates
PATIENCE   = 7       # increase to 10 if training is noisy
```

---

## Output files summary

| File | Size | Description |
|------|------|-------------|
| `output/model_best.pt` | ~100 MB | Best ResNet50 checkpoint (by test F1) |
| `output/training_report.json` | ~10 KB | Per-run + averaged metrics |
| `output/training_curves.png` | ~50 KB | Val F1 / AUC-ROC / loss per epoch |
| `output/confusion_matrix.png` | ~30 KB | Confusion matrix for best run |
