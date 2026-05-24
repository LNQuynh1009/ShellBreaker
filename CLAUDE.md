# ShellBreaker — Java Memory Webshell Detector

## What this project does
Detect Java fileless webshell (memory horse) injected into running JVM.
Based on paper: GAShellBreaker (Electronics MDPI, 2025), extended with XGBoost + hybrid rule-based detection.

Pipeline:
```
.class bytecode → javap -c -verbose → opcode sequence
→ Feature vector (unigram 149 + bigram 22,201 + metadata 10 = 22,360 dims)
→ XGBoost classifier
→ Rule-based check (c0ny1-derived: Filter/Servlet/Listener interfaces, Runtime.exec, defineClass)
→ Combined tiered verdict: CONFIRMED / HIGH / MEDIUM / BENIGN
```

## Project layout
```
ShellBreaker/
├── CLAUDE.md                      ← you are here
├── REPORT.md                      # project report with full results
├── DEMO.md                        # demo guide with runnable commands
├── requirements.txt               # Python deps
├── .venv/                         # virtualenv (use .venv/bin/python for all scripts)
├── scripts/
│   ├── 01_collect_dataset.sh      # clone webshell/benign repos from GitHub
│   ├── 02_compile_and_filter.py   # compile benign repos → .class, dedup by MD5
│   ├── 02b_categorize.py          # separate webshell repos into file-based/fileless
│   ├── 03_build_grayscale.py      # .class → opcode → adjacency matrix PNG (3 categories)
│   ├── 04_train_resnet50.py       # ResNet50 training (superseded — kept for reference)
│   ├── 04b_train_xgboost.py       # XGBoost training — CURRENT BEST MODEL (runs locally)
│   └── 05_inference_api.py        # FastAPI + CLI: POST .class → tiered verdict JSON
├── agent/                         # Java Agent (Phase 3 — not started)
├── dataset/
│   ├── webshell_src/              # raw cloned repos (webshell, all types)
│   ├── benign_src/                # raw cloned repos (18 repos incl. Tomcat, Spring, Netty)
│   └── compiled/
│       ├── webshell_file/         # deduplicated .class — file-based webshells (train/val)
│       ├── webshell_fileless/     # deduplicated .class — fileless/memory webshells (test only)
│       └── benign/                # deduplicated .class — benign classes (train/val)
├── output/
│   ├── webshell_file/             # grayscale PNGs (label=1, type=webshell_file)
│   ├── webshell_fileless/         # grayscale PNGs (label=1, type=webshell_fileless)
│   ├── benign/                    # grayscale PNGs (label=0)
│   ├── dataset.csv                # path,label,type — 3,106 samples
│   ├── vocab.json                 # 149 opcodes → index mapping
│   ├── xgb_model.pkl              # trained XGBoost model (joblib)
│   ├── xgb_report.json            # metrics: 3 runs + fileless generalisation
│   ├── model_best.pt              # ResNet50 checkpoint (superseded)
│   ├── training_report.json       # ResNet50 metrics (superseded)
│   └── detections.jsonl           # runtime detection log (append-only)
└── notebooks/
    └── colab_train.ipynb          # Google Colab notebook (ResNet50, superseded)
```

## Tech stack
- **Python**: XGBoost, scipy (sparse matrices), joblib, FastAPI, Pillow, scikit-learn, tqdm
- **Java**: JDK 21 (needs `javac` + `javap` on PATH)
- **Training**: runs locally, no GPU needed (~2 min for XGBoost)
- **Java Agent** (Phase 3): Javassist, Maven

## Key design decisions — never change without discussion
- Feature vector: **unigram (149) + bigram (22,201) + metadata (10)** = 22,360 dims
- Bigram matrix is **linear per-image normalised** (`mat / mat.max() * 255`) — NOT log-normalised, NOT raw clamp. Log-normalisation erases visual distinction between classes.
- Opcode vocabulary: **149 opcodes** fixed by JVM Spec Chapter 6 (non-deprecated, short-form variants collapsed)
- **3 independent runs**, average metrics — matches paper methodology
- Fileless webshells are **held out entirely from training** — used only for cross-type generalisation test
- Class imbalance handled by XGBoost `scale_pos_weight = n_benign / n_webshell`
- Threshold optimisation: find lowest threshold where val precision ≥ 0.50, maximising recall
- Alert tiers: CONFIRMED (rule HIGH + ML) > HIGH (ML ≥ 0.85) > MEDIUM > BENIGN
- Rule layer derived from **c0ny1/java-memshell-scanner**: Filter/Servlet/Listener interface check, Runtime.exec, defineClass, URLClassLoader, suspicious class name keywords
- Java Agent uses **both premain + agentmain** mode (unlike copagent which is static only)

## Commands
```bash
# Setup
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Run pipeline (steps 1-3 local, step 4 local too now)
bash scripts/01_collect_dataset.sh
.venv/bin/python scripts/02_compile_and_filter.py
.venv/bin/python scripts/02b_categorize.py
.venv/bin/python scripts/03_build_grayscale.py

# Train XGBoost (local, ~2 min, no GPU)
.venv/bin/python scripts/04b_train_xgboost.py

# Inference — CLI (single file)
.venv/bin/python scripts/05_inference_api.py /path/to/Suspicious.class

# Inference — API server
.venv/bin/python scripts/05_inference_api.py
# → http://localhost:8080/docs

# New .class files added → re-run from step 03 then 04b (not 01)
```

## Dataset
- 523 file-based webshell .class (train/val)
- 83 fileless/memory webshell .class (test only — never seen in training)
- 2,500 benign .class (18 repos: Tomcat, Spring, Netty, Shiro, Struts, Jersey, Hibernate, MyBatis + 10 utility libs)
- Total: 3,106 PNGs + dataset.csv

## Results (XGBoost, 3-run average, post size-filter)

| Threshold | Precision | Recall | F1 | AUC-ROC |
|---|---|---|---|---|
| Default (0.50) | **0.925** ±0.025 | 0.857 ±0.016 | **0.890** ±0.016 | **0.981** ±0.008 |
| High-recall (0.04) | 0.547 ±0.052 | **0.966** ±0.005 | 0.697 ±0.041 | **0.981** ±0.008 |

**Fileless generalisation (never seen in training):** Recall=0.952, Precision=1.000, F1=0.975

**Dataset after quality filter:** 514 webshell_file (76 sub-500B stubs removed), 83 fileless, 2500 benign = 3,097 total

## Current status
- [x] Phase 1: Dataset pipeline (scripts 01-03 + 02b) — complete
- [x] Phase 2: ML pipeline — XGBoost (04b) + inference API (05) complete
- [x] Phase 2: ResNet50 baseline on Colab — complete (superseded by XGBoost)
- [x] Hybrid detection: ML + c0ny1 rule-based layer — complete
- [x] Tiered alerts: CONFIRMED / HIGH / MEDIUM / BENIGN — complete
- [x] Training visualizations (06_visualize.py → output/figures/) — complete
- [x] Lab integration (memshell-lab/shellbreaker/) — complete
  - Watches Tomcat work dir for compiled JSP .class files
  - Sends events to Splunk HEC (index=shellbreaker)
  - Sends email for CONFIRMED/HIGH to jodielieberher@gmail.com
- [ ] Phase 3: Java Agent (agent/ directory) — not started
- [ ] Phase 5: Production hardening — not started

## Conventions
- Always use `.venv/bin/python`, never system Python
- All Python scripts print progress with `tqdm` progress bars
- Every script ends with "Next step: run XX_scriptname"
- Paths always derived from `Path(__file__).parent.parent` (relative to script)
- Never hardcode API keys — use environment variables
- New .class files added → re-run from step 03 then 04b (not 01)

## Reference
- Paper: GAShellBreaker — Electronics MDPI 2025
- Rule-based baseline: c0ny1/java-memshell-scanner (JSP runtime scanner)
- Compared against: copagent (rule-based), JShellDetector, OpenRASP
- Opcode vocabulary: JVM Specification Chapter 6 (149 non-deprecated opcodes)
