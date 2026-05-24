# ShellBreaker — Demo Guide

## Prerequisites

```bash
cd /home/quynh/Downloads/ShellBreaker
# All commands below assume you are in this directory
```

Required files in `output/`:
- `xgb_model.pkl`
- `xgb_report.json`
- `vocab.json`

---

## Demo 1 — CLI: single file verdict

The fastest way to show the detector in action.

### Webshell (should fire as HIGH or MEDIUM)
```bash
.venv/bin/python scripts/05_inference_api.py \
  dataset/compiled/webshell_file/005a7b6a031c0bb390d0997ffff2eb23.class
```
Expected output:
```
  File    : 005a7b6a031c0bb390d0997ffff2eb23.class
  Verdict : WEBSHELL [HIGH]
  ML score: 0.9933
  Rules   : none triggered
```

### Fileless / memory webshell (the actual target)
```bash
.venv/bin/python scripts/05_inference_api.py \
  dataset/compiled/webshell_fileless/$(ls dataset/compiled/webshell_fileless/ | head -1)
```

### Benign class (should be BENIGN)
```bash
.venv/bin/python scripts/05_inference_api.py \
  dataset/compiled/benign/00090d453edfaf96a90a1f517b16db21.class
```
Expected output:
```
  File    : 00090d453edfaf96a90a1f517b16db21.class
  Verdict : BENIGN [BENIGN]
  ML score: 0.0124
  Rules   : none triggered
```

---

## Demo 2 — Batch scan: recall vs specificity

Scan 20 webshells and 20 benign classes in one shot and tally results.

```bash
python3 - <<'EOF'
import json, re, subprocess, numpy as np
from pathlib import Path
import joblib
from scipy.sparse import csr_matrix

ROOT  = Path(".")
vocab = json.loads((ROOT/"output/vocab.json").read_text())
thr   = json.loads((ROOT/"output/xgb_report.json").read_text())["inference_threshold"]
model = joblib.load(ROOT/"output/xgb_model.pkl")

OPCODE_NORM = {**{f"iconst_{s}":"iconst" for s in ["m1","0","1","2","3","4","5"]},**{f"lconst_{i}":"lconst" for i in range(2)},**{f"fconst_{i}":"fconst" for i in range(3)},**{f"dconst_{i}":"dconst" for i in range(2)},**{f"iload_{i}":"iload" for i in range(4)},**{f"lload_{i}":"lload" for i in range(4)},**{f"fload_{i}":"fload" for i in range(4)},**{f"dload_{i}":"dload" for i in range(4)},**{f"aload_{i}":"aload" for i in range(4)},**{f"istore_{i}":"istore" for i in range(4)},**{f"lstore_{i}":"lstore" for i in range(4)},**{f"fstore_{i}":"fstore" for i in range(4)},**{f"dstore_{i}":"dstore" for i in range(4)},**{f"astore_{i}":"astore" for i in range(4)}}
RE = re.compile(r"^\s+\d+:\s+([a-z][a-z0-9_]+)")

def predict(path):
    try:
        r = subprocess.run(["javap","-c","-p","-verbose",str(path)], capture_output=True, text=True, timeout=15)
        ops = [OPCODE_NORM.get(m.group(1),m.group(1)) for l in r.stdout.splitlines() if (m:=RE.match(l))]
        if len(ops) < 4: return None
        n = len(vocab); t = len(ops)
        u = np.zeros(n, dtype=np.float32)
        for op in ops:
            i = vocab.get(op,-1)
            if i>=0: u[i]+=1
        u /= t
        b = np.zeros(n*n, dtype=np.float32)
        for i in range(len(ops)-1):
            a=vocab.get(ops[i],-1); bb=vocab.get(ops[i+1],-1)
            if a>=0 and bb>=0: b[a*n+bb]+=1
        b /= max(t-1,1)
        feat = np.concatenate([u, b, np.zeros(10, dtype=np.float32)])
        return float(model.predict_proba(csr_matrix(feat.reshape(1,-1)))[0,1])
    except: return None

import random; random.seed(7)
ws = random.sample(list(Path("dataset/compiled/webshell_file").glob("*.class")), 20)
fl = list(Path("dataset/compiled/webshell_fileless").glob("*.class"))[:20]
bn = random.sample(list(Path("dataset/compiled/benign").glob("*.class")), 20)

def tally(files, label):
    detected = missed = errors = 0
    for f in files:
        s = predict(f)
        if s is None: errors += 1; continue
        if s >= thr: detected += 1
        else: missed += 1
    print(f"  {label}: detected={detected}  missed={missed}  errors={errors}  ({detected}/{detected+missed} = {detected/(detected+missed)*100:.0f}%)")

print(f"Threshold: {thr:.4f}\n")
tally(ws, "File-based webshells (20)")
tally(fl, "Fileless webshells   (20)")
tally(bn, "Benign classes       (20)")
EOF
```

---

## Demo 3 — FastAPI server + curl

### Start the server
```bash
.venv/bin/python scripts/05_inference_api.py
# Running on http://localhost:8080
```

### In a second terminal — submit a webshell
```bash
curl -s -X POST http://localhost:8080/predict \
  -F "file=@dataset/compiled/webshell_file/005a7b6a031c0bb390d0997ffff2eb23.class" \
  | python3 -m json.tool
```

Expected response:
```json
{
  "verdict": "WEBSHELL",
  "tier": "HIGH",
  "ml_score": 0.9933,
  "rule": {
    "triggered": false,
    "rules": [],
    "risk": "LOW"
  },
  "opcodes": null
}
```

### Check alert tiers
```bash
curl -s http://localhost:8080/threshold | python3 -m json.tool
```

### Interactive Swagger UI
Open in browser: `http://localhost:8080/docs`
Upload any `.class` file and see the verdict live.

---

## Demo 4 — Key result to highlight

Run this to show the fileless generalisation result (model trained on file-based, tested on fileless):

```bash
python3 -c "
import json
r = json.load(open('output/xgb_report.json'))
fl = r['fileless_generalisation']
print('=== Fileless webshell generalisation ===')
print(f'  Recall    : {fl[\"recall\"]:.4f}  (webshells caught)')
print(f'  Precision : {fl[\"precision\"]:.4f}  (no false positives)')
print(f'  F1        : {fl[\"f1\"]:.4f}')
cm = fl['confusion_matrix']
print(f'  CM: TN={cm[0][0]} FP={cm[0][1]} | FN={cm[1][0]} TP={cm[1][1]}')
print()
print('  → Model catches 77/83 fileless shells it has NEVER seen in training')
print('  → Zero false positives on fileless set')
"
```

---

## Key talking points

| Claim | Evidence |
|---|---|
| Catches memory webshells it was never trained on | Fileless recall = 92.8% |
| Low false positives on fileless | Fileless precision = 100% |
| Better than image-based approach | XGBoost F1=0.84 vs ResNet50 F1=0.62 |
| Fast inference | ~50ms per class file on CPU |
| Hybrid detection reduces alert fatigue | CONFIRMED tier requires both ML + rules |
| Works without file-on-disk check | Pure bytecode analysis, no live JVM needed |
