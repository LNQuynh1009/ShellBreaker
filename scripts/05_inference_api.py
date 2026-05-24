#!/usr/bin/env python3
"""
05_inference_api.py — Hybrid Java webshell detector: XGBoost + rule-based.

ML layer: XGBoost on opcode unigram + bigram + metadata features.
Rule layer (c0ny1-derived): servlet/filter/listener interfaces, exec/reflect
  patterns, suspicious class names, missing SourceFile attribute.

Combined verdict tiers:
  CONFIRMED  rule HIGH  + ML >= threshold  → alert immediately
  HIGH       ML score  >= HIGH_THRESHOLD   → alert immediately
  MEDIUM     ML >= threshold OR rule fired → queue for review
  BENIGN     neither                       → ignore

POST /predict  multipart: file=<.class bytes>
GET  /threshold
"""

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT        = Path(__file__).parent.parent
MODEL_PATH  = ROOT / "output" / "xgb_model.pkl"
REPORT_PATH = ROOT / "output" / "xgb_report.json"
VOCAB_JSON  = ROOT / "output" / "vocab.json"
LOG_PATH    = ROOT / "output" / "detections.jsonl"

HIGH_THRESHOLD = 0.85

def load_inference_threshold() -> float:
    try:
        return float(json.loads(REPORT_PATH.read_text()).get("inference_threshold", 0.50))
    except Exception:
        return 0.50

# ---------------------------------------------------------------------------
# Opcode normalisation (must match 03_build_grayscale.py / 04b exactly)
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
_OPCODE_RE  = re.compile(r"^\s+\d+:\s+([a-z][a-z0-9_]+)")
INVOKE_OPS  = {"invokevirtual","invokespecial","invokestatic","invokeinterface","invokedynamic"}
REFLECT_OPS = {"invokevirtual","invokedynamic"}

# ---------------------------------------------------------------------------
# Feature extraction (identical to 04b_train_xgboost.py)
# ---------------------------------------------------------------------------

def disassemble(class_path: Path) -> tuple[list[str] | None, str]:
    try:
        r = subprocess.run(
            ["javap", "-c", "-p", "-verbose", str(class_path)],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return None, ""
        ops = []
        for line in r.stdout.splitlines():
            m = _OPCODE_RE.match(line)
            if m:
                ops.append(OPCODE_NORM.get(m.group(1), m.group(1)))
        return (ops if ops else None), r.stdout
    except Exception:
        return None, ""


def extract_features(class_path: Path, vocab: dict[str, int]) -> np.ndarray | None:
    ops, javap_text = disassemble(class_path)
    if ops is None or len(ops) < 4:
        return None, javap_text

    n     = len(vocab)
    total = len(ops)

    unigram = np.zeros(n, dtype=np.float32)
    for op in ops:
        idx = vocab.get(op, -1)
        if idx >= 0:
            unigram[idx] += 1
    unigram /= total

    bigram = np.zeros(n * n, dtype=np.float32)
    for i in range(len(ops) - 1):
        a = vocab.get(ops[i], -1)
        b = vocab.get(ops[i + 1], -1)
        if a >= 0 and b >= 0:
            bigram[a * n + b] += 1
    bigram /= max(total - 1, 1)

    SERVLET_IFACES = {
        "javax/servlet/Filter","javax/servlet/Servlet","javax/servlet/http/HttpServlet",
        "javax/servlet/ServletRequestListener","javax/servlet/http/HttpSessionListener",
        "jakarta/servlet/Filter","jakarta/servlet/Servlet","jakarta/servlet/http/HttpServlet",
    }
    invoke_cnt  = sum(1 for op in ops if op in INVOKE_OPS)
    reflect_cnt = sum(1 for op in ops if op in REFLECT_OPS)
    athrow_cnt  = ops.count("athrow")
    meta = np.array([
        min(total / 1000.0, 1.0),
        float("SourceFile:" in javap_text),
        float("$" in class_path.stem),
        float(any(iface in javap_text for iface in SERVLET_IFACES)),
        float("java/lang/Runtime" in javap_text),
        float("defineClass" in javap_text),
        float("java/net/URLClassLoader" in javap_text),
        invoke_cnt  / total,
        reflect_cnt / total,
        athrow_cnt  / total,
    ], dtype=np.float32)

    return np.concatenate([unigram, bigram, meta]), javap_text

# ---------------------------------------------------------------------------
# Rule-based layer (c0ny1-derived)
# ---------------------------------------------------------------------------
_WEBSHELL_INTERFACES = {
    "javax/servlet/Filter","javax/servlet/Servlet","javax/servlet/http/HttpServlet",
    "javax/servlet/ServletRequestListener","javax/servlet/http/HttpSessionListener",
    "javax/servlet/ServletContextListener",
    "jakarta/servlet/Filter","jakarta/servlet/Servlet","jakarta/servlet/http/HttpServlet",
}
_SUSPICIOUS_KEYWORDS = [
    "shell","cmd","exec","backdoor","payload","webshell",
    "memshell","agent","inject","exploit","hack","evil",
    "godzilla","behinder","regeorg",
]
_DANGER_PATTERNS = [
    re.compile(r"java/lang/Runtime.*exec|ProcessBuilder", re.IGNORECASE),
    re.compile(r"defineClass",                            re.IGNORECASE),
    re.compile(r"java/net/URLClassLoader",                re.IGNORECASE),
]

def rule_check(class_path: Path, javap_text: str) -> dict:
    rules = []
    for iface in _WEBSHELL_INTERFACES:
        if iface in javap_text:
            rules.append(f"implements {iface.split('/')[-1]}")
    stem = class_path.stem.lower()
    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in stem:
            rules.append(f"name:{kw}")
    for pat in _DANGER_PATTERNS:
        if pat.search(javap_text):
            rules.append(f"danger:{pat.pattern[:35]}")
    if "SourceFile:" not in javap_text and "$" not in class_path.stem:
        rules.append("no SourceFile")
    if not rules:
        return {"triggered": False, "rules": [], "risk": "LOW"}
    risk = "HIGH" if (any("implements" in r for r in rules) and
                      any("danger" in r for r in rules)) else "MEDIUM"
    return {"triggered": True, "rules": rules, "risk": risk}

# ---------------------------------------------------------------------------
# Combined verdict
# ---------------------------------------------------------------------------

def combined_verdict(ml_score: float, rule: dict, inf_threshold: float) -> tuple[str, str]:
    rule_high   = rule["triggered"] and rule["risk"] == "HIGH"
    rule_medium = rule["triggered"] and rule["risk"] == "MEDIUM"
    ml_high     = ml_score >= HIGH_THRESHOLD
    ml_medium   = ml_score >= inf_threshold
    if rule_high and ml_medium:
        return "WEBSHELL", "CONFIRMED"
    if ml_high:
        return "WEBSHELL", "HIGH"
    if ml_medium or rule_high or rule_medium:
        return "WEBSHELL", "MEDIUM"
    return "BENIGN", "BENIGN"

# ---------------------------------------------------------------------------
# Predictor
# ---------------------------------------------------------------------------

class Predictor:
    def __init__(self):
        print(f"Loading XGBoost model from {MODEL_PATH}")
        self.model         = joblib.load(MODEL_PATH)
        self.vocab         = json.loads(VOCAB_JSON.read_text())
        self.inf_threshold = load_inference_threshold()
        print(f"  Inference threshold : {self.inf_threshold:.4f}")
        print(f"  HIGH threshold      : {HIGH_THRESHOLD:.2f}")

    def predict(self, class_path: Path) -> dict:
        result = extract_features(class_path, self.vocab)
        feats, javap_text = result if isinstance(result, tuple) else (result, "")

        if feats is None:
            return {
                "verdict": "ERROR", "tier": "ERROR",
                "ml_score": None,
                "rule": {"triggered": False, "rules": [], "risk": "LOW"},
                "reason": "javap failed or too few opcodes",
            }

        X       = csr_matrix(feats.reshape(1, -1))
        ml_score = float(self.model.predict_proba(X)[0, 1])
        rule     = rule_check(class_path, javap_text)
        verdict, tier = combined_verdict(ml_score, rule, self.inf_threshold)

        return {
            "verdict":  verdict,
            "tier":     tier,
            "ml_score": round(ml_score, 4),
            "rule":     rule,
            "opcodes":  None,
        }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cli_mode(class_file: str):
    path = Path(class_file)
    if not path.exists():
        print(f"File not found: {path}"); sys.exit(1)

    predictor = Predictor()
    result    = predictor.predict(path)

    colours = {"CONFIRMED":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m",
               "BENIGN":"\033[92m","ERROR":"\033[90m"}
    c = colours.get(result["tier"], ""); rst = "\033[0m"

    print(f"\n  File    : {path.name}")
    print(f"  Verdict : {c}{result['verdict']} [{result['tier']}]{rst}")
    print(f"  ML score: {result['ml_score']}")
    rule = result["rule"]
    if rule["triggered"]:
        print(f"  Rules   : [{rule['risk']}] {'; '.join(rule['rules'])}")
    else:
        print(f"  Rules   : none triggered")

# ---------------------------------------------------------------------------
# FastAPI server
# ---------------------------------------------------------------------------

def run_server():
    try:
        from fastapi import FastAPI, File, HTTPException, UploadFile
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError:
        print("Missing deps: pip install fastapi uvicorn python-multipart"); sys.exit(1)

    predictor = Predictor()
    app = FastAPI(title="ShellBreaker", version="2.1",
                  description="Hybrid Java memory webshell detector (XGBoost + rules).")

    @app.post("/predict")
    async def predict(file: UploadFile = File(...)):
        if not file.filename.endswith(".class"):
            raise HTTPException(400, "Only .class files accepted")
        data = await file.read()
        with tempfile.NamedTemporaryFile(suffix=".class", delete=False) as tmp:
            tmp.write(data); tmp_path = Path(tmp.name)
        try:
            result = predictor.predict(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "file": file.filename, **result}) + "\n")
        return JSONResponse(content=result)

    @app.get("/threshold")
    def get_threshold():
        return {
            "inference_threshold": predictor.inf_threshold,
            "high_threshold":      HIGH_THRESHOLD,
            "tiers": {
                "CONFIRMED": f"rule HIGH + ML >= {predictor.inf_threshold:.4f}",
                "HIGH":      f"ML >= {HIGH_THRESHOLD}",
                "MEDIUM":    f"ML >= {predictor.inf_threshold:.4f} OR any rule",
                "BENIGN":    "neither",
            },
        }

    print("\nStarting ShellBreaker API  http://localhost:8080")
    print("  POST /predict   — submit .class file")
    print("  GET  /threshold — view tiers")
    print("  GET  /docs      — Swagger UI\n")
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_mode(sys.argv[1])
    else:
        run_server()
