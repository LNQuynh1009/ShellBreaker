#!/usr/bin/env python3
"""
03b_build_csv.py — Build dataset.csv directly from compiled .class files.

Replaces the PNG-generation step (03_build_grayscale.py) entirely.
The XGBoost training script only needs the CSV to map stem → (label, type);
it runs javap on the .class file itself, never reads the PNG.

The "path" column keeps the output/<type>/<stem>.png format that
04b_train_xgboost.py expects (it strips .png to get the stem, then looks up
the .class in dataset/compiled/<type>/<stem>.class).
"""

import csv
import json
import random
from pathlib import Path

ROOT            = Path(__file__).parent.parent
COMPILED_FILE   = ROOT / "dataset" / "compiled" / "webshell_file"
COMPILED_FL     = ROOT / "dataset" / "compiled" / "webshell_fileless"
COMPILED_BN     = ROOT / "dataset" / "compiled" / "benign"
DATASET_CSV     = ROOT / "output" / "dataset.csv"
VOCAB_JSON      = ROOT / "output" / "vocab.json"

# 149-opcode canonical vocabulary — identical to 03_build_grayscale.py
JVM_VOCAB_149 = [
    "nop", "aconst_null",
    "iconst", "lconst", "fconst", "dconst",
    "bipush", "sipush",
    "ldc", "ldc_w", "ldc2_w",
    "iload", "lload", "fload", "dload", "aload",
    "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload",
    "istore", "lstore", "fstore", "dstore", "astore",
    "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore",
    "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap",
    "iadd", "isub", "imul", "idiv", "irem", "ineg",
    "ishl", "ishr", "iushr", "iand", "ior", "ixor", "iinc",
    "ladd", "lsub", "lmul", "ldiv", "lrem", "lneg",
    "lshl", "lshr", "lushr", "land", "lor", "lxor",
    "fadd", "fsub", "fmul", "fdiv", "frem", "fneg",
    "dadd", "dsub", "dmul", "ddiv", "drem", "dneg",
    "i2l", "i2f", "i2d",
    "l2i", "l2f", "l2d",
    "f2i", "f2l", "f2d",
    "d2i", "d2l", "d2f",
    "i2b", "i2c", "i2s",
    "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg",
    "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
    "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple",
    "if_acmpeq", "if_acmpne",
    "goto", "goto_w",
    "tableswitch", "lookupswitch",
    "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return",
    "getstatic", "putstatic", "getfield", "putfield",
    "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic",
    "new", "newarray", "anewarray", "multianewarray",
    "arraylength", "athrow", "checkcast", "instanceof",
    "monitorenter", "monitorexit",
    "wide",
    "ifnull", "ifnonnull",
]
assert len(JVM_VOCAB_149) == 149

RANDOM_SEED        = 42
MIN_BYTES_WEBSHELL = 500   # skip tiny stubs


def collect(directory: Path, label: int, type_name: str,
            limit: int = 999999) -> list[dict]:
    files = sorted(directory.glob("*.class"))
    if type_name in ("webshell_file", "webshell_fileless"):
        files = [f for f in files if f.stat().st_size >= MIN_BYTES_WEBSHELL]
    if len(files) > limit:
        files = random.sample(files, limit)
    rows = []
    for f in files:
        rows.append({
            "path": f"output/{type_name}/{f.stem}.png",  # stem-only; PNG need not exist
            "label": label,
            "type":  type_name,
            "class": f.stem,
        })
    return rows


def main():
    random.seed(RANDOM_SEED)

    ROOT / "output"
    (ROOT / "output").mkdir(parents=True, exist_ok=True)

    # Write vocab.json (needed by training script)
    vocab = {op: i for i, op in enumerate(JVM_VOCAB_149)}
    VOCAB_JSON.write_text(json.dumps(vocab, indent=2))
    print(f"Saved vocab.json  ({len(vocab)} opcodes)")

    # Count available
    n_file     = len([f for f in COMPILED_FILE.glob("*.class")
                      if f.stat().st_size >= MIN_BYTES_WEBSHELL])
    n_fileless = len([f for f in COMPILED_FL.glob("*.class")
                      if f.stat().st_size >= MIN_BYTES_WEBSHELL])
    n_benign   = len(list(COMPILED_BN.glob("*.class")))

    # Benign target: 8× file-based webshell, capped at available
    target_benign = min(n_file * 8, n_benign)
    target_benign = max(target_benign, 500)

    print(f"\nAvailable:")
    print(f"  webshell_file     : {n_file}  (≥{MIN_BYTES_WEBSHELL}B)")
    print(f"  webshell_fileless : {n_fileless}  (≥{MIN_BYTES_WEBSHELL}B, test-only)")
    print(f"  benign            : {n_benign}  → sampling {target_benign}")

    file_rows     = collect(COMPILED_FILE, 1, "webshell_file")
    fileless_rows = collect(COMPILED_FL,   1, "webshell_fileless")
    benign_rows   = collect(COMPILED_BN,   0, "benign", limit=target_benign)

    all_rows = file_rows + fileless_rows + benign_rows
    with open(DATASET_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "label", "type", "class"])
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\ndataset.csv written: {len(all_rows)} rows")
    print(f"  webshell_file     : {len(file_rows)}")
    print(f"  webshell_fileless : {len(fileless_rows)}")
    print(f"  benign            : {len(benign_rows)}")
    print(f"\nNext step: run scripts/04b_train_xgboost.py")


if __name__ == "__main__":
    main()
