#!/usr/bin/env python3
"""
03_build_grayscale.py — Convert .class bytecode → opcode sequence →
149×149 bigram adjacency matrix → grayscale PNG.

Three-category output:
  output/webshell_file/   (label=1, type=webshell_file)    — train/val only
  output/webshell_fileless/ (label=1, type=webshell_fileless) — test set only
  output/benign/          (label=0, type=benign)            — train/val only

Sampling targets (written to dataset.csv):
  613 file-based webshell, 87 fileless webshell, 2500 benign

Opcode normalization collapses short-form variants (iload_0..3 → iload,
iconst_0..5 → iconst, etc.) to produce exactly 149 canonical opcodes,
matching the JVM Specification Chapter 6 vocabulary used in the paper.

Outputs:
  output/{webshell_file,webshell_fileless,benign}/<md5>.png
  output/dataset.csv    (path, label, type, class_name)
  output/vocab.json     (opcode → index, exactly 149 entries)
"""

import csv
import json
import os
import random
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import numpy as np
from PIL import Image
from tqdm import tqdm

ROOT              = Path(__file__).parent.parent
COMPILED_FILE     = ROOT / "dataset" / "compiled" / "webshell_file"
COMPILED_FILELESS = ROOT / "dataset" / "compiled" / "webshell_fileless"
COMPILED_BN       = ROOT / "dataset" / "compiled" / "benign"
COMPILED_BN_TEST  = ROOT / "dataset" / "compiled" / "benign_test"
OUT_FILE          = ROOT / "output" / "webshell_file"
OUT_FILELESS      = ROOT / "output" / "webshell_fileless"
OUT_BN            = ROOT / "output" / "benign"
OUT_BN_TEST       = ROOT / "output" / "benign_test"
DATASET_CSV       = ROOT / "output" / "dataset.csv"
VOCAB_JSON        = ROOT / "output" / "vocab.json"

WORKERS = min(8, (os.cpu_count() or 4))

TARGET_FILE     = 9999  # take all available (signal-filtered in 02b)
TARGET_FILELESS = 9999  # take all available
# TARGET_BENIGN is computed dynamically in main() as 8× file-based count, capped at available

# Files smaller than this are almost always interfaces, annotations, empty stubs, or
# trivial POJOs scraped from exploit-framework repos — not actual webshells.
MIN_BYTES_WEBSHELL = 500

RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# Opcode normalization — collapses short-form variants to canonical names.
# This is what produces exactly 149 unique opcodes from the JVM spec.
# ---------------------------------------------------------------------------
OPCODE_NORM: dict[str, str] = {
    # iconst variants → iconst
    **{f"iconst_{s}": "iconst" for s in ["m1", "0", "1", "2", "3", "4", "5"]},
    # lconst / fconst / dconst
    **{f"lconst_{i}": "lconst" for i in range(2)},
    **{f"fconst_{i}": "fconst" for i in range(3)},
    **{f"dconst_{i}": "dconst" for i in range(2)},
    # load short forms
    **{f"iload_{i}": "iload" for i in range(4)},
    **{f"lload_{i}": "lload" for i in range(4)},
    **{f"fload_{i}": "fload" for i in range(4)},
    **{f"dload_{i}": "dload" for i in range(4)},
    **{f"aload_{i}": "aload" for i in range(4)},
    # store short forms
    **{f"istore_{i}": "istore" for i in range(4)},
    **{f"lstore_{i}": "lstore" for i in range(4)},
    **{f"fstore_{i}": "fstore" for i in range(4)},
    **{f"dstore_{i}": "dstore" for i in range(4)},
    **{f"astore_{i}": "astore" for i in range(4)},
}

# ---------------------------------------------------------------------------
# Fixed 149-opcode vocabulary (JVM Spec Chapter 6, non-deprecated, normalized).
# Derived by collapsing short-form constant/load/store variants to base names.
# Count: verified at 149 entries.
# ---------------------------------------------------------------------------
JVM_VOCAB_149: list[str] = [
    # Null / no-op (2)
    "nop", "aconst_null",
    # Constants — normalized (4)
    "iconst", "lconst", "fconst", "dconst",
    # Push (2)
    "bipush", "sipush",
    # LDC (3)
    "ldc", "ldc_w", "ldc2_w",
    # Loads — normalized from _0/_1/_2/_3 short forms (5)
    "iload", "lload", "fload", "dload", "aload",
    # Array loads (8)
    "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload",
    # Stores — normalized (5)
    "istore", "lstore", "fstore", "dstore", "astore",
    # Array stores (8)
    "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore",
    # Stack manipulation (9)
    "pop", "pop2", "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap",
    # Integer arithmetic & logic (13)
    "iadd", "isub", "imul", "idiv", "irem", "ineg",
    "ishl", "ishr", "iushr", "iand", "ior", "ixor", "iinc",
    # Long arithmetic & logic (12)
    "ladd", "lsub", "lmul", "ldiv", "lrem", "lneg",
    "lshl", "lshr", "lushr", "land", "lor", "lxor",
    # Float arithmetic (6)
    "fadd", "fsub", "fmul", "fdiv", "frem", "fneg",
    # Double arithmetic (6)
    "dadd", "dsub", "dmul", "ddiv", "drem", "dneg",
    # Type conversions (15)
    "i2l", "i2f", "i2d",
    "l2i", "l2f", "l2d",
    "f2i", "f2l", "f2d",
    "d2i", "d2l", "d2f",
    "i2b", "i2c", "i2s",
    # Comparisons (5)
    "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg",
    # Integer branches (6)
    "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
    # Integer compare branches (6)
    "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple",
    # Reference branches (2)
    "if_acmpeq", "if_acmpne",
    # Jumps (2)
    "goto", "goto_w",
    # Switch (2)
    "tableswitch", "lookupswitch",
    # Returns (6)
    "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return",
    # Field access (4)
    "getstatic", "putstatic", "getfield", "putfield",
    # Method invocation (5)
    "invokevirtual", "invokespecial", "invokestatic", "invokeinterface", "invokedynamic",
    # Object / array creation (4)
    "new", "newarray", "anewarray", "multianewarray",
    # Object operations (4)
    "arraylength", "athrow", "checkcast", "instanceof",
    # Synchronisation (2)
    "monitorenter", "monitorexit",
    # Misc (1)
    "wide",
    # Null checks (2)
    "ifnull", "ifnonnull",
]

assert len(JVM_VOCAB_149) == 149, f"Vocab has {len(JVM_VOCAB_149)} entries, expected 149"

_OPCODE_RE = re.compile(r"^\s+\d+:\s+([a-z][a-z0-9_]+)")


def normalize(op: str) -> str:
    return OPCODE_NORM.get(op, op)


def disassemble(class_path: Path) -> list[str] | None:
    """Run javap -c; return normalized opcode list or None."""
    try:
        result = subprocess.run(
            ["javap", "-c", "-p", str(class_path)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return None
        ops = []
        for line in result.stdout.splitlines():
            m = _OPCODE_RE.match(line)
            if m:
                ops.append(normalize(m.group(1)))
        return ops if ops else None
    except Exception:
        return None


def extract_class_name(class_path: Path) -> str:
    try:
        r = subprocess.run(
            ["javap", "-p", str(class_path)],
            capture_output=True, text=True, timeout=10,
        )
        for line in r.stdout.splitlines():
            m = re.search(r"\bclass\s+([\w.$]+)", line)
            if m:
                return m.group(1).split(".")[-1]
    except Exception:
        pass
    return class_path.stem


def build_matrix(opcodes: list[str], vocab: dict[str, int], n: int) -> np.ndarray:
    mat = np.zeros((n, n), dtype=np.uint32)
    for i in range(len(opcodes) - 1):
        a = vocab.get(opcodes[i], -1)
        b = vocab.get(opcodes[i + 1], -1)
        if a >= 0 and b >= 0:
            mat[a, b] += 1
    max_val = mat.max()
    if max_val == 0:
        return mat.astype(np.uint8)
    return (mat.astype(float) / max_val * 255).astype(np.uint8)


def process_one(args: tuple) -> tuple[Path, str] | None:
    """Worker: disassemble → matrix → PNG. Returns (png_path, class_name) or None."""
    class_path, out_dir, vocab, n = args
    png_path = out_dir / f"{class_path.stem}.png"
    if png_path.exists():
        return png_path, class_path.stem  # resume: already done

    ops = disassemble(class_path)
    if not ops or len(ops) < 4:
        return None

    class_name = extract_class_name(class_path)
    mat = build_matrix(ops, vocab, n)
    Image.fromarray(mat).save(png_path)
    return png_path, class_name


def process_split(
    compiled_dir: Path,
    out_dir: Path,
    label: int,
    type_name: str,
    vocab: dict[str, int],
    n: int,
    min_bytes: int = 0,
) -> list[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    class_files = sorted(compiled_dir.glob("*.class"))
    if min_bytes > 0:
        before = len(class_files)
        class_files = [cf for cf in class_files if cf.stat().st_size >= min_bytes]
        print(f"\n  [{type_name}] size filter ≥{min_bytes}B: {before} → {len(class_files)} kept "
              f"({before - len(class_files)} stubs removed)")
    already = sum(1 for cf in class_files if (out_dir / f"{cf.stem}.png").exists())
    print(f"  [{type_name}] {len(class_files)} .class  "
          f"(done: {already}, new: {len(class_files)-already})  workers={WORKERS}")

    rows: list[dict] = []
    work = [(cf, out_dir, vocab, n) for cf in class_files]

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(process_one, a): a for a in work}
        with tqdm(total=len(work), desc=f"  {type_name}", unit="file") as bar:
            for fut in as_completed(futures):
                bar.update(1)
                result = fut.result()
                if result is None:
                    continue
                png_path, class_name = result
                rows.append({
                    "path": str(png_path.relative_to(ROOT)),
                    "label": label,
                    "type": type_name,
                    "class": class_name,
                })
    return rows


def main():
    random.seed(RANDOM_SEED)

    # Compute benign target dynamically before any prints that reference it
    n_file_avail   = len(list(COMPILED_FILE.glob("*.class"))) if COMPILED_FILE.exists() else 0
    n_benign_avail = len(list(COMPILED_BN.glob("*.class")))   if COMPILED_BN.exists()   else 0
    TARGET_BENIGN  = min(2000, n_benign_avail)

    print("=== Step 03: Build Grayscale PNGs (three-category) ===")
    print(f"  Vocab: {len(JVM_VOCAB_149)} opcodes → {len(JVM_VOCAB_149)}×{len(JVM_VOCAB_149)} matrix")
    print(f"  Targets: {TARGET_FILE} file-based, {TARGET_FILELESS} fileless, {TARGET_BENIGN} benign")

    for d, name in [
        (COMPILED_FILE, "webshell_file"),
        (COMPILED_FILELESS, "webshell_fileless"),
        (COMPILED_BN, "benign"),
    ]:
        count = len(list(d.glob("*.class"))) if d.exists() else 0
        print(f"  {name}: {count} .class files")
        if count == 0:
            print(f"  [error] No .class files in dataset/compiled/{name}/")
            if name == "webshell_file":
                print("  Run scripts/02b_categorize.py first.")
                sys.exit(1)
            elif name == "benign":
                print("  Run scripts/02_compile_and_filter.py first.")
                sys.exit(1)

    vocab: dict[str, int] = {op: i for i, op in enumerate(JVM_VOCAB_149)}
    n = len(JVM_VOCAB_149)  # 149

    ROOT.joinpath("output").mkdir(parents=True, exist_ok=True)
    with open(VOCAB_JSON, "w") as f:
        json.dump(vocab, f, indent=2)
    print(f"\n  Saved vocab.json ({n} opcodes → {n}×{n})")

    file_rows     = process_split(COMPILED_FILE,     OUT_FILE,     1, "webshell_file",     vocab, n, min_bytes=MIN_BYTES_WEBSHELL)
    fileless_rows = process_split(COMPILED_FILELESS, OUT_FILELESS, 1, "webshell_fileless", vocab, n)
    bn_rows       = process_split(COMPILED_BN,       OUT_BN,       0, "benign",            vocab, n)

    # benign_test — held-out negatives for the fileless generalisation eval (never in training CSV)
    bn_test_rows = []
    if COMPILED_BN_TEST.exists() and any(COMPILED_BN_TEST.glob("*.class")):
        bn_test_rows = process_split(COMPILED_BN_TEST, OUT_BN_TEST, 0, "benign_test", vocab, n)
        print(f"\n  benign_test PNGs generated: {len(bn_test_rows)}  (held-out, not in dataset.csv)")
    else:
        print(f"\n  [info] No benign_test .class files — skipping benign_test PNGs")

    # Sample to exact targets
    if len(file_rows) > TARGET_FILE:
        print(f"\n  Sampling file-based: {len(file_rows)} → {TARGET_FILE}")
        file_rows = random.sample(file_rows, TARGET_FILE)

    if len(fileless_rows) > TARGET_FILELESS:
        print(f"  Sampling fileless: {len(fileless_rows)} → {TARGET_FILELESS}")
        fileless_rows = random.sample(fileless_rows, TARGET_FILELESS)

    if len(bn_rows) > TARGET_BENIGN:
        print(f"  Sampling benign: {len(bn_rows)} → {TARGET_BENIGN}")
        bn_rows = random.sample(bn_rows, TARGET_BENIGN)

    # dataset.csv covers train/val splits only (webshell_file + benign)
    # fileless and benign_test are held-out — referenced by path in training script directly
    all_rows = file_rows + fileless_rows + bn_rows
    with open(DATASET_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "label", "type", "class"])
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n=== Done ===")
    print(f"  webshell_file     in CSV : {len(file_rows)}")
    print(f"  webshell_fileless in CSV : {len(fileless_rows)}")
    print(f"  benign            in CSV : {len(bn_rows)}")
    print(f"  benign_test (held-out)   : {len(bn_test_rows)}  (PNGs only — not in CSV)")
    print(f"  Total in CSV             : {len(all_rows)}")
    print(f"  dataset.csv → {DATASET_CSV}")
    print(f"  vocab.json  → {VOCAB_JSON}  (matrix {n}×{n})")

    if len(file_rows) < 100:
        print("\n  [warn] Very few file-based webshell samples — run 02b_categorize.py")
    if len(fileless_rows) < TARGET_FILELESS:
        print(f"\n  [warn] Only {len(fileless_rows)} fileless samples; target is {TARGET_FILELESS}")

    print("\nNext step: python3 scripts/04_train_resnet50.py  (GPU recommended — use Colab)")


if __name__ == "__main__":
    main()
