#!/usr/bin/env python3
"""
02c_extract_benign_test.py — Extract benign .class files from JARs for held-out test.

Source : dataset/benign_test_jars/
Output : dataset/compiled/benign_test/

Rules  : skip inner classes ($), skip < MIN_SIZE bytes, MD5-dedup, cap at MAX_TOTAL.
"""

import hashlib
import zipfile
from pathlib import Path

from tqdm import tqdm

ROOT    = Path(__file__).parent.parent
JAR_DIR = ROOT / "dataset" / "benign_test_jars"
OUT_DIR = ROOT / "dataset" / "compiled" / "benign_test"

MAX_TOTAL = 500
MIN_SIZE  = 500


def main():
    print("=== Step 02c: Extract benign test .class files ===\n")

    if not JAR_DIR.exists():
        print(f"JAR directory not found: {JAR_DIR}")
        print("Run scripts/01b_collect_benign_test.sh first.")
        return

    jars = sorted(JAR_DIR.glob("*.jar"))
    if not jars:
        print(f"No JARs found in {JAR_DIR}")
        print("Run scripts/01b_collect_benign_test.sh first.")
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  Source JARs : {JAR_DIR}  ({len(jars)} files)")
    print(f"  Output dir  : {OUT_DIR}")
    print(f"  Cap         : {MAX_TOTAL} files | Min size: {MIN_SIZE} B\n")

    seen_md5: set[str] = set()
    total = 0

    for jar in tqdm(jars, desc="JARs"):
        if total >= MAX_TOTAL:
            break
        try:
            with zipfile.ZipFile(jar, "r") as zf:
                entries = [
                    e for e in zf.namelist()
                    if e.endswith(".class") and "$" not in Path(e).name
                ]
                for entry in entries:
                    if total >= MAX_TOTAL:
                        break
                    data = zf.read(entry)
                    if len(data) < MIN_SIZE:
                        continue
                    md5 = hashlib.md5(data).hexdigest()
                    if md5 in seen_md5:
                        continue
                    seen_md5.add(md5)
                    stem = Path(entry).stem
                    out_path = OUT_DIR / f"{stem}_{md5[:8]}.class"
                    out_path.write_bytes(data)
                    total += 1
        except Exception as e:
            tqdm.write(f"  Warning: {jar.name}: {e}")

    print(f"\n  Extracted {total} unique benign .class files → {OUT_DIR}")
    print("\nNext step: run scripts/06_visualize.py")


if __name__ == "__main__":
    main()
