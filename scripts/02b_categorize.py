#!/usr/bin/env python3
"""
02b_categorize.py — Separate compiled webshell .class files into two categories:
  webshell_file/     (file-based webshells: ysoserial, marshalsec, etc.)
  webshell_fileless/ (memory/fileless webshells: java-memshell-generator, etc.)

Strategy:
  1. Scan each repo's .class files (skip lib/libs dirs to avoid SDK classes)
  2. Compile .java sources with servlet-api classpath
  3. MD5-deduplicate into the appropriate output directory
  4. If file-based count < TARGET_FILE, download ysoserial-all.jar release JAR

Targets: 383 file-based, 56 fileless (sampled from what we produce)
"""

import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from tqdm import tqdm

ROOT          = Path(__file__).parent.parent
WEBSHELL_SRC  = ROOT / "dataset" / "webshell_src"
OUT_FILE      = ROOT / "dataset" / "compiled" / "webshell_file"
OUT_FILELESS  = ROOT / "dataset" / "compiled" / "webshell_fileless"
LIBS_DIR      = ROOT / "dataset" / "libs"
RELEASE_DIR   = ROOT / "dataset" / "release_jars"

WORKERS = min(8, (os.cpu_count() or 4))

TARGET_FILE     = 383
TARGET_FILELESS = 56

# Repos that contain memory/fileless webshell techniques
FILELESS_REPOS = {
    "java-memshell-generator",
    "copagent",
    "MemoryShell",
    "MemoryShellLearn",
    "memShell",
    "wsMemShell",
}

# Repos that contain file-based / serialization webshell techniques
FILE_BASED_REPOS = {
    "JavaLearnVulnerability",
    "learnjavabug",
    "ShiroAttack2",
    "ysomap",
    "ysoserial",
    "marshalsec",
}

# Release JARs from known security research tools (file-based category).
# Each entry: (url, filename, package_prefix_filter)
# package_prefix_filter: if non-empty, only extract classes whose entry path starts with it.
# This prevents bundled third-party library classes from polluting the webshell dataset.
RELEASE_JARS_FILE_BASED = [
    (
        "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar",
        "ysoserial-all.jar",
        "ysoserial/",   # fat JAR — only take ysoserial's own ~125 payload/exploit classes
    ),
]

SKIP_DIRS = {
    "test", "tests", "Test", "Tests",
    "generated", "generated-sources", "gen",
    "build", "target", "out", ".gradle", ".mvn",
    "example", "examples", "sample", "samples",
    "benchmark", "benchmarks", "demo", "demos",
    "docs", "doc",
}

# Directories that likely contain third-party SDK/library JARs (not attack payload classes)
SKIP_LIB_DIRS = {"lib", "libs", "lib64", "lib32", "third_party", "vendor", "dependency"}


def should_skip(rel_path: Path) -> bool:
    parts = set(rel_path.parts)
    return bool(parts & (SKIP_DIRS | SKIP_LIB_DIRS))


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def md5_file(path: Path) -> str:
    return md5_bytes(path.read_bytes())


def build_classpath() -> str:
    jars = list(LIBS_DIR.glob("*.jar"))
    return ":".join(str(j) for j in jars)


def compile_java(args: tuple) -> list[Path]:
    java_path, classpath = args
    out_dir = java_path.parent
    cmd = ["javac", "-encoding", "UTF-8", "-nowarn", "-proc:none"]
    if classpath:
        cmd += ["-cp", classpath]
    cmd += ["-d", str(out_dir), str(java_path)]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=20)
        if result.returncode != 0:
            return []
        stem = java_path.stem
        produced = (
            list(out_dir.glob(f"{stem}.class"))
            + list(out_dir.glob(f"{stem}$*.class"))
            + list(out_dir.glob(f"{stem}*.class"))
        )
        return list(set(produced))
    except Exception:
        return []


def collect_from_repo(repo_dir: Path, out_dir: Path, seen: dict[str, Path]) -> int:
    """Copy pre-compiled + compile .java from one repo into out_dir. Returns new files added."""
    cp = build_classpath()
    added = 0

    # 1. Copy pre-existing .class files (skip lib dirs)
    class_files = [
        f for f in repo_dir.rglob("*.class")
        if not should_skip(f.relative_to(repo_dir))
    ]
    for cf in class_files:
        try:
            data = cf.read_bytes()
            h = md5_bytes(data)
            if h in seen:
                continue
            dest = out_dir / f"{h}.class"
            dest.write_bytes(data)
            seen[h] = dest
            added += 1
        except Exception:
            pass

    # 2. Compile .java files (skip lib/test dirs)
    java_files = [
        f for f in repo_dir.rglob("*.java")
        if not should_skip(f.relative_to(repo_dir))
    ]
    compile_args = [(jf, cp) for jf in java_files]

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(compile_java, a): a for a in compile_args}
        for fut in as_completed(futures):
            for cf in fut.result():
                try:
                    data = cf.read_bytes()
                    h = md5_bytes(data)
                    if h in seen:
                        continue
                    dest = out_dir / f"{h}.class"
                    dest.write_bytes(data)
                    seen[h] = dest
                    added += 1
                except Exception:
                    pass

    return added


def extract_jar_classes(jar_path: Path, out_dir: Path, seen: dict[str, Path],
                         pkg_prefix: str = "") -> int:
    """Extract non-inner, non-module .class files from a JAR into out_dir.

    pkg_prefix: if non-empty, only extract entries whose path starts with this prefix.
    """
    added = 0
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".class"):
                    continue
                if pkg_prefix and not name.startswith(pkg_prefix):
                    continue
                basename = name.split("/")[-1]
                if "$" in basename or basename in ("package-info.class", "module-info.class"):
                    continue
                data = zf.read(name)
                h = md5_bytes(data)
                if h in seen:
                    continue
                dest = out_dir / f"{h}.class"
                dest.write_bytes(data)
                seen[h] = dest
                added += 1
    except Exception as e:
        print(f"  [warn] Could not read {jar_path.name}: {e}")
    return added


def download_jar(url: str, dest: Path) -> bool:
    if dest.exists():
        return True
    print(f"  Downloading {dest.name}...")
    try:
        urllib.request.urlretrieve(url, dest)
        print(f"  [ok] {dest.name} ({dest.stat().st_size // 1024} KB)")
        return True
    except Exception as e:
        print(f"  [warn] Could not download {dest.name}: {e}")
        return False


def process_category(repos: set[str], out_dir: Path, label: str) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    seen: dict[str, Path] = {}

    available = [WEBSHELL_SRC / r for r in repos if (WEBSHELL_SRC / r).is_dir()]
    print(f"\n  [{label}] Processing {len(available)} repos...")

    for repo_dir in tqdm(available, desc=f"  {label}", unit="repo"):
        before = len(seen)
        n = collect_from_repo(repo_dir, out_dir, seen)
        print(f"    {repo_dir.name}: +{n} new  (total={len(seen)})")

    return seen


def main():
    print("=== Step 02b: Categorize Webshell Classes ===")
    print(f"  Targets: {TARGET_FILE} file-based, {TARGET_FILELESS} fileless")

    if not LIBS_DIR.exists() or not list(LIBS_DIR.glob("*.jar")):
        print("  [error] No servlet JARs in dataset/libs/. Run 02_compile_and_filter.py first.")
        sys.exit(1)

    # Process fileless repos
    fileless = process_category(FILELESS_REPOS, OUT_FILELESS, "fileless")
    print(f"\n  Fileless total: {len(fileless)}  (target: {TARGET_FILELESS})")

    # Process file-based repos
    file_based = process_category(FILE_BASED_REPOS, OUT_FILE, "file-based")
    print(f"\n  File-based total: {len(file_based)}  (target: {TARGET_FILE})")

    # If file-based count is short, try release JARs
    if len(file_based) < TARGET_FILE:
        shortfall = TARGET_FILE - len(file_based)
        print(f"\n  File-based is {shortfall} short of target — trying release JARs...")
        RELEASE_DIR.mkdir(parents=True, exist_ok=True)

        for url, filename, pkg_prefix in RELEASE_JARS_FILE_BASED:
            dest = RELEASE_DIR / filename
            if download_jar(url, dest):
                before = len(file_based)
                n = extract_jar_classes(dest, OUT_FILE, file_based, pkg_prefix)
                print(f"  Extracted {n} new classes from {filename} "
                      f"(prefix={repr(pkg_prefix) or 'all'})  (total={len(file_based)})")
                if len(file_based) >= TARGET_FILE:
                    break

    print(f"\n=== Results ===")
    print(f"  webshell_file/    : {len(file_based)}  (target={TARGET_FILE})")
    print(f"  webshell_fileless/: {len(fileless)}  (target={TARGET_FILELESS})")

    if len(file_based) < TARGET_FILE:
        print(f"  [warn] Only {len(file_based)} file-based samples; target was {TARGET_FILE}.")
        print("         The training script will use all available samples.")

    if len(fileless) < TARGET_FILELESS:
        print(f"  [error] Only {len(fileless)} fileless samples; need at least {TARGET_FILELESS}.")
        sys.exit(1)

    print("\nNext step: run python3 scripts/03_build_grayscale.py")


if __name__ == "__main__":
    main()
