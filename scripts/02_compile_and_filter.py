#!/usr/bin/env python3
"""
02_compile_and_filter.py — Compile .java → .class; copy pre-existing .class
files; deduplicate everything by MD5 hash.

Output: dataset/compiled/{webshell,benign}/*.class (unique files only)
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

ROOT         = Path(__file__).parent.parent
WEBSHELL_SRC = ROOT / "dataset" / "webshell_src"
BENIGN_SRC   = ROOT / "dataset" / "benign_src"
OUT_WEBSHELL = ROOT / "dataset" / "compiled" / "webshell"
OUT_BENIGN   = ROOT / "dataset" / "compiled" / "benign"
LIBS_DIR     = ROOT / "dataset" / "libs"

# Number of parallel javac workers
WORKERS = min(8, (os.cpu_count() or 4))

# Dirs to skip during discovery (reduces noise and compilation time)
SKIP_DIRS = {
    "test", "tests", "Test", "Tests",
    "generated", "generated-sources", "gen",
    "build", "target", "out", ".gradle", ".mvn",
    "example", "examples", "sample", "samples",
    "benchmark", "benchmarks", "demo", "demos",
    "docs", "doc",
}

SERVLET_JARS = [
    (
        "https://repo1.maven.org/maven2/javax/servlet/javax.servlet-api/4.0.1/javax.servlet-api-4.0.1.jar",
        "javax.servlet-api-4.0.1.jar",
    ),
    (
        "https://repo1.maven.org/maven2/jakarta/servlet/jakarta.servlet-api/5.0.0/jakarta.servlet-api-5.0.0.jar",
        "jakarta.servlet-api-5.0.0.jar",
    ),
]

# Popular Java library JARs downloaded from Maven Central to use as benign samples.
# These are definitively benign and provide diverse bytecode patterns.
BENIGN_JARS = [
    ("https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar", "commons-lang3-3.14.0.jar"),
    ("https://repo1.maven.org/maven2/org/apache/commons/commons-collections4/4.4/commons-collections4-4.4.jar", "commons-collections4-4.4.jar"),
    ("https://repo1.maven.org/maven2/com/google/guava/guava/33.2.0-jre/guava-33.2.0-jre.jar", "guava-33.2.0-jre.jar"),
    ("https://repo1.maven.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar", "gson-2.11.0.jar"),
    ("https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.17.1/jackson-databind-2.17.1.jar", "jackson-databind-2.17.1.jar"),
    ("https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.17.1/jackson-core-2.17.1.jar", "jackson-core-2.17.1.jar"),
    ("https://repo1.maven.org/maven2/org/apache/commons/commons-io/1.3.2/commons-io-1.3.2.jar", "commons-io-1.3.2.jar"),
    ("https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.13/slf4j-api-2.0.13.jar", "slf4j-api-2.0.13.jar"),
    ("https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/1.5.6/logback-classic-1.5.6.jar", "logback-classic-1.5.6.jar"),
    ("https://repo1.maven.org/maven2/org/springframework/spring-core/6.1.8/spring-core-6.1.8.jar", "spring-core-6.1.8.jar"),
    ("https://repo1.maven.org/maven2/org/springframework/spring-context/6.1.8/spring-context-6.1.8.jar", "spring-context-6.1.8.jar"),
    ("https://repo1.maven.org/maven2/org/springframework/spring-web/6.1.8/spring-web-6.1.8.jar", "spring-web-6.1.8.jar"),
    ("https://repo1.maven.org/maven2/io/netty/netty-all/4.1.110.Final/netty-all-4.1.110.Final.jar", "netty-all-4.1.110.Final.jar"),
    ("https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.jar", "httpclient-4.5.14.jar"),
    ("https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar", "okhttp-4.12.0.jar"),
]


def md5(path: Path) -> str:
    h = hashlib.md5()
    h.update(path.read_bytes())
    return h.hexdigest()


def download_jars(jar_list: list[tuple[str, str]], dest_dir: Path, desc: str) -> list[Path]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    downloaded = []
    for url, filename in jar_list:
        dest = dest_dir / filename
        if dest.exists():
            downloaded.append(dest)
            continue
        print(f"  Downloading {filename}...")
        try:
            urllib.request.urlretrieve(url, dest)
            print(f"  [ok] {filename}")
            downloaded.append(dest)
        except Exception as e:
            print(f"  [warn] Could not download {filename}: {e}")
    return downloaded


def download_libs():
    download_jars(SERVLET_JARS, LIBS_DIR, "servlet JARs")


def build_classpath() -> str:
    jars = list(LIBS_DIR.glob("*.jar"))
    return ":".join(str(j) for j in jars)


def should_skip_path(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def compile_java(args: tuple) -> list[Path]:
    """
    Worker function: compile one .java file.
    Returns list of produced .class files (empty if compilation failed).
    """
    java_path, classpath = args
    out_dir = java_path.parent
    cmd = ["javac", "-encoding", "UTF-8", "-nowarn", "-proc:none"]
    if classpath:
        cmd += ["-cp", classpath]
    cmd += ["-d", str(out_dir), str(java_path)]

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=20,
        )
        if result.returncode != 0:
            return []
        stem = java_path.stem
        produced = (
            list(out_dir.glob(f"{stem}.class"))
            + list(out_dir.glob(f"{stem}$*.class"))
            + list(out_dir.glob(f"{stem}*.class"))
        )
        return list(set(produced))
    except (subprocess.TimeoutExpired, Exception):
        return []


def collect_classes(src_dir: Path, out_dir: Path, label: str) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Discover files
    java_files = [
        f for f in src_dir.rglob("*.java")
        if not should_skip_path(f.relative_to(src_dir))
    ]
    class_files = [
        f for f in src_dir.rglob("*.class")
        if not should_skip_path(f.relative_to(src_dir))
    ]
    print(f"\n  [{label}] {len(java_files)} .java, {len(class_files)} pre-compiled .class")
    print(f"  [{label}] Compiling with {WORKERS} parallel workers...")

    cp = build_classpath()

    # Compile in parallel
    compiled_classes: list[Path] = []
    compile_args = [(jf, cp) for jf in java_files]
    ok = fail = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(compile_java, arg): arg for arg in compile_args}
        with tqdm(total=len(compile_args), desc=f"  Compile {label}", unit="file") as bar:
            for future in as_completed(futures):
                produced = future.result()
                if produced:
                    compiled_classes.extend(produced)
                    ok += 1
                else:
                    fail += 1
                bar.update(1)

    print(f"  [{label}] compiled ok={ok}, failed={fail}")

    # Dedup all candidate .class files
    all_candidates = class_files + compiled_classes
    seen: dict[str, Path] = {}
    dup = accepted = 0

    for cf in tqdm(all_candidates, desc=f"  Dedup {label:8s}", unit="file"):
        if not cf.exists():
            continue
        try:
            h = md5(cf)
        except Exception:
            continue
        if h in seen:
            dup += 1
            continue
        dest = out_dir / f"{h}.class"
        try:
            shutil.copy2(cf, dest)
            seen[h] = dest
            accepted += 1
        except Exception:
            pass

    print(f"  [{label}] accepted={accepted}, duplicates removed={dup}")
    return seen


def extract_benign_jars(out_dir: Path) -> dict[str, Path]:
    """
    Download popular Java library JARs from Maven Central and extract their
    .class files as additional benign training samples.
    JARs are ZIP files — we read them in-memory without unpacking.
    """
    JARS_EXTRACT_DIR = ROOT / "dataset" / "benign_jars"
    JARS_EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

    jar_paths = download_jars(BENIGN_JARS, JARS_EXTRACT_DIR, "benign library JARs")
    if not jar_paths:
        print("  [warn] No benign JARs downloaded.")
        return {}

    seen: dict[str, Path] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    total_extracted = dup = 0

    for jar_path in tqdm(jar_paths, desc="  Extract JARs", unit="jar"):
        try:
            with zipfile.ZipFile(jar_path, "r") as zf:
                for name in zf.namelist():
                    if not name.endswith(".class"):
                        continue
                    # Skip inner classes and package-info / module-info
                    basename = name.split("/")[-1]
                    if "$" in basename or basename in ("package-info.class", "module-info.class"):
                        continue
                    data = zf.read(name)
                    h = hashlib.md5(data).hexdigest()
                    if h in seen:
                        dup += 1
                        continue
                    dest = out_dir / f"{h}.class"
                    if not dest.exists():
                        dest.write_bytes(data)
                    seen[h] = dest
                    total_extracted += 1
        except Exception as e:
            print(f"  [warn] Could not read {jar_path.name}: {e}")

    print(f"  Extracted from JARs: {total_extracted} unique .class, {dup} duplicates skipped")
    return seen


def main():
    print("=== Step 02: Compile & Filter ===")
    print(f"  CPU workers for javac: {WORKERS}")
    download_libs()

    ws = collect_classes(WEBSHELL_SRC, OUT_WEBSHELL, "webshell")

    print("\n  Collecting benign from cloned repos...")
    bn_repos = collect_classes(BENIGN_SRC, OUT_BENIGN, "benign")

    print("\n  Augmenting benign with popular Java library JARs...")
    bn_jars = extract_benign_jars(OUT_BENIGN)

    # Merge (jar extraction writes directly to OUT_BENIGN with MD5 names, deduped inline)
    total_bn = len(set(list(bn_repos.keys()) + list(bn_jars.keys())))

    print(f"\n=== Done ===")
    print(f"  Unique webshell .class:  {len(ws)}")
    print(f"  Unique benign   .class:  {total_bn}  (repos: {len(bn_repos)}, jars: {len(bn_jars)})")
    print(f"  Total:                   {len(ws) + total_bn}")

    if len(ws) < 50:
        print("\n  [warn] Fewer than 50 webshell samples. Add more repos to 01_collect_dataset.sh")

    print("\nNext step: run python3 scripts/03_build_grayscale.py")


if __name__ == "__main__":
    main()
