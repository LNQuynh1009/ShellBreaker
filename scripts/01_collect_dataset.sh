#!/usr/bin/env bash
# 01_collect_dataset.sh — Clone webshell and benign Java repos from GitHub.
# Uses --depth=1 (shallow clone). Skips repos already present.
#
# Three-category dataset design:
#   FILELESS repos  → dataset/webshell_src/  → compiled into webshell_fileless/ (test-only)
#   FILE_BASED repos → dataset/webshell_src/ → compiled into webshell_file/    (train/val)
#   BENIGN repos    → dataset/benign_src/    → compiled into benign/            (train/val)
#
# After cloning, run 02_compile_and_filter.py (benign) then 02b_categorize.py (webshells).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WEBSHELL_DIR="$ROOT/dataset/webshell_src"
BENIGN_DIR="$ROOT/dataset/benign_src"
mkdir -p "$WEBSHELL_DIR" "$BENIGN_DIR"

# ── Fileless / memory webshell repos (used as TEST SET ONLY) ────────────────
# These inject code into JVM memory at runtime without writing to disk.
# Kept separate: model trains on file-based shells, tests generalise to fileless.
FILELESS_REPOS=(
    "https://github.com/pen4uin/java-memshell-generator"
    "https://github.com/su18/MemoryShell"
    "https://github.com/rebeyond/memShell"
    "https://github.com/veo/wsMemShell"
    "https://github.com/bitterzzZZ/MemoryShellLearn"
    "https://github.com/LandGrey/copagent"
)

# ── File-based / serialization webshell repos (TRAIN + VAL) ─────────────────
# Classic servlet-based webshells and Java deserialization exploit frameworks.
FILE_BASED_REPOS=(
    "https://github.com/SummerSec/JavaLearnVulnerability"
    "https://github.com/threedr3am/learnjavabug"
    "https://github.com/c0ny1/ShiroAttack2"
    "https://github.com/mbechler/marshalsec"
    "https://github.com/wh1t3p1g/ysomap"
    "https://github.com/frohoff/ysoserial"
)

# ── Benign Java repos ───────────────────────────────────────────────────────
# Mix of utility libs (existing) + web-framework code (new).
# Web-framework repos are critical: they contain HTTP dispatch, reflection, and
# classloading patterns that superficially resemble webshells, so training on
# them directly reduces false positives on legitimate web-serving code.
BENIGN_REPOS=(
    # Utility / general (original set)
    "https://github.com/spring-projects/spring-petclinic"
    "https://github.com/apache/commons-lang"
    "https://github.com/apache/commons-collections"
    "https://github.com/mockito/mockito"
    "https://github.com/junit-team/junit5"
    "https://github.com/square/retrofit"
    "https://github.com/ReactiveX/RxJava"
    "https://github.com/google/gson"
    "https://github.com/FasterXML/jackson-core"
    "https://github.com/apache/commons-io"
    # Web frameworks — HTTP dispatch, reflection, classloading (targets FP reduction)
    "https://github.com/apache/tomcat"
    "https://github.com/spring-projects/spring-framework"
    "https://github.com/netty/netty"
    "https://github.com/apache/shiro"
    "https://github.com/apache/struts"
    "https://github.com/eclipse-ee4j/jersey"
    "https://github.com/hibernate/hibernate-orm"
    "https://github.com/mybatis/mybatis-3"
)

clone_repo() {
    local url="$1"
    local target_dir="$2"
    local name
    name="$(basename "$url" .git)"
    local dest="$target_dir/$name"

    if [ -d "$dest/.git" ]; then
        echo "  [skip] $name (already cloned)"
        return 0
    fi

    echo "  Cloning $name ..."
    if git clone --depth=1 --quiet "$url" "$dest" 2>/dev/null; then
        echo "  [ok]   $name"
    else
        echo "  [fail] $name — skipping"
        rm -rf "$dest"
    fi
}

echo "=== Collecting fileless webshell repos (test-only) ==="
for url in "${FILELESS_REPOS[@]}"; do
    clone_repo "$url" "$WEBSHELL_DIR"
done

echo ""
echo "=== Collecting file-based webshell repos (train/val) ==="
for url in "${FILE_BASED_REPOS[@]}"; do
    clone_repo "$url" "$WEBSHELL_DIR"
done

echo ""
echo "=== Collecting benign repos ==="
for url in "${BENIGN_REPOS[@]}"; do
    clone_repo "$url" "$BENIGN_DIR"
done

echo ""
echo "=== Dataset collection complete ==="
java_ws=$(find "$WEBSHELL_DIR" -name '*.java' 2>/dev/null | grep -c '.' || true)
java_bn=$(find "$BENIGN_DIR"   -name '*.java' 2>/dev/null | grep -c '.' || true)
cls_ws=$(find "$WEBSHELL_DIR"  -name '*.class' 2>/dev/null | grep -c '.' || true)
echo "  Webshell .java:  $java_ws"
echo "  Benign   .java:  $java_bn"
echo "  Pre-compiled .class (webshell): $cls_ws"
echo ""
echo "Next steps:"
echo "  python3 scripts/02_compile_and_filter.py   # compiles benign"
echo "  python3 scripts/02b_categorize.py           # compiles + separates webshells"
