#!/usr/bin/env bash
# 02d_compile_ysrc_jsps.sh — Compile ysrc-back JSP webshells via Tomcat Jasper.
#
# The gxu-yuan/ysrc-back repo contains raw .jsp files (no pre-compiled .class).
# Jasper (Tomcat's JSP compiler) is needed to produce .class bytecode.
#
# How it works:
#   1. Start the memshell-lab Tomcat container (or use an already-running one).
#   2. Copy each JSP into Tomcat's webapps/jsp-compile/ directory.
#   3. Trigger compilation via curl (one request per JSP).
#   4. Copy the compiled .class files from Tomcat's work volume into
#      dataset/compiled/webshell_file/ (MD5-deduplicated).
#
# Prerequisites:
#   - Docker running
#   - memshell-lab/docker-compose.yml accessible
#   - Run from the ShellBreaker root directory
#
# After this script: run python3 scripts/02b_categorize.py (it will pick up
# the new .class files already in webshell_file/) then scripts/03_build_grayscale.py.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="/home/quynh/memshell-lab"
JSP_SRC="$ROOT/dataset/webshell_src/ysrc-back/webshell-sample/jsp"
OUT_DIR="$ROOT/dataset/compiled/webshell_file"
WORK_VOLUME="tomcat-work"
CONTAINER="memshell-tomcat"

if [ ! -d "$JSP_SRC" ]; then
    echo "[error] JSP source not found: $JSP_SRC"
    echo "        Extract ysrc.zip first: unzip ysrc.zip -d dataset/webshell_src/"
    exit 1
fi

JSP_COUNT=$(find "$JSP_SRC" -name "*.jsp" | wc -l)
echo "=== Compile ysrc-back JSPs via Tomcat Jasper ==="
echo "  JSP source : $JSP_SRC  ($JSP_COUNT files)"
echo "  Output     : $OUT_DIR"
echo ""

# ── 1. Start Tomcat if not running ──────────────────────────────────────────
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo "Starting Tomcat container..."
    cd "$LAB_DIR"
    docker compose up -d tomcat
    echo "Waiting for Tomcat to be healthy..."
    until curl -sf http://localhost:8080/ > /dev/null 2>&1; do sleep 2; done
    echo "  Tomcat ready."
    cd "$ROOT"
else
    echo "  Tomcat container already running."
fi

# ── 2. Create a scratch webapp in Tomcat for JSP compilation ────────────────
echo "  Creating scratch webapp: jsp-compile"
docker exec "$CONTAINER" mkdir -p /usr/local/tomcat/webapps/jsp-compile/WEB-INF

mkdir -p /tmp/ysrc_compile_staging

# ── 3. Compile each JSP ────────────────────────────────────────────────────
echo "  Compiling JSPs (one curl request each)..."
compiled=0
failed=0

for jsp in "$JSP_SRC"/*.jsp; do
    name="$(basename "$jsp" .jsp)"
    safe_name="${name:0:60}"   # truncate long sha1 names for safety

    # Copy JSP into container
    docker cp "$jsp" "$CONTAINER:/usr/local/tomcat/webapps/jsp-compile/${safe_name}.jsp" 2>/dev/null || continue

    # Trigger Jasper compilation
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://localhost:8080/jsp-compile/${safe_name}.jsp" 2>/dev/null || echo "000")

    if [ "$code" = "200" ] || [ "$code" = "500" ]; then
        # 200 = compiled OK; 500 = compiled but threw runtime error (still produces .class)
        compiled=$((compiled + 1))
    else
        failed=$((failed + 1))
    fi
done

echo "  Triggered: $compiled ok, $failed unreachable"

# ── 4. Extract compiled .class files from the work volume ───────────────────
echo "  Extracting .class files from Tomcat work volume..."
mkdir -p "$OUT_DIR"

TMP_EXTRACT="/tmp/ysrc_class_extract"
rm -rf "$TMP_EXTRACT" && mkdir -p "$TMP_EXTRACT"

docker exec "$CONTAINER" sh -c \
    "find /usr/local/tomcat/work -name '*jsp*.class' 2>/dev/null" \
    | while read -r class_path; do
        dest="$TMP_EXTRACT/$(basename "$class_path")"
        docker cp "$CONTAINER:$class_path" "$dest" 2>/dev/null || true
    done

# MD5-deduplicate into OUT_DIR
added=0
for f in "$TMP_EXTRACT"/*.class; do
    [ -f "$f" ] || continue
    md5=$(md5sum "$f" | cut -d' ' -f1)
    dest="$OUT_DIR/${md5}.class"
    if [ ! -f "$dest" ]; then
        cp "$f" "$dest"
        added=$((added + 1))
    fi
done

echo "  Added $added new .class files to webshell_file/"

# ── 5. Cleanup ───────────────────────────────────────────────────────────────
docker exec "$CONTAINER" rm -rf /usr/local/tomcat/webapps/jsp-compile 2>/dev/null || true
rm -rf "$TMP_EXTRACT"

echo ""
echo "=== Done ==="
echo "  New .class files: $added"
echo "  Total in webshell_file/: $(find "$OUT_DIR" -name '*.class' | wc -l)"
echo ""
echo "Next steps:"
echo "  python3 scripts/03_build_grayscale.py   # generates PNGs for new samples"
echo "  python3 scripts/04_train_resnet50.py     # retrain"
