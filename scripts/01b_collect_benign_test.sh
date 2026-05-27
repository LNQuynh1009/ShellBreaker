#!/usr/bin/env bash
# 01b_collect_benign_test.sh — Download benign JARs for the held-out test set.
#
# Downloads from Maven Central into dataset/benign_test_jars/.
# All domains are OUTSIDE the training set (no spring, netty, tomcat,
# hibernate, shiro, struts, jersey, mybatis, jackson, gson, commons-lang/io/collections,
# mockito, junit5, retrofit, rxjava).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dataset/benign_test_jars"
mkdir -p "$OUT"

BASE="https://repo1.maven.org/maven2"

dl() {
    local group_path="$1" artifact="$2" version="$3"
    local fname="${artifact}-${version}.jar"
    local url="${BASE}/${group_path}/${artifact}/${version}/${fname}"
    if [[ -f "$OUT/$fname" ]]; then
        echo "  skip (exists): $fname"
    else
        echo "  downloading: $fname"
        curl -fsSL --retry 3 -o "$OUT/$fname" "$url"
    fi
}

echo "=== Step 01b: Download benign test JARs (held-out domains) ==="
echo "  Target: $OUT"
echo ""

dl "org/apache/kafka"                          "kafka-clients"    "3.7.0"
dl "org/apache/logging/log4j"                  "log4j-core"       "2.23.1"
dl "org/apache/poi"                            "poi"              "5.2.5"
dl "org/apache/commons"                        "commons-math3"    "3.6.1"
dl "org/apache/httpcomponents/client5"         "httpclient5"      "5.3.1"
dl "redis.clients"                             "jedis"            "5.1.0"
dl "org/apache/lucene"                         "lucene-core"      "9.10.0"

echo ""
echo "Done. JARs in: $OUT"
echo "Next step: run scripts/02c_extract_benign_test.py"
