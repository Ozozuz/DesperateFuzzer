#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
JAVAC="$JAVA_HOME/bin/javac"
JAR="$JAVA_HOME/bin/jar"
MONTOYA_API="$ROOT_DIR/lib/montoya-api-2026.4.jar"
MONTOYA_API_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.4/montoya-api-2026.4.jar"
CLASSES_DIR="$ROOT_DIR/build/classes"
JAR_PATH="$ROOT_DIR/build/libs/UnusualFuzzer-0.1.0.jar"

if [[ ! -x "$JAVAC" ]]; then
    echo "Missing javac: $JAVAC" >&2
    exit 1
fi

if [[ ! -f "$MONTOYA_API" ]]; then
    mkdir -p "$(dirname "$MONTOYA_API")"
    curl -fsSL -o "$MONTOYA_API" "$MONTOYA_API_URL"
fi

rm -rf "$CLASSES_DIR"
mkdir -p "$CLASSES_DIR" "$(dirname "$JAR_PATH")"

"$JAVAC" \
    --release 17 \
    -cp "$MONTOYA_API" \
    -d "$CLASSES_DIR" \
    $(find "$ROOT_DIR/src/main/java" -name '*.java' | sort)

"$JAR" --create --file "$JAR_PATH" -C "$CLASSES_DIR" .

echo "$JAR_PATH"
