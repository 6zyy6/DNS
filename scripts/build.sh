#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

mkdir -p build/classes
javac -encoding UTF-8 -d build/classes $(find src/main/java -name '*.java' | sort)

echo "Compiled main classes to build/classes"
echo "Run with: java -cp build/classes dnsrelay -dd 114.114.114.114 dnsrelay.txt"
