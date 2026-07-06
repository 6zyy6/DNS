#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

mkdir -p build/classes build/test-classes
javac -encoding UTF-8 -d build/classes $(find src/main/java -name '*.java' | sort)
javac -encoding UTF-8 -cp build/classes -d build/test-classes $(find src/test/java -name '*.java' | sort)
java -cp build/classes:build/test-classes dnsrelay.AllTests
