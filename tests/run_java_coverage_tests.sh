#!/bin/sh
# Synthetic databases and injected child processes only. Caller supplies fresh receipt paths.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
sh java/build.sh --jar-only
mkdir -p java/build/test-classes
"$JAVA_HOME/bin/javac" --release 25 -encoding UTF-8 -Xlint:all,-options -cp java/build/tattletale.jar -d java/build/test-classes java/src/test/java/dev/tattletale/*.java
exec "$JAVA_HOME/bin/java" --enable-native-access=ALL-UNNAMED -cp java/build/tattletale.jar:java/build/test-classes dev.tattletale.CoverageTest --fixtures tests/fixtures/coverage.json "$@"
