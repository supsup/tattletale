#!/bin/sh
# Synthetic fixture tests only; explicit receipt paths, no watcher or native-image.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
sh java/build.sh --jar-only
mkdir -p java/build/test-classes
"$JAVA_HOME/bin/javac" --release 25 -encoding UTF-8 -Xlint:all,-options -cp java/build/tattletale.jar -d java/build/test-classes java/src/test/java/dev/tattletale/CollectionHealthTest.java
exec "$JAVA_HOME/bin/java" -Duser.home="$HOME" -cp java/build/tattletale.jar:java/build/test-classes dev.tattletale.CollectionHealthTest --fixtures tests/fixtures/collection-health.json "$@"
