#!/bin/sh
# Build the Java version of tattletale from the JDK alone (no Maven, no Gradle, no downloads).
#   sh java/build.sh             javac -> java/build/classes, jar -> java/build/tattletale.jar,
#                                then a native binary java/build/tattletale if GraalVM's
#                                native-image is found ($GRAALVM_HOME/bin/native-image)
#   sh java/build.sh --jar-only  stop after the jar
# Works from any directory: paths are taken relative to this script.
set -eu
here=$(cd "$(dirname "$0")" && pwd) || { echo "build: cannot locate this folder" >&2; exit 2; }
cd "$here"

if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
    bin="$JAVA_HOME/bin/"
else
    bin=""
fi
javac="${bin}javac"
jar="${bin}jar"
command -v "$javac" >/dev/null 2>&1 || { echo "build: javac not found (set JAVA_HOME to a JDK 25)" >&2; exit 2; }

rm -rf build/classes
mkdir -p build/classes
# Every source file, newline-separated in a file javac reads with @ (paths here hold no spaces).
find src/main/java -name '*.java' | sort > build/sources.txt
"$javac" --release 25 -encoding UTF-8 -Xlint:all,-options -d build/classes @build/sources.txt
cp -R src/main/resources/. build/classes/

cat > build/manifest.txt <<MF
Main-Class: dev.tattletale.Main
Enable-Native-Access: ALL-UNNAMED
MF
rm -f build/tattletale.jar
"$jar" --create --file build/tattletale.jar --manifest build/manifest.txt -C build/classes .
echo "built $here/build/tattletale.jar"

if [ "${1:-}" = "--jar-only" ]; then
    exit 0
fi

ni="${GRAALVM_HOME:-}/bin/native-image"
if [ -n "${GRAALVM_HOME:-}" ] && [ -x "$ni" ]; then
    "$ni" -jar build/tattletale.jar -o build/tattletale
    echo "built $here/build/tattletale"
else
    echo "native-image not found (set GRAALVM_HOME to a GraalVM 25); skipped the native binary"
fi
