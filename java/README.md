# tattletale, the Java version

A Java 25 port of `python/tattletale.py` with the same features, flags, settings, database,
log format and page data file. It uses the JDK and nothing else (no Maven, no Gradle, no
third-party libraries), and it builds to a GraalVM native binary.

Both versions share one data directory, `<repo>/data/`, one database (schema v1, the same
`CREATE` statements), one page (`dashboard/tattletale.html`, copied into `data/`) and one
`tattletale.pid`. Run one of them at a time. The Java version refuses to start while a Python or
Java tattletale holds the pid file.

## Build

    sh java/build.sh              # jar, then the native binary if GraalVM is found
    sh java/build.sh --jar-only   # jar only

- `javac` (from `$JAVA_HOME`, else `PATH`) compiles into `java/build/classes`.
- `jar` writes `java/build/tattletale.jar` (Main-Class `dev.tattletale.Main`, runnable with
  `java -jar`).
- If `$GRAALVM_HOME/bin/native-image` exists, it builds `java/build/tattletale`, a native binary
  of about 20 MB. Its reachability metadata ships in the jar under
  `META-INF/native-image/dev.tattletale/tattletale/`: one foreign downcall
  (`proc_pidpath`). Nothing reflective is needed.

javac prints three warnings that cannot be suppressed: `sun.misc.Signal` "is internal
proprietary API". It is the JDK's own `jdk.unsupported` module and the only way to handle
SIGINT and SIGTERM without exiting the JVM (see below).

## Run

    java -jar java/build/tattletale.jar            # or: java/build/tattletale
    java -jar java/build/tattletale.jar --report
    java -jar java/build/tattletale.jar --query "SELECT exe, signer FROM programs WHERE signer LIKE 'unsigned%'"
    java -jar java/build/tattletale.jar --show-settings
    java -jar java/build/tattletale.jar --version  # tattletale 0.0.2

Every flag, environment variable and `tattletale.env` line is the Python version's (see
`tattletale.env.example`). The precedence is the same: flag > `TATTLETALE_*` environment
variable > `tattletale.env` > default.

At login: `sh java/install-login-agent.sh` (with `--dry-run` to print the agent file and change
nothing), and `sh java/uninstall-login-agent.sh` to remove it. The agent runs the native binary
if one is built, else `java -jar`. Its label is `io.github.tattletale`, the same agent as the
Python one, so installing either version replaces the other.

## Where it looks for the repository

The repository is three levels above the running code: `<repo>/java/build/tattletale.jar`,
`<repo>/java/build/classes`, or the native binary `<repo>/java/build/tattletale`. The path is
resolved through symlinks. The jar's location comes from its code source; the native binary's
from its own executable path. If that does not land in a folder holding `java/`, it falls back
to the working directory: the working directory itself if it holds `java/` or `dashboard/`, its
parent if it is `java/`, else the working directory as is.

## How it works, and how it differs from the Python version

- **SQLite** goes through one long-lived `/usr/bin/sqlite3 -safe -batch -json` process per
  connection, the way Python keeps one `sqlite3.Connection`. PRAGMAs, WAL mode and the 30 s busy
  timeout are set once. Each batch ends with a `.print` marker, and a transaction is
  `BEGIN` … `COMMIT`, or `ROLLBACK` if any statement failed. Values are bound as SQL literals
  (quotes doubled, CR and NUL spliced in with `char()`, since the shell would alter them inside
  a literal). One lock guards the log and the connection, as in Python.
- **`--query`** passes the statement to `sqlite3 -safe -readonly` as one argument, with
  `query_only` on. Python uses an authorizer; this version uses a read-only connection plus
  `-safe` (no `ATTACH`, no `load_extension`, no file functions). The same statements are refused,
  sometimes with different text: `WITH q AS (SELECT 1) DELETE FROM events` says "attempt to
  write a readonly database" where Python says "not authorized". Rows are byte-identical to
  Python's for text, integers, NULL and floats. BLOBs print raw, not as Python's `b'...'`.
- **Executable paths** come from libproc's `proc_pidpath`, the call Python makes through ctypes,
  made here through the JDK's Foreign Function API. `ProcessHandle.info().command()` is only a
  fallback: on macOS it returns nothing for root processes and keeps doubled slashes
  (`.../Support//cloudphotod`), so programs would be keyed differently from the Python version
  that shares the database.
- **Startup diffs** use a port of Python's `difflib.unified_diff` (context 1, `before`/`after`),
  not `/usr/bin/diff -u`, so the STARTUP~ text is the same. Checked against Python's difflib on
  400 random cases.
- **Signals**: SIGINT and SIGTERM set the stop flag. The loop then saves, logs STOP, closes the
  database, removes the pid file and exits 0, as Python does.
- **`log stream`** is stopped when the watcher stops, in both versions (the Python 0.0.1 left it
  running; fixed in 0.0.2).
- **Config file keys** are checked against the documented names, in both versions (Python 0.0.1
  refused every `TATTLETALE_*` line in `tattletale.env`; fixed in 0.0.2).
- **Pid file**: both versions treat a pid as a live tattletale when its command line has
  `tattletale.py`, `tattletale.jar`, `dev.tattletale.Main`, `java/build/tattletale`, or a first
  word named `tattletale`, so neither takes over a database the other is watching.
- **Small things**: the usage line says `tattletale`, not `tattletale.py`. `~user` in a path is
  expanded only for the current user. Map-import JSON errors are worded by this reader, not by
  Python's `json` module.
