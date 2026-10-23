#!/usr/bin/env python3
"""tattletale: one small read-only watcher for four kinds of change on this Mac, one log.

  1. CREDENTIAL PROMPTS  every 3 s. Any git credential helper, git-remote-https, ssh-askpass,
     SecurityAgent or similar process is logged EVERY time a new instance appears, with its
     parent chain, so the program that asked is named. A `log stream` on SecurityAgent (the
     macOS password dialog) runs alongside as a second source.
  2. LISTENING PORTS     every 30 s. Each new (program, address, port) TCP listener is logged;
     a listener on all interfaces (*, 0.0.0.0, ::) is flagged EXPOSED.
  3. NEW PROGRAMS        every 3 s. The full process list (not just the busy ones); each
     executable path never seen before is logged once, with its parent chain.
  4. STARTUP ITEMS       every 5 min. Launch agents and daemons, crontab, shell startup files:
     added, changed or removed files are logged.

First run: everything present is recorded as the baseline and not logged as new. The state is
kept in one SQLite database (tattletale.db), so a restart does not re-report. Its tables:

  programs           one row per executable path ever seen, with its sha256 and signer
  sightings          one row per new process instance (a pid seen for the first time)
  listeners          one row per (program, address, port) TCP listener; present = listening now
  credential_events  each credential helper or password dialog seen (source ps or log)
  startup_items      the current hash of each startup item
  startup_versions   each version of a startup item seen, with the path of its saved copy
  events             every line written to the log

Sightings older than sightings_retention_days (7) and events and credential events older than
retention_days (30) are deleted on start and
hourly; programs, listeners and startup rows are kept. If the database is empty and an older
JSON map (tattletale-map.json) exists, it is imported once on start; the JSON map is never
written. tattletale-data.js (for tattletale.html) and startup-snapshots/ are kept next to the
database. Stop with Ctrl-C or SIGTERM.

Usage:
  python3 tattletale.py                    # log and database next to this script
  python3 tattletale.py --log ~/tattletale.log --db ~/tattletale.db
  python3 tattletale.py --report           # summary of the database
  python3 tattletale.py --query "SELECT exe, signer FROM programs WHERE signer LIKE 'unsigned%'"

Read-only: it runs ps, lsof, log and crontab -l, reads files, and writes only its log, its
database, its page data file and its startup copies.
"""
import argparse
import contextlib
import difflib
import queue
import re
import shutil
import datetime as dt
import hashlib
import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import ctypes
import time
import urllib.parse
import ipaddress

HERE = os.path.dirname(os.path.abspath(__file__))
# v0.0.2 layout: <repo>/python/tattletale.py; the Java version shares <repo>/data/ and the page.
REPO = os.path.dirname(HERE)
DATA = os.path.join(REPO, "data")
DASHBOARD = os.path.join(REPO, "dashboard", "tattletale.html")
HOME = os.path.expanduser("~")

# Programs that ask for, or broker, a credential. Matched on the executable's base name.
CRED_NAMES = ("git-credential", "git-remote-https", "git-remote-http", "ssh-askpass",
              "SecurityAgent", "askpass", "pinentry", "gh-credential", "credential-helper")

STARTUP_DIRS = [os.path.join(HOME, "Library/LaunchAgents"), "/Library/LaunchAgents",
                "/Library/LaunchDaemons", "/Library/StartupItems"]
STARTUP_FILES = [os.path.join(HOME, f) for f in
                 (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile",
                  ".profile", ".config/fish/config.fish")] + ["/etc/zshrc", "/etc/profile",
                                                              "/etc/paths", "/etc/hosts"]

# One lock guards the log file and the one database connection; every thread takes it before
# touching either. It is not re-entrant: never call Watch.log() while holding it.
lock = threading.Lock()

try:
    _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    _libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    _libproc.proc_pidpath.restype = ctypes.c_int
except OSError:
    _libproc = None


def pid_path(pid):
    """The kernel's executable path for a pid (what ps shows as a bare name, e.g. "perl",
    resolved to /usr/bin/perl), or None if it cannot be read."""
    if type(pid) is not int or not 0 < pid <= 2147483647:
        raise CollectionError("ps-parse")
    if _libproc is None:
        return None
    buf = ctypes.create_string_buffer(4096)
    n = _libproc.proc_pidpath(pid, buf, 4096)
    return buf.value.decode("utf-8", "replace") if n > 0 else None


def is_tattletale(command):
    """True when a ps command line is a Tattletale watcher: the Python script, the Java jar,
    or the Java native binary (java/build/tattletale)."""
    # Kept identical to the Java version's isTattletaleCommand.
    if ("tattletale.py" in command or "tattletale.jar" in command
            or "dev.tattletale.Main" in command or "java/build/tattletale" in command):
        return True
    first = command.split(None, 1)[0] if command.split() else ""
    return os.path.basename(first) == "tattletale"


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- database ----
__version__ = "0.0.2"
SCHEMA_VERSION = 1
FORMAT_VERSION = 2
CHECKS = ("processes", "listeners", "startup", "crontab")
ASCII_WS = " \t\r\n\v\f"


class CollectionError(ValueError):
    """A fixed, non-observed diagnostic; never put command output in health."""


class FatalDatabaseError(RuntimeError):
    """The connection is unusable; propagate past recoverable polling errors."""


def bounded_ascii_number(value, minimum, maximum, reason):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise CollectionError(reason)
    canonical = value.lstrip("0") or "0"
    if len(canonical) > len(str(maximum)) or not minimum <= int(canonical) <= maximum:
        raise CollectionError(reason)
    return int(canonical)


def checked_pid(value, reason, zero=False):
    return bounded_ascii_number(value, 0 if zero else 1, 2147483647, reason)


def ascii_split(value, maxsplit=0):
    return re.split(r"[ \t\r\n\v\f]+", value.strip(ASCII_WS), maxsplit=maxsplit)


def bind_scope(host):
    """Classify a literal bind address, without DNS or reachability claims."""
    if not isinstance(host, str) or not host or host != host.strip():
        return "unknown"
    if host == "*":
        return "wildcard"
    if host.startswith("[") or host.endswith("]"):
        if not (host.startswith("[") and host.endswith("]")):
            return "unknown"
        host = host[1:-1]
        if ":" not in host:
            return "unknown"
    if "%" in host:
        host, sep, zone = host.partition("%")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", zone) or ":" not in host:
            return "unknown"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    address = getattr(address, "ipv4_mapped", None) or address
    if address.is_unspecified:
        return "wildcard"
    return "loopback" if address.is_loopback else "non-loopback"


def command_result(argv, timeout):
    """Run one collector with strict decoding. Callers validate its exit policy."""
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout,
                                env=dict(os.environ, LC_ALL="C"))
        out = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
        err = result.stderr.decode("utf-8") if isinstance(result.stderr, bytes) else result.stderr
    except subprocess.TimeoutExpired:
        raise CollectionError("collection-timeout") from None
    except (OSError, subprocess.SubprocessError):
        raise CollectionError("collection-io") from None
    except UnicodeError:
        raise CollectionError("collection-parse") from None
    if not isinstance(out, str) or not isinstance(err, str):
        raise CollectionError("collection-parse")
    return (result.returncode, out.replace("\r\n", "\n").replace("\r", "\n"),
            err.replace("\r\n", "\n").replace("\r", "\n"))


def command_policy(tool, code, out, err):
    """The supported empty-result conventions, separate from inventory parsing."""
    if tool == "lsof" and code == 1 and out == "" and err == "":
        return "ok-empty"
    if tool == "crontab" and code == 1 and out == "" and re.fullmatch(
            r"(?:crontab: )?no crontab for [^ \t\r\n\v\f]+\n?", err):
        return "ok-absent"
    if tool == "lsof" and code == 0 and err:
        raise CollectionError("lsof-warning")
    if code != 0:
        raise CollectionError(tool + "-command")
    if err:
        raise CollectionError(tool + "-command")
    return "ok-empty" if not out else "ok"
SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS programs(
  exe TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, user TEXT, first_pid INTEGER,
  first_args TEXT, parent TEXT, sha256 TEXT, size INTEGER, signer TEXT, team TEXT,
  signing_id TEXT);
CREATE TABLE IF NOT EXISTS sightings(
  id INTEGER PRIMARY KEY, time TEXT, pid INTEGER, exe TEXT, user TEXT, args TEXT, chain TEXT);
CREATE TABLE IF NOT EXISTS listeners(
  key TEXT PRIMARY KEY, exe TEXT, address TEXT, port INTEGER, command TEXT, pid INTEGER,
  user TEXT, args TEXT, chain TEXT, exposed INTEGER, present INTEGER, first_seen TEXT,
  last_seen TEXT);
CREATE TABLE IF NOT EXISTS credential_events(
  id INTEGER PRIMARY KEY, time TEXT, source TEXT, pid INTEGER, user TEXT, exe TEXT, args TEXT,
  chain TEXT);
CREATE TABLE IF NOT EXISTS startup_items(path TEXT PRIMARY KEY, hash TEXT, last_checked TEXT);
CREATE TABLE IF NOT EXISTS startup_versions(
  id INTEGER PRIMARY KEY, path TEXT, hash TEXT, copy_path TEXT, seen_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, time TEXT, kind TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS programs_first_seen ON programs(first_seen);
CREATE INDEX IF NOT EXISTS sightings_time ON sightings(time);
CREATE INDEX IF NOT EXISTS sightings_exe ON sightings(exe);
CREATE INDEX IF NOT EXISTS listeners_first_seen ON listeners(first_seen);
CREATE INDEX IF NOT EXISTS credential_events_time ON credential_events(time);
CREATE INDEX IF NOT EXISTS startup_versions_seen_at ON startup_versions(seen_at);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
"""
RETAINED_TABLES = ("sightings", "events", "credential_events")


def open_db(path):
    """The watcher's read-write connection: WAL mode, foreign keys off, autocommit (batches
    use explicit transactions). check_same_thread is off because every use is under `lock`."""
    if not os.path.exists(path):
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))  # machine data: owner only
    try:
        conn = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(SCHEMA)
        v = conn.execute("SELECT max(version) FROM schema_version").fetchone()[0]
        if v is None:
            conn.execute("INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,))
        elif v > SCHEMA_VERSION:
            sys.exit(f"tattletale: {path} has schema version {v}; this tattletale knows {SCHEMA_VERSION}")
    except sqlite3.Error as e:
        sys.exit(f"tattletale: cannot open database {path}: {e}")
    return conn


def open_db_readonly(path):
    if not os.path.exists(path):
        return None
    uri = "file:" + urllib.parse.quote(os.path.abspath(path)) + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30)
    conn.execute("PRAGMA query_only=ON")
    return conn


@contextlib.contextmanager
def transaction(conn):
    try:
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except BaseException as original:
        try:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
        except sqlite3.Error:
            try:
                conn.close()  # Unknown transaction state must never be reused.
            except sqlite3.Error:
                pass
            raise FatalDatabaseError("collection-db-fatal") from original
        raise


class Watch:
    def __init__(self, log_path, db_path, listen_every=30, startup_every=300, extra_startup=(),
                 notify=True, rotate_bytes=20 * 1024 * 1024, keep_logs=3, process_every=3,
                 map_path=None, retention_days=30, sightings_retention_days=7):
        self.log_path, self.db_path, self.map_path = log_path, db_path, map_path
        self.notify_on, self.rotate_bytes, self.keep_logs = notify, rotate_bytes, keep_logs
        self.process_every = process_every
        self.retention_days = retention_days
        self.sightings_retention_days = sightings_retention_days
        self.last_notified = {}
        self.stream_pids = {}
        self.listen_every, self.startup_every = listen_every, startup_every
        self.extra_startup = list(extra_startup)
        self.data_dir = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(self.data_dir, exist_ok=True)
        self.snap_dir = os.path.join(self.data_dir, "startup-snapshots")
        self.db = open_db(db_path)
        self.cred_seen_pids = set()
        self.stop = threading.Event()
        self.ident_q = queue.Queue()
        # In-memory mirrors of what the hot paths need; the database is the record.
        self.known_progs = set()     # exe paths in programs
        self.listeners = {}          # key -> {"present": bool, "exposed": bool}
        self.startup = {}            # path -> hash, as in startup_items
        self.announce = {}           # exe -> first command line, for NEW programs awaiting IDENTITY
        self.prev_pids = None        # pid -> exe at the last process scan (None before the first)
        self.dirty_progs, self.dirty_listeners = {}, {}   # last_seen updates, flushed by save()
        self.baseline = {}
        self.crontab_text = ""
        # Health describes this watcher epoch; persisted inventory may be older.
        self.collection_health = {k: {"lastAttempt": None, "lastSuccess": None,
                                      "status": "unknown", "error": None} for k in CHECKS}

    def _attempt(self, name):
        with lock:
            self.collection_health[name]["lastAttempt"] = now()

    def _accepted(self, name):
        with lock:
            self.collection_health[name].update(lastSuccess=now(), status="ok", error=None)

    def _rejected(self, name, error):
        if isinstance(error, CollectionError):
            reason = str(error) if str(error) in {"ps-command", "ps-parse", "lsof-command",
                "lsof-parse", "lsof-warning", "crontab-command", "startup-read", "startup-unreadable", "collection-io",
                "collection-timeout", "collection-db", "collection-parse"} else "collection-parse"
        elif isinstance(error, sqlite3.Error):
            reason = "collection-db"
        elif isinstance(error, subprocess.TimeoutExpired):
            reason = "collection-timeout"
        elif isinstance(error, OSError):
            reason = "collection-io"
        else:
            reason = "collection-parse"
        with lock:
            previous = self.collection_health[name]
            warning_transition = (name == "listeners" and reason == "lsof-warning"
                                  and not (previous["status"] == "degraded"
                                           and previous["error"] == "lsof-warning"))
            self.collection_health[name].update(status="degraded", error=reason[:64])
        if warning_transition:
            self.log("NOTE", "listeners collection degraded: lsof-warning")

    # ---- persistence ----
    def load_state(self):
        """Import the old JSON map into an empty database, then read the mirrors and work out
        which checks are on their first (baseline) run."""
        self.import_map()
        with lock:
            c = self.db
            self.known_progs = {r[0] for r in c.execute("SELECT exe FROM programs")}
            self.listeners = {k: {"present": bool(p), "exposed": bool(e)}
                              for k, p, e in c.execute("SELECT key, present, exposed FROM listeners")}
            self.startup = dict(c.execute("SELECT path, hash FROM startup_items ORDER BY path"))
            for (exe,) in c.execute("SELECT exe FROM programs WHERE sha256 IS NULL AND exe LIKE '/%'"):
                self.ident_q.put(exe)
        self.baseline = {"programs": not self.known_progs, "listeners": not self.listeners,
                         "startup": not any(p != "crontab -l" for p in self.startup),
                         "crontab": "crontab -l" not in self.startup}

    def import_map(self):
        """One-time import of the old JSON map, only into a database with no programs."""
        if not self.map_path or not os.path.exists(self.map_path):
            return
        with lock:
            if self.db.execute("SELECT count(*) FROM programs").fetchone()[0]:
                return
        try:
            with open(self.map_path) as f:
                s = json.load(f)
        except (OSError, ValueError) as e:
            self.log("ERROR", f"cannot import map {self.map_path}: {e}")
            return
        progs, ls = s.get("programs", {}), s.get("listeners", {})
        creds, startup = s.get("credentials", []), s.get("startup", {})
        t = now()
        with lock, transaction(self.db) as c:
            c.executemany(
                "INSERT OR IGNORE INTO programs(exe, first_seen, last_seen, user, first_pid, first_args,"
                " parent, sha256, size, signer, team, signing_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(exe, v.get("firstSeen"), v.get("lastSeen"), v.get("user"), v.get("firstPid"),
                  v.get("firstArgs"), v.get("parent"), v.get("sha256"), v.get("size"), v.get("signer"),
                  v.get("team"), v.get("signingId")) for exe, v in progs.items()])
            # A map from before the present flag existed says nothing about what is listening
            # now; import those as not present, so the first scan marks the live ones present
            # silently instead of logging an UNLISTEN for every old listener.
            rows = []
            for key, v in ls.items():
                exe, _, addr = key.rpartition(" ")
                host, _, port = addr.rpartition(":")
                rows.append((key, exe, host, int(port) if port.isdigit() else None, v.get("command"),
                             v.get("pid"), v.get("user"), v.get("args"), v.get("chain"),
                             int(bool(v.get("exposed"))), int(bool(v.get("present", False))),
                             v.get("firstSeen"), v.get("lastSeen")))
            c.executemany("INSERT OR IGNORE INTO listeners(key, exe, address, port, command, pid, user,"
                          " args, chain, exposed, present, first_seen, last_seen)"
                          " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            c.executemany("INSERT INTO credential_events(time, source, pid, user, exe, args, chain)"
                          " VALUES (?,?,?,?,?,?,?)",
                          [(v.get("time"), v.get("source", "ps"), v.get("pid"), v.get("user"),
                            v.get("exe"), v.get("args"), v.get("chain")) for v in creds])
            c.executemany("INSERT OR REPLACE INTO startup_items(path, hash, last_checked) VALUES (?,?,?)",
                          [(p, h, t) for p, h in startup.items()])
            vrows = []
            for p, h in startup.items():
                copy = os.path.join(self.snap_dir, self.safe_name(p), str(h)[:16])
                vrows.append((p, h, copy if os.path.exists(copy) else None, t))
            c.executemany("INSERT INTO startup_versions(path, hash, copy_path, seen_at) VALUES (?,?,?,?)",
                          vrows)
        self.log("IMPORT", f"imported {self.map_path}: {len(progs)} programs, {len(ls)} listeners, "
                           f"{len(creds)} credential events, {len(startup)} startup items; "
                           f"the JSON map is no longer written")

    def retain(self):
        """Delete old rows. Sightings (one per new process instance, which is the busiest table:
        tens per minute on a developer machine) have their own, shorter window,
        sightings_retention_days; events and credential events use retention_days. 0 keeps
        that table forever."""
        def cutoff(days):
            return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        windows = {"sightings": self.sightings_retention_days, "events": self.retention_days,
                   "credential_events": self.retention_days}
        counts = {}
        with lock, transaction(self.db) as c:
            for tbl in RETAINED_TABLES:
                days = windows[tbl]
                if days > 0:
                    counts[tbl] = c.execute(f"DELETE FROM {tbl} WHERE time < ?", (cutoff(days),)).rowcount
        if sum(counts.values()):
            self.log("RETENTION", "deleted old rows: " + ", ".join(
                f"{k} {v} (older than {windows[k]} days)" for k, v in counts.items()))

    def save(self):
        """Flush last-seen times to the database and rewrite the page data file."""
        with lock:
            with transaction(self.db) as c:
                c.executemany("UPDATE programs SET last_seen=? WHERE exe=?",
                              [(t, exe) for exe, t in self.dirty_progs.items()])
                c.executemany("UPDATE listeners SET last_seen=? WHERE key=?",
                              [(t, k) for k, t in self.dirty_listeners.items()])
            self.dirty_progs, self.dirty_listeners = {}, {}
            m = self.page_map()
        self.write_page_data(self.data_dir, m)

    def page_map(self):
        """The dashboard's "map" object, built from the database in the shape the old JSON
        map had (identity keys are absent until known: the page tests `"signer" in v`).
        Caller holds the lock."""
        c = self.db
        programs = {}
        for r in c.execute("SELECT exe, first_seen, last_seen, user, first_pid, first_args, parent,"
                           " sha256, size, signer, team, signing_id FROM programs"):
            v = {"firstSeen": r[1], "lastSeen": r[2], "user": r[3], "firstPid": r[4],
                 "firstArgs": r[5], "parent": r[6]}
            for k, x in zip(("sha256", "size", "signer", "team", "signingId"), r[7:]):
                if x is not None:
                    v[k] = x
            programs[r[0]] = v
        listeners = {}
        for r in c.execute("SELECT key, first_seen, last_seen, pid, command, exposed, user, args,"
                            " chain, present, address FROM listeners"):
            listeners[r[0]] = {"firstSeen": r[1], "lastSeen": r[2], "pid": r[3], "command": r[4],
                               "exposed": bool(r[5]), "user": r[6], "args": r[7], "chain": r[8],
                                "present": bool(r[9]), "bindScope": bind_scope(r[10])}
        creds = [{"time": r[0], "pid": r[1], "user": r[2], "exe": r[3], "args": r[4], "chain": r[5],
                  "source": r[6]}
                 for r in c.execute("SELECT time, pid, user, exe, args, chain, source FROM"
                                    " (SELECT * FROM credential_events ORDER BY id DESC LIMIT 500)"
                                    " ORDER BY id")]
        startup = dict(c.execute("SELECT path, hash FROM startup_items ORDER BY path"))
        return {"programs": programs, "listeners": listeners, "credentials": creds,
                "startup": startup}

    def write_page_data(self, d, state):
        """tattletale-data.js for tattletale.html: the map plus the last 500 log lines, as a
        script the page can load from disk (a page opened as a file cannot fetch JSON)."""
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 400_000))
                tail = f.read().decode("utf-8", "replace").splitlines()[-500:]
        except OSError:
            tail = []
        with lock:
            health = {k: dict(v) for k, v in self.collection_health.items()}
        payload = {"generatedAt": now(), "version": __version__, "pid": os.getpid(), "map": state,
                   "log": tail, "formatVersion": FORMAT_VERSION, "collectionHealth": health}
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tattletale-data.", suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            f.write("window.TATTLETALE = ")
            json.dump(payload, f, separators=(",", ":"))
            f.write(";\n")
        os.replace(tmp, os.path.join(d, "tattletale-data.js"))

    NOTIFY_KINDS = {"CREDENTIAL": "Credential prompt", "CRED-NET": "Git network credential lookup",
                    "LISTEN!": "Listener bound to all interfaces", "STARTUP+": "Startup item added",
                    "STARTUP~": "Startup item changed", "STARTUP-": "Startup item removed",
                    "UNSIGNED": "Unsigned program ran", "PASSWORD": "Password dialog"}

    def log(self, kind, msg, stored=False, event_time=None):
        t = event_time or now()
        line = f"{t}  {kind:<9} {msg}"
        with lock:
            self._rotate()
            with open(self.log_path, "a") as f:
                f.write(line + "\n")
            if not stored:
                try:
                    self.db.execute("INSERT INTO events(time, kind, message) VALUES (?,?,?)", (t, kind, msg))
                except sqlite3.Error as e:
                    print(f"tattletale: event not stored in database: {e}", file=sys.stderr, flush=True)
        print(line, flush=True)
        if kind in self.NOTIFY_KINDS:
            self.notify(kind, msg)

    def _rotate(self):
        """Keep the log under rotate_bytes: tattletale.log -> .1 -> .2 ... keep_logs old files."""
        try:
            if os.path.getsize(self.log_path) < self.rotate_bytes:
                return
        except OSError:
            return
        for i in range(self.keep_logs, 0, -1):
            src = self.log_path if i == 1 else f"{self.log_path}.{i - 1}"
            if os.path.exists(src):
                os.replace(src, f"{self.log_path}.{i}")

    def notify(self, kind, msg):
        """A macOS notification, at most one per kind per minute. Text is passed as an
        argument to osascript (never spliced into the script), so a program name cannot
        inject AppleScript."""
        if not self.notify_on:
            return
        t = time.monotonic()
        if t - self.last_notified.get(kind, float("-inf")) < 60:
            return
        self.last_notified[kind] = t
        script = ('on run argv\n display notification (item 2 of argv) with title "Tattletale" '
                  'subtitle (item 1 of argv)\nend run')
        try:
            subprocess.Popen(["osascript", "-e", script, self.NOTIFY_KINDS[kind], msg[:180]],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass

    # ---- process table ----
    @staticmethod
    def processes():
        """A complete, validated pair of ps samples; PID churn between them is normal."""
        code, out, err = command_result(["ps", "-axo", "pid=,ppid=,user=,comm="], 20)
        command_policy("ps", code, out, err)
        procs = {}
        for line in out.split("\n"):
            if not line.strip(ASCII_WS):
                continue
            parts = ascii_split(line, 3)
            if len(parts) != 4 or not parts[3].strip(ASCII_WS):
                raise CollectionError("ps-parse")
            pid = checked_pid(parts[0], "ps-parse")
            ppid = checked_pid(parts[1], "ps-parse", zero=True)
            if pid in procs:
                raise CollectionError("ps-parse")
            exe = parts[3].strip(ASCII_WS)
            if not exe.startswith("/") and not exe.startswith("("):
                exe = pid_path(pid) or exe
            procs[pid] = (ppid, parts[2], exe)
        if not procs:
            raise CollectionError("ps-parse")
        code, argv, err = command_result(["ps", "-axo", "pid=,args="], 20)
        command_policy("ps", code, argv, err)
        args = {}
        for line in argv.split("\n"):
            if not line.strip(ASCII_WS):
                continue
            parts = ascii_split(line, 1)
            pid = checked_pid(parts[0], "ps-parse")
            if pid in args:
                raise CollectionError("ps-parse")
            args[pid] = parts[1].strip(ASCII_WS) if len(parts) == 2 else ""
        if not args:
            raise CollectionError("ps-parse")
        return {pid: row + (args.get(pid, ""),) for pid, row in procs.items()}

    @staticmethod
    def chain(procs, pid, depth=6):
        names = []
        while pid in procs and depth > 0 and pid > 1:
            ppid, _, exe, _ = procs[pid]
            names.append(f"{os.path.basename(exe)}({pid})")
            pid, depth = ppid, depth - 1
        return " <- ".join(names) if names else "?"

    @staticmethod
    def identity(exe):
        """sha256 and code-signing identity of an executable file. Big files (over 512 MB) are
        not hashed; an unsigned or unreadable file says so."""
        out = {}
        try:
            size = os.path.getsize(exe)
            out["size"] = size
            if size <= 512 * 1024 * 1024:
                h = hashlib.sha256()
                with open(exe, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                out["sha256"] = h.hexdigest()
            else:
                out["sha256"] = "not hashed: larger than 512 MB"
        except OSError as e:
            out["sha256"] = f"unreadable: {e.strerror}"
        r = subprocess.run(["codesign", "-dv", "--verbose=2", exe], capture_output=True, text=True,
                           timeout=20)
        text = r.stderr
        auth = re.findall(r"^Authority=(.*)$", text, re.M)
        team = re.search(r"^TeamIdentifier=(.*)$", text, re.M)
        ident = re.search(r"^Identifier=(.*)$", text, re.M)
        if r.returncode != 0:
            out["signer"] = "unsigned or unreadable: " + " ".join(text.split())[:120]
        else:
            out["signer"] = auth[0] if auth else ("adhoc" if "Signature=adhoc" in text else "signed, no authority")
            out["team"] = team.group(1) if team else None
            out["signingId"] = ident.group(1) if ident else None
        return out

    def identity_worker(self):
        while not self.stop.is_set():
            try:
                exe = self.ident_q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                info = self.identity(exe)
            except (subprocess.SubprocessError, OSError) as e:
                info = {"sha256": f"failed: {e}"}
            try:
                with lock:
                    self.db.execute("UPDATE programs SET sha256=?, size=?, signer=?, team=?, signing_id=?"
                                    " WHERE exe=?", (info.get("sha256"), info.get("size"),
                                                     info.get("signer"), info.get("team"),
                                                     info.get("signingId"), exe))
            except sqlite3.Error as e:
                self.log("ERROR", f"identity of {exe} not stored: {e}")
            self.baseline_logged_identity(exe, info)

    def baseline_logged_identity(self, exe, info):
        """Log a NEW program's identity once it is known (baseline programs are not logged)."""
        with lock:
            first_args = self.announce.pop(exe, None)
        if first_args is not None:
            self.log("IDENTITY", f"{exe} | signer: {info.get('signer')} team: {info.get('team')} "
                                 f"| sha256: {info.get('sha256')}")
            signer = str(info.get("signer", ""))
            if signer.startswith("unsigned") or signer == "adhoc":
                self.log("UNSIGNED", f"{exe} ran with no named signer ({signer[:60]}) "
                                     f"| first command line: {first_args[:200]}")
            return True
        return False

    @staticmethod
    def args(pid):
        r = subprocess.run(["ps", "-o", "args=", "-p", str(pid)], capture_output=True, text=True)
        return " ".join(r.stdout.split())[:300]

    # ---- 1 and 3: processes ----
    def check_processes(self):
        self._attempt("processes")
        try:
            procs = self.processes()
            t = now()
            first_scan = self.prev_pids is None
            cur, new_progs, sightings, creds, events = {}, [], [], [], []
            known, cred_seen = set(self.known_progs), set(self.cred_seen_pids)
            announce, dirty = {}, dict(self.dirty_progs)
            for pid, (ppid, user, exe, argline) in procs.items():
                if (exe.startswith("(") and exe.endswith(")")) or exe == "<defunct>":
                    continue
                cur[pid] = exe
                if first_scan or self.prev_pids.get(pid) != exe:
                    sightings.append((t, pid, exe, user, argline[:1000], self.chain(procs, pid, 8)))
                base = os.path.basename(exe)
                head = " ".join(os.path.basename(a) for a in argline.split()[:2])
                if (any(c.lower() in base.lower() or c.lower() in head.lower() for c in CRED_NAMES)
                        and pid not in cred_seen):
                    cred_seen.add(pid)
                    if not self.baseline["programs"]:
                        chain = self.chain(procs, pid)
                        events.append(("CREDENTIAL", f"pid {pid} user {user} {exe} | args: {argline[:300]} "
                                       f"| chain: {chain}"))
                        creds.append((t, "ps", pid, user, exe, argline[:1000], self.chain(procs, pid, 12)))
                if exe not in known:
                    known.add(exe)
                    new_progs.append((exe, t, t, user, pid, argline[:1000], self.chain(procs, ppid, 6)))
                    if not self.baseline["programs"]:
                        announce[exe] = argline[:1000]
                        events.append(("NEW-PROG", f"pid {pid} user {user} {exe} | args: {argline[:300]} "
                                       f"| chain: {self.chain(procs, pid)}"))
                else:
                    dirty[exe] = t
            if self.baseline["programs"]:
                events.append(("BASELINE", f"programs: {len(known)} recorded"))
            with lock:
                with transaction(self.db) as c:
                    c.executemany("INSERT OR IGNORE INTO programs(exe, first_seen, last_seen, user, first_pid,"
                                  " first_args, parent) VALUES (?,?,?,?,?,?,?)", new_progs)
                    if first_scan:
                        sightings = [s for s in sightings if c.execute(
                            "SELECT 1 FROM sightings WHERE exe=? AND pid=? LIMIT 1", (s[2], s[1])).fetchone() is None]
                    c.executemany("INSERT INTO sightings(time, pid, exe, user, args, chain) VALUES (?,?,?,?,?,?)",
                                  sightings)
                    c.executemany("INSERT INTO credential_events(time, source, pid, user, exe, args, chain)"
                                  " VALUES (?,?,?,?,?,?,?)", creds)
                    c.executemany("INSERT INTO events(time, kind, message) VALUES (?,?,?)",
                                  [(t, kind, message) for kind, message in events])
                self.known_progs, self.cred_seen_pids = known, cred_seen & set(procs)
                # Identity completion can remove older announcements during collection.
                self.announce.update(announce)
                self.dirty_progs, self.prev_pids = dirty, cur
                self.baseline["programs"] = False
        except (OSError, subprocess.SubprocessError, sqlite3.Error, ValueError,
                TypeError, KeyError, OverflowError, ctypes.ArgumentError) as e:
            self._rejected("processes", e)
            return False
        for row in new_progs:
            if row[0].startswith("/"):
                self.ident_q.put(row[0])
        self._accepted("processes")
        for kind, message in events:
            self.log(kind, message, stored=True, event_time=t)
        return True

    # ---- 2: listeners ----
    def check_listeners(self):
        self._attempt("listeners")
        try:
            code, out, err = command_result(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"], 60)
            command_policy("lsof", code, out, err)
            records, pid, cmd, named, pending_fd = [], None, None, False, False
            lines = out.split("\n") if out else []
            if lines and lines[-1] == "":
                lines.pop()
            for line in lines:
                if not line:
                    raise CollectionError("lsof-parse")
                tag, value = line[0], line[1:]
                if tag == "p":
                    if pending_fd or (pid is not None and not named):
                        raise CollectionError("lsof-parse")
                    pid, cmd, named = checked_pid(value, "lsof-parse"), None, False
                elif tag == "c" and pid is not None and cmd is None and value:
                    cmd = value
                elif tag == "f" and pid is not None and cmd:
                    if pending_fd or not re.fullmatch(r"[0-9]+", value):
                        raise CollectionError("lsof-parse")
                    pending_fd = True
                elif tag == "n" and pid is not None and cmd:
                    host, sep, port = value.rpartition(":")
                    if not sep or not host or any(x in ASCII_WS for x in host):
                        raise CollectionError("lsof-parse")
                    port_number = bounded_ascii_number(port, 1, 65535, "lsof-parse")
                    records.append((pid, cmd, value, host, port_number))
                    named = True
                    pending_fd = False
                else:
                    raise CollectionError("lsof-parse")
            if pending_fd or (pid is not None and not named) or (out and not records):
                raise CollectionError("lsof-parse")
            procs = self.processes() if records else {}
            seen = {k: dict(v) for k, v in self.listeners.items()}
            dirty = dict(self.dirty_listeners)
            present, new_rows, events = set(), [], []
            t = now()
            for pid, cmd, addr, host, port in records:
                p = procs.get(pid)
                exe = p[2] if p else pid_path(pid)
                if not exe or not exe.startswith("/"):
                    code, comm, err = command_result(["ps", "-o", "comm=", "-p", str(pid)], 20)
                    rows = comm.split("\n")
                    if rows and rows[-1] == "":
                        rows.pop()
                    if code != 0 or err or len(rows) != 1 or not rows[0].strip(ASCII_WS):
                        raise CollectionError("lsof-parse")
                    exe = rows[0].strip(ASCII_WS)
                if (not exe.startswith("/") or exe == "<defunct>"
                        or (exe.startswith("(") and exe.endswith(")"))):
                    raise CollectionError("lsof-parse")
                key = f"{exe} {addr}"
                if key in present:
                    continue
                present.add(key)
                exposed = host in ("*", "0.0.0.0", "[::]", "::")
                if key not in seen:
                    user, args = (p[1], p[3]) if p else ("?", "")
                    chain = self.chain(procs, pid, 8)
                    seen[key] = {"present": True, "exposed": exposed}
                    new_rows.append((key, exe, host, port, cmd, pid, user, args[:1000], chain,
                                     int(exposed), 1, t, t))
                    if not self.baseline["listeners"]:
                        events.append(("LISTEN" + ("!" if exposed else ""),
                                       f"{'EXPOSED on all interfaces ' if exposed else ''}{cmd} pid {pid} "
                                       f"listening on {addr} ({exe}) user {user} | chain: {chain}"))
                else:
                    dirty[key] = t
            changed = []
            for key, value in seen.items():
                was = value["present"]
                value["present"] = key in present
                if was != value["present"]:
                    changed.append((int(value["present"]), key))
                if was and not value["present"] and not self.baseline["listeners"]:
                    events.append(("UNLISTEN", f"stopped listening: {key}"))
            if self.baseline["listeners"]:
                exposed = [k for k, v in seen.items() if v["exposed"]]
                events.append(("BASELINE", f"listeners: {len(seen)} recorded, {len(exposed)} on all interfaces: "
                               + "; ".join(exposed)))
            with lock:
                with transaction(self.db) as c:
                    c.executemany("INSERT OR IGNORE INTO listeners(key, exe, address, port, command, pid, user,"
                                  " args, chain, exposed, present, first_seen, last_seen)"
                                  " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", new_rows)
                    c.executemany("UPDATE listeners SET present=? WHERE key=?", changed)
                    c.executemany("INSERT INTO events(time, kind, message) VALUES (?,?,?)",
                                  [(t, kind, message) for kind, message in events])
                self.listeners, self.dirty_listeners = seen, dirty
                self.baseline["listeners"] = False
        except (OSError, subprocess.SubprocessError, sqlite3.Error, ValueError,
                TypeError, KeyError, OverflowError, ctypes.ArgumentError) as e:
            self._rejected("listeners", e)
            return False
        self._accepted("listeners")
        for kind, message in events:
            self.log(kind, message, stored=True, event_time=t)
        return True

    # ---- 4: startup items ----
    def _startup_files(self):
        """Stage filesystem hashes and copy bytes without changing any accepted state."""
        def optional_absent(path):
            if os.path.lexists(path):
                raise CollectionError("startup-read")
            ancestor = os.path.dirname(os.path.abspath(path))
            while True:
                if os.path.islink(ancestor) and not os.path.exists(ancestor):
                    raise CollectionError("startup-read")
                parent = os.path.dirname(ancestor)
                if parent == ancestor:
                    break
                ancestor = parent
        contents, markers = {}, {}
        def read_entry(path, listed=False):
            try:
                with open(path, "rb") as f:
                    contents[path] = f.read()
            except PermissionError:
                os.lstat(path)  # A source ancestor failure must not masquerade as a known entry.
                markers[path] = "unreadable: permission-denied"
            except IsADirectoryError:
                os.lstat(path)
                markers[path] = "unreadable: directory"
            except FileNotFoundError:
                if os.path.islink(path) and not os.path.exists(path):
                    markers[path] = "unreadable: dangling-link"
                elif listed:
                    raise CollectionError("startup-read") from None
                else:
                    optional_absent(path)
        for directory in STARTUP_DIRS:
            try:
                names = sorted(os.listdir(directory))
            except FileNotFoundError:
                optional_absent(directory)
                continue
            for name in names:
                path = os.path.join(directory, name)
                read_entry(path, listed=True)
        for path in STARTUP_FILES + self.extra_startup:
            read_entry(path)
        snap = {p: hashlib.sha256(data).hexdigest() for p, data in contents.items()}
        snap.update(markers)
        return snap, contents

    @staticmethod
    def _crontab_sample():
        code, out, err = command_result(["crontab", "-l"], 20)
        policy = command_policy("crontab", code, out, err)
        return ("none" if policy == "ok-absent" else hashlib.sha256(out.encode()).hexdigest()), out

    def startup_snapshot(self):
        """Return a validated candidate map; accepted state/text belongs to check_startup."""
        snap, _ = self._startup_files()
        digest, _ = self._crontab_sample()
        snap["crontab -l"] = digest
        return snap

    def content(self, p):
        if p == "crontab -l":
            return self.crontab_text.encode()
        try:
            with open(p, "rb") as f:
                return f.read(4 * 1024 * 1024)
        except OSError:
            return None

    @staticmethod
    def safe_name(p):
        return re.sub(r"[^A-Za-z0-9._-]+", "_", p.strip("/")) or "root"

    def keep_copy(self, p, digest, data=None):
        """Save a copy of a startup item under startup-snapshots/, named by path and hash, so
        any later change can be diffed against it. Returns the copy's path or None."""
        if data is None:
            data = self.content(p)
        elif p != "crontab -l":
            data = data[:4 * 1024 * 1024]
        if data is None or digest.startswith("unreadable"):
            return None
        d = os.path.join(self.snap_dir, self.safe_name(p))
        os.makedirs(d, exist_ok=True)
        dest = os.path.join(d, digest[:16])
        def existing_matches():
            try:
                fd = os.open(dest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                return False
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode) or f.read(len(data) + 1) != data:
                    raise OSError("startup-copy")
            return True
        if existing_matches():
            return dest
        fd, pending = tempfile.mkstemp(prefix=".copy-", dir=d)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(pending, dest)
            except FileExistsError:
                if not existing_matches():
                    raise OSError("startup-copy")
        finally:
            if os.path.exists(pending):
                os.unlink(pending)
        return dest

    def diff(self, old_copy, new_copy, limit=40):
        try:
            a = open(old_copy, "rb").read().decode("utf-8", "replace").splitlines()
            b = open(new_copy, "rb").read().decode("utf-8", "replace").splitlines()
        except (OSError, TypeError):
            return "(no text diff: binary or missing copy)"
        lines = list(difflib.unified_diff(a, b, "before", "after", lineterm="", n=1))
        more = len(lines) - limit
        return "\n".join(lines[:limit]) + (f"\n... {more} more diff lines" if more > 0 else "")

    @staticmethod
    def hash_file(p):
        try:
            with open(p, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except OSError as e:
            return f"unreadable: {e.strerror}"

    def check_startup(self):
        self._attempt("startup")
        errors, eligible = {}, set()
        snap, contents = {}, {}
        try:
            snap, contents = self._startup_files()
            snap = {p: h for p, h in snap.items() if p != "crontab -l"}
            eligible.add("startup")
        except (OSError, subprocess.SubprocessError, ValueError, TypeError,
                KeyError, OverflowError) as e:
            errors["startup"] = (CollectionError("startup-read") if isinstance(e, OSError) else e)
        self._attempt("crontab")
        crontab_text = self.crontab_text
        try:
            digest, crontab_text = self._crontab_sample()
            eligible.add("crontab")
        except (OSError, subprocess.SubprocessError, ValueError, TypeError,
                KeyError, OverflowError) as e:
            errors["crontab"] = e
        old, t = dict(self.startup), now()
        baselines = {"startup": self.baseline["startup"],
                     "crontab": self.baseline.get("crontab", "crontab -l" not in old)}
        candidates = {"startup": snap, "crontab": {}}
        if "crontab" in eligible:
            candidates["crontab"] = {"crontab -l": digest}
            contents["crontab -l"] = crontab_text.encode()
        copies, partition_versions = {}, {"startup": [], "crontab": []}
        for partition in ("startup", "crontab"):
            if partition not in eligible:
                continue
            try:
                staged_copies, staged_versions = {}, []
                for path, value in sorted(candidates[partition].items()):
                    if baselines[partition] or path not in old or old[path] != value:
                        copy = self.keep_copy(path, value, contents[path]) if path in contents else None
                        staged_copies[path] = copy
                        staged_versions.append((path, value, copy, t))
                copies.update(staged_copies)
                partition_versions[partition] = staged_versions
            except (OSError, subprocess.SubprocessError, sqlite3.Error, ValueError,
                    TypeError, KeyError, OverflowError) as e:
                errors[partition] = e
                eligible.remove(partition)
        proposed = dict(old)
        if "startup" in eligible:
            proposed = {p: h for p, h in old.items() if p == "crontab -l"}
            proposed.update(snap)
        if "crontab" in eligible:
            proposed["crontab -l"] = digest
        try:
            versions = sorted((row for partition in ("startup", "crontab")
                               for row in partition_versions[partition]), key=lambda row: row[0])
            events = []
            upserts, removals = [], []
            for path in sorted(set(old) | set(proposed)):
                partition = "crontab" if path == "crontab -l" else "startup"
                if partition not in eligible:
                    continue
                if path not in proposed:
                    removals.append((path,))
                    if not baselines[partition]:
                        before = (None if old[path].startswith("unreadable: ") else
                                  os.path.join(self.snap_dir, self.safe_name(path), old[path][:16]))
                        events.append(("STARTUP-", f"removed: {path} | last copy: {before}"))
                    continue
                upserts.append((path, proposed[path], t))
                if baselines[partition] or path not in old or old[path] != proposed[path]:
                    copy = copies[path]
                    if not baselines[partition]:
                        if path not in old:
                            events.append(("STARTUP+", f"added: {path} | copy: {copy}"))
                        else:
                            before = (None if old[path].startswith("unreadable: ") else
                                      os.path.join(self.snap_dir, self.safe_name(path), old[path][:16]))
                            events.append(("STARTUP~", f"changed: {path} | before: {before} | after: {copy}\n"
                                           + self.diff(before, copy)))
            if "startup" in eligible and baselines["startup"]:
                events.append(("BASELINE", f"startup items: {len(snap)} recorded, copies in {self.snap_dir}"))
            if "crontab" in eligible and baselines["crontab"]:
                events.append(("BASELINE", f"crontab: 1 recorded, copies in {self.snap_dir}"))
            if eligible:
                with lock:
                    with transaction(self.db) as c:
                        c.executemany("DELETE FROM startup_items WHERE path=?", removals)
                        c.executemany("INSERT OR REPLACE INTO startup_items(path, hash, last_checked) VALUES (?,?,?)",
                                      upserts)
                        c.executemany("INSERT INTO startup_versions(path, hash, copy_path, seen_at) VALUES (?,?,?,?)",
                                      versions)
                        c.executemany("INSERT INTO events(time, kind, message) VALUES (?,?,?)",
                                      [(t, kind, message) for kind, message in events])
                    self.startup = proposed
                    if "crontab" in eligible:
                        self.crontab_text = crontab_text
                    for partition in eligible:
                        self.baseline[partition] = False
        except (OSError, subprocess.SubprocessError, sqlite3.Error, ValueError,
                TypeError, KeyError, OverflowError) as e:
            for partition in eligible:
                errors[partition] = e
            events = []
        if "startup" in eligible and "startup" not in errors and any(
                h.startswith("unreadable: ") for h in snap.values()):
            errors["startup"] = CollectionError("startup-unreadable")
        for partition in ("startup", "crontab"):
            if partition in errors:
                self._rejected(partition, errors[partition])
            elif partition in eligible:
                self._accepted(partition)
        for kind, message in events:
            self.log(kind, message, stored=True, event_time=t)
        return not errors

    # ---- 1b: short-lived credential and git network helpers from the unified log ----
    STREAM_PROCS = ("git-credential-osxkeychain", "git-remote-https", "git-remote-http",
                    "SecurityAgent", "ssh-askpass")

    def lookup_now(self, pid):
        """Command line and parent chain of a pid, read immediately (it may live under a
        second). Each hop is one ps call; returns what was readable."""
        args = self.args(pid)
        hops, cur = [], pid
        for _ in range(10):
            r = subprocess.run(["ps", "-o", "ppid=,comm=", "-p", str(cur)], capture_output=True,
                               text=True)
            parts = r.stdout.split(None, 1)
            if len(parts) < 2 or not parts[0].isdigit():
                break
            hops.append(f"{os.path.basename(parts[1].strip())}({cur})")
            cur = int(parts[0])
            if cur <= 1:
                break
        return args, " <- ".join(hops) if hops else "exited before lookup"

    def log_stream(self):
        pred = " OR ".join(f'process == "{p}"' for p in self.STREAM_PROCS)
        cmd = ["log", "stream", "--style", "ndjson", "--predicate", pred]
        while not self.stop.is_set():
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                     errors="replace")
                self.stream_proc = p  # stopped in run() on exit, so it never outlives the watcher
            except OSError as e:
                self.log("NOTE", f"log stream unavailable ({e}); credential checks use the process list only")
                return
            lines = 0
            for line in p.stdout:
                lines += 1
                if self.stop.is_set():
                    break
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                pid = ev.get("processID")
                proc = os.path.basename(ev.get("processImagePath") or "")
                if not pid or not proc:
                    continue
                t = time.monotonic()
                if t - self.stream_pids.get(pid, float("-inf")) < 300:
                    continue
                self.stream_pids[pid] = t
                if len(self.stream_pids) > 2000:
                    self.stream_pids = {k: v for k, v in self.stream_pids.items() if t - v < 300}
                args, chain = self.lookup_now(pid)
                kind = "PASSWORD" if proc == "SecurityAgent" else "CRED-NET"
                self.log(kind, f"{proc} pid {pid} | args: {args or '(exited)'} | chain: {chain} "
                               f"| first log: {str(ev.get('eventMessage', ''))[:160]}")
                try:
                    with lock:
                        self.db.execute("INSERT INTO credential_events(time, source, pid, user, exe, args,"
                                        " chain) VALUES (?,?,?,?,?,?,?)",
                                        (now(), "log", pid, "", proc, args[:1000], chain))
                except sqlite3.Error as e:
                    self.log("ERROR", f"credential event not stored: {e}")
            p.terminate()
            code = p.wait()
            if lines == 0 and code not in (0, None) and not self.stop.is_set():
                # An older `log` that rejects --style ndjson exits at once with nothing read;
                # say so once instead of restarting it every 10 seconds forever.
                self.log("NOTE", f"log stream exited with code {code} and no output (this macOS may not "
                                 "support --style ndjson); credential checks use the process list only")
                return
            if not self.stop.is_set():
                time.sleep(10)

    def claim_pid_file(self):
        """One watcher per database. tattletale.pid sits next to the db; a live tattletale
        holding it refuses this start (install-login-agent.sh reads the same file). A stale
        file, or one whose pid now belongs to another program, is taken over."""
        path = os.path.join(os.path.dirname(os.path.abspath(self.db_path)), "tattletale.pid")
        try:
            with open(path) as f:
                other = checked_pid(f.read().strip(ASCII_WS), "ps-parse")
        except FileNotFoundError:
            if os.path.lexists(path):
                raise SystemExit("tattletale: pid identity unavailable") from None
            other = 0
        except (OSError, ValueError):
            raise SystemExit("tattletale: pid identity unavailable") from None
        if other and other != os.getpid():
            try:
                r = subprocess.run(["ps", "-p", str(other), "-o", "command="],
                                   capture_output=True, timeout=20)
                out = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else r.stdout
                err = r.stderr.decode("utf-8", "replace") if isinstance(r.stderr, bytes) else r.stderr
                if not isinstance(out, str) or not isinstance(err, str):
                    raise ValueError("pid-observation")
                out, err = (s.replace("\r\n", "\n").replace("\r", "\n") for s in (out, err))
            except (OSError, subprocess.SubprocessError, ValueError):
                raise SystemExit("tattletale: pid identity unavailable") from None
            rows = out.split("\n")
            if rows and rows[-1] == "":
                rows.pop()
            absent = r.returncode == 1 and out == "" and err == ""
            observed = r.returncode == 0 and err == "" and len(rows) == 1 and rows[0].strip(ASCII_WS)
            if not absent and not observed:
                raise SystemExit("tattletale: pid identity unavailable")
            if observed and is_tattletale(rows[0]):
                raise SystemExit(f"tattletale: already running as pid {other} for this database "
                                 f"({path}); stop it first: kill {other}")
        with open(path, "w") as f:
            f.write(f"{os.getpid()}\n")
        self.pid_file = path

    def release_pid_file(self):
        path = getattr(self, "pid_file", None)
        try:
            with open(path) as f:
                if int(f.read().strip() or 0) == os.getpid():
                    os.remove(path)
        except (OSError, ValueError, TypeError):
            pass

    def install_dashboard(self):
        """Copy the shared page next to the data file (where it loads tattletale-data.js from)
        whenever its bytes differ, so an upgraded page reaches an existing data directory."""
        dst = os.path.join(self.data_dir, "tattletale.html")
        try:
            with open(DASHBOARD, "rb") as f:
                page = f.read()
        except OSError as e:
            self.log("NOTE", f"dashboard not copied: {e}")
            return
        try:
            with open(dst, "rb") as f:
                if f.read() == page:
                    return
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(dir=self.data_dir, prefix=".tattletale-page.", suffix=".tmp")
        with os.fdopen(fd, "wb") as f:
            f.write(page)
        os.replace(tmp, dst)

    def run(self):
        self.claim_pid_file()
        workers = []
        try:
            self.install_dashboard()
            self.log("START", f"tattletale {__version__} pid {os.getpid()} db {self.db_path}")
            self.load_state()
            self._safe("retention", self.retain)
            for target in (self.log_stream, self.identity_worker):
                worker = threading.Thread(target=target, daemon=True)
                worker.start()
                workers.append(worker)
            # Start every scheduled check on the first pass.
            last = {"listeners": float("-inf"), "startup": float("-inf")}
            last_retention = time.monotonic()
            while not self.stop.is_set():
                t0 = time.monotonic()
                for name, fn in (("processes", self.check_processes),):
                    self._safe(name, fn)
                if t0 - last["listeners"] >= self.listen_every:
                    self._safe("listeners", self.check_listeners)
                    last["listeners"] = t0
                if t0 - last["startup"] >= self.startup_every:
                    self._safe("startup", self.check_startup)
                    last["startup"] = t0
                    self._safe("save", self.save)
                if t0 - last_retention >= 3600:
                    self._safe("retention", self.retain)
                    last_retention = t0
                if int(t0) % 60 < 3:
                    self._safe("save", self.save)
                self.stop.wait(self.process_every)
        finally:
            # A fatal DB error must exit, not turn into a silent live no-op. Cleanup may
            # fail too, but must neither mask the primary failure nor skip PID release.
            original = sys.exc_info()[1]
            cleanup_error = None
            self.stop.set()
            def cleanup(fn):
                nonlocal cleanup_error
                try:
                    fn()
                except Exception as e:
                    cleanup_error = cleanup_error or e
            cleanup(lambda: self._safe("save", self.save))
            def stop_stream():
                p = getattr(self, "stream_proc", None)
                if p is not None and p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
            cleanup(stop_stream)
            for worker in workers:
                cleanup(lambda worker=worker: worker.join(timeout=2))
            cleanup(lambda: self.log("STOP", "tattletale stopped"))
            def close_db():
                with lock:
                    self.db.close()
            cleanup(close_db)
            cleanup(self.release_pid_file)
            if cleanup_error is not None:
                print("tattletale: cleanup incomplete", file=sys.stderr, flush=True)
                if original is None:
                    raise FatalDatabaseError("collection-db-fatal") from cleanup_error

    def _safe(self, name, fn):
        try:
            fn()
        except (subprocess.SubprocessError, OSError, sqlite3.Error, ValueError) as e:
            # ValueError covers a decode error from odd process data: one bad process must
            # never stop the watcher.
            self.log("ERROR", f"{name} check failed: {e}")


# ---- settings: flag > environment variable > config file > default ----
# Every setting has one name. As a flag it is --name-with-dashes; as an environment variable or
# a line in the config file it is TATTLETALE_NAME_WITH_UNDERSCORES. See tattletale.env.example.
SETTINGS = {
    # name:              (type,  default,                              help)
    "log":               (str,   os.path.join(DATA, "tattletale.log"),  "log file"),
    "db":                (str,   os.path.join(DATA, "tattletale.db"),   "state database (SQLite); the page data file and startup copies are kept beside it"),
    "map":               (str,   os.path.join(DATA, "tattletale-map.json"), "old JSON state map, imported once into an empty database; never written"),
    "process_interval":  (float, 3,     "seconds between process-list scans"),
    "listen_interval":   (float, 30,    "seconds between listening-port scans"),
    "startup_interval":  (float, 300,   "seconds between startup-item scans"),
    "notify":            (bool,  True,  "show macOS notifications for alerts"),
    "rotate_mb":         (float, 20,    "rotate the log when it reaches this many MB"),
    "keep_logs":         (int,   3,     "how many rotated logs to keep"),
    "extra_startup":     (list,  [],    "extra files to treat as startup items (colon-separated in env/config)"),
    "retention_days":    (int,   30,    "days to keep events and credential events (0 keeps them forever)"),
    "sightings_retention_days": (int, 7, "days to keep process sightings, the busiest table (0 keeps them forever)"),
}


def parse_env_file(path):
    """KEY=VALUE lines; # comments and blank lines ignored; optional single or double quotes.
    No shell expansion: a value is taken literally."""
    out = {}
    with open(path) as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            key, sep, val = line.partition("=")
            if not sep:
                sys.exit(f"tattletale: {path}:{n}: expected KEY=VALUE")
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
                val = val[1:-1]
            out[key.strip()] = val
    return out


def convert(name, kind, raw):
    if kind is bool:
        v = str(raw).strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
        sys.exit(f"tattletale: {name}: expected true or false, got {raw!r}")
    if kind is list:
        return [os.path.expanduser(x) for x in (raw if isinstance(raw, list) else str(raw).split(":")) if x]
    try:
        return kind(raw)
    except ValueError:
        sys.exit(f"tattletale: {name}: expected {'a whole number' if kind is int else 'a number'}, got {raw!r}")


def resolve_settings(args):
    """Effective settings and where each came from (flag, env, config or default)."""
    cfg_path = args.config or os.environ.get("TATTLETALE_CONFIG") or os.path.join(REPO, "tattletale.env")
    file_vals = {}
    if os.path.exists(os.path.expanduser(cfg_path)):
        file_vals = parse_env_file(os.path.expanduser(cfg_path))
        unknown = sorted(k for k in file_vals if k != "TATTLETALE_CONFIG"
                         and not (k.startswith("TATTLETALE_") and k[len("TATTLETALE_"):].lower() in SETTINGS))
        if unknown:
            sys.exit(f"tattletale: {cfg_path}: unknown setting(s): {', '.join(unknown)}")
    elif args.config:
        sys.exit(f"tattletale: config file not found: {args.config}")
    eff, src = {}, {}
    for name, (kind, default, _) in SETTINGS.items():
        key = "TATTLETALE_" + name.upper()
        flag = getattr(args, name, None)
        if flag is not None and flag != []:
            eff[name], src[name] = convert(name, kind, flag), "flag"
        elif key in os.environ:
            eff[name], src[name] = convert(name, kind, os.environ[key]), "env"
        elif key in file_vals:
            eff[name], src[name] = convert(name, kind, file_vals[key]), "config"
        else:
            eff[name], src[name] = default, "default"
    for name in ("log", "db", "map"):
        eff[name] = os.path.expanduser(eff[name])
    return eff, src, cfg_path


def report(db_path):
    conn = open_db_readonly(db_path)
    if conn is None:
        print("no database yet")
        return
    one = lambda sql: conn.execute(sql).fetchone()[0]
    print(f"programs seen: {one('SELECT count(*) FROM programs')}")
    print(f"listeners seen: {one('SELECT count(*) FROM listeners')}")
    for k, first in conn.execute("SELECT key, first_seen FROM listeners WHERE exposed ORDER BY key"):
        print(f"  EXPOSED  {k}  (first seen {first})")
    print(f"startup items tracked: {one('SELECT count(*) FROM startup_items')}")
    print(f"process sightings kept: {one('SELECT count(*) FROM sightings')}")
    print(f"credential events kept: {one('SELECT count(*) FROM credential_events')}")
    print(f"log events kept: {one('SELECT count(*) FROM events')}")
    conn.close()


# What a --query statement may do: read tables and call functions, nothing else.
_QUERY_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                  getattr(sqlite3, "SQLITE_RECURSIVE", 33)}


def run_query(db_path, sql):
    """Run one SELECT (or WITH ... SELECT) against the database opened read-only and print the
    rows tab-separated, with a header line. Anything else is refused."""
    s = sql.strip()
    while s.endswith(";"):
        s = s[:-1].rstrip()
    if not re.match(r"(?is)^(select|with)\b", s) or ";" in s:
        sys.exit("tattletale: --query takes a single SELECT or WITH statement (no ';' inside)")
    try:
        conn = open_db_readonly(db_path)
        if conn is None:
            sys.exit(f"tattletale: no database at {db_path}")
        conn.set_authorizer(lambda action, *_: sqlite3.SQLITE_OK if action in _QUERY_ALLOWED
                            else sqlite3.SQLITE_DENY)
        cur = conn.execute(s)
        clean = lambda x: "" if x is None else str(x).replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
        print("\t".join(d[0] for d in cur.description or ()))
        for row in cur:
            print("\t".join(clean(x) for x in row))
        conn.close()
    except sqlite3.Error as e:
        sys.exit(f"tattletale: query failed: {e}")


# Files v0.0.1 kept next to tattletale.py, which was then the repo root.
V001_FILES = ("tattletale.db", "tattletale.db-wal", "tattletale.db-shm", "tattletale-data.js",
              "tattletale.stdout", "tattletale-map.json", "startup-snapshots")


def migrate_v001(data_dir):
    """One-time move of a v0.0.1 data set from the repo root into data/. Runs only with the
    default database path, only when data/ has no database yet, and never while a v0.0.1
    watcher still holds the old pid file."""
    old_db = os.path.join(REPO, "tattletale.db")
    if not os.path.exists(old_db) or os.path.exists(os.path.join(data_dir, "tattletale.db")):
        return None
    old_pid = os.path.join(REPO, "tattletale.pid")
    try:
        with open(old_pid) as f:
            pid = int(f.read().strip() or 0)
        r = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
        if pid and r.returncode == 0 and "tattletale.py" in r.stdout:
            sys.exit(f"tattletale: a v0.0.1 watcher (pid {pid}) is still using {old_db}; "
                     f"stop it first (kill {pid}), then start again to move its data into {data_dir}")
    except (OSError, ValueError):
        pass
    os.makedirs(data_dir, exist_ok=True)
    moved = []
    names = list(V001_FILES) + sorted(n for n in os.listdir(REPO) if n.startswith("tattletale.log"))
    for name in names:
        src = os.path.join(REPO, name)
        if os.path.exists(src):
            os.replace(src, os.path.join(data_dir, name))
            moved.append(name)
    try:
        os.remove(old_pid)  # dead, checked above
    except OSError:
        pass
    old_snap = os.path.join(REPO, "startup-snapshots")
    new_snap = os.path.join(data_dir, "startup-snapshots")
    conn = sqlite3.connect(os.path.join(data_dir, "tattletale.db"))
    with conn:
        conn.execute("UPDATE startup_versions SET copy_path = ? || substr(copy_path, ?) "
                     "WHERE copy_path LIKE ? || '%'", (new_snap, len(old_snap) + 1, old_snap))
    conn.close()
    return moved


def main():
    ap = argparse.ArgumentParser(description="Watch for credential prompts, new listeners, new programs and startup changes.")
    ap.add_argument("--config", help="settings file (default: tattletale.env at the repository root)")
    ap.add_argument("--version", action="version", version=f"tattletale {__version__}")
    ap.add_argument("--report", action="store_true", help="print a summary of the database and exit")
    ap.add_argument("--query", metavar="SQL", help="run one read-only SELECT against the database, print tab-separated rows, and exit")
    ap.add_argument("--show-settings", action="store_true", help="print the effective settings and where each came from, then exit")
    for name, (kind, default, help_text) in SETTINGS.items():
        flag = "--" + name.replace("_", "-")
        if kind is bool:
            ap.add_argument(flag, dest=name, action="store_const", const=True, default=None, help=help_text)
            ap.add_argument("--no-" + name.replace("_", "-"), dest=name, action="store_const", const=False)
        elif kind is list:
            ap.add_argument(flag, dest=name, action="append", default=None, help=help_text + " (repeatable)")
        else:
            ap.add_argument(flag, dest=name, type=kind, default=None, help=f"{help_text} (default {default})")
    a = ap.parse_args()
    eff, src, cfg_path = resolve_settings(a)
    if a.show_settings:
        print(f"config file: {cfg_path}" + ("" if os.path.exists(os.path.expanduser(cfg_path)) else " (not present)"))
        for name in SETTINGS:
            print(f"  {name:<17} = {eff[name]!r:<60} ({src[name]})")
        return
    if a.report:
        report(eff["db"])
        return
    if a.query is not None:
        run_query(eff["db"], a.query)
        return
    if src["db"] == "default":
        moved = migrate_v001(os.path.dirname(eff["db"]))
        if moved:
            print(f"tattletale: moved the v0.0.1 data into {os.path.dirname(eff['db'])}: "
                  + ", ".join(moved), file=sys.stderr)
    w = Watch(eff["log"], eff["db"], eff["listen_interval"], eff["startup_interval"],
              eff["extra_startup"], notify=eff["notify"],
              rotate_bytes=int(eff["rotate_mb"] * 1024 * 1024), keep_logs=max(0, eff["keep_logs"]),
              process_every=max(0.5, eff["process_interval"]), map_path=eff["map"],
              retention_days=eff["retention_days"],
              sightings_retention_days=eff["sightings_retention_days"])
    signal.signal(signal.SIGINT, lambda *_: w.stop.set())
    signal.signal(signal.SIGTERM, lambda *_: w.stop.set())
    w.run()


if __name__ == "__main__":
    main()
