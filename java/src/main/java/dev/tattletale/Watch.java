package dev.tattletale;

import dev.tattletale.Db.DbException;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The watcher: python/tattletale.py's Watch class, check for check. */
final class Watch {
    static final String VERSION = "0.0.2";
    static final int SCHEMA_VERSION = 1;
    // Byte-identical to python/tattletale.py's SCHEMA, so both versions share one database.
    static final String SCHEMA = """

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
            """;
    static final List<String> RETAINED_TABLES = List.of("sightings", "events", "credential_events");

    static final List<String> CRED_NAMES = List.of("git-credential", "git-remote-https", "git-remote-http",
            "ssh-askpass", "SecurityAgent", "askpass", "pinentry", "gh-credential", "credential-helper");
    static final List<String> STREAM_PROCS = List.of("git-credential-osxkeychain", "git-remote-https",
            "git-remote-http", "SecurityAgent", "ssh-askpass");
    static final Map<String, String> NOTIFY_KINDS = new LinkedHashMap<>();

    static {
        NOTIFY_KINDS.put("CREDENTIAL", "Credential prompt");
        NOTIFY_KINDS.put("CRED-NET", "Git network credential lookup");
        NOTIFY_KINDS.put("LISTEN!", "Port exposed to the network");
        NOTIFY_KINDS.put("STARTUP+", "Startup item added");
        NOTIFY_KINDS.put("STARTUP~", "Startup item changed");
        NOTIFY_KINDS.put("STARTUP-", "Startup item removed");
        NOTIFY_KINDS.put("UNSIGNED", "Unsigned program ran");
        NOTIFY_KINDS.put("PASSWORD", "Password dialog");
    }

    static List<String> startupDirs() {
        return List.of(Paths.join(Py.home(), "Library/LaunchAgents"), "/Library/LaunchAgents",
                "/Library/LaunchDaemons", "/Library/StartupItems");
    }

    static List<String> startupFiles() {
        List<String> l = new ArrayList<>();
        for (String f : List.of(".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile",
                ".config/fish/config.fish")) l.add(Paths.join(Py.home(), f));
        l.addAll(List.of("/etc/zshrc", "/etc/profile", "/etc/paths", "/etc/hosts"));
        return l;
    }

    /**
     * One lock guards the log file and the one database connection; every thread takes it
     * before touching either. Never call log() while holding it (Python's lock is not
     * re-entrant; this one is, but the discipline is kept).
     */
    static final Object LOCK = new Object();

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);

    static String now() {
        return ISO.format(Instant.now());
    }

    static double monotonic() {
        return System.nanoTime() / 1e9;
    }

    static final PrintStream OUT = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true,
            StandardCharsets.UTF_8);
    static final PrintStream ERR = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err), true,
            StandardCharsets.UTF_8);

    /** Python's sys.exit("message"): the message on stderr, exit status 1. */
    static final class Exit extends RuntimeException {
        final int code;

        private static final long serialVersionUID = 1L;

        Exit(String msg) {
            this(msg, 1);
        }

        Exit(String msg, int code) {
            super(msg);
            this.code = code;
        }
    }

    // ---- database ----
    static Db openDb(String path) {
        try {
            Path p = Path.of(path);
            if (!Files.exists(p)) {
                // machine data: owner only
                Files.createFile(p, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
            }
        } catch (IOException e) {
            throw new Exit("tattletale: cannot open database " + path + ": unable to open database file");
        }
        Db db = null;
        try {
            db = Db.open(path, false);
            db.exec("PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\nPRAGMA foreign_keys=OFF;\n");
            db.exec(SCHEMA);
            Object v = db.scalar("SELECT max(version) AS v FROM schema_version;");
            if (v == null) {
                db.exec(Db.bind("INSERT INTO schema_version(version) VALUES (?)", (long) SCHEMA_VERSION));
            } else if (Db.asLong(v) != null && Db.asLong(v) > SCHEMA_VERSION) {
                db.close();
                throw new Exit("tattletale: " + path + " has schema version " + Py.str(v) + "; this tattletale knows "
                        + SCHEMA_VERSION);
            }
        } catch (DbException e) {
            if (db != null) db.close();
            throw new Exit("tattletale: cannot open database " + path + ": " + e.getMessage());
        }
        return db;
    }

    static Db openDbReadonly(String path) throws DbException {
        if (!Files.exists(Path.of(path))) return null;
        Db db = Db.open(path, true);
        db.exec("PRAGMA query_only=ON;");
        return db;
    }

    // ---- state ----
    final String logPath, dbPath, mapPath, dashboard;
    final boolean notifyOn;
    final long rotateBytes;
    final long keepLogs;
    final double processEvery, listenEvery, startupEvery;
    final long retentionDays, sightingsRetentionDays;
    final List<String> extraStartup;
    final String dataDir, snapDir;
    final Db db;
    final Map<String, Double> lastNotified = new HashMap<>();
    Map<Long, Double> streamPids = new HashMap<>();
    final Set<Long> credSeenPids = new HashSet<>();
    final CountDownLatch stop = new CountDownLatch(1);
    final LinkedBlockingQueue<String> identQ = new LinkedBlockingQueue<>();
    Set<String> knownProgs = new HashSet<>();
    Map<String, Listener> listeners = new LinkedHashMap<>();
    Map<String, String> startup = new LinkedHashMap<>();
    final Map<String, String> announce = new HashMap<>();
    Map<Long, String> prevPids = null;
    Map<String, String> dirtyProgs = new LinkedHashMap<>(), dirtyListeners = new LinkedHashMap<>();
    final Map<String, Boolean> baseline = new HashMap<>();
    String crontabText = "";
    String pidFile;
    volatile Process streamProc;

    static final class Listener {
        boolean present, exposed;

        Listener(boolean present, boolean exposed) {
            this.present = present;
            this.exposed = exposed;
        }
    }

    Watch(String logPath, String dbPath, double listenEvery, double startupEvery, List<String> extraStartup,
            boolean notify, long rotateBytes, long keepLogs, double processEvery, String mapPath, long retentionDays,
            long sightingsRetentionDays, String dashboard) {
        this.logPath = logPath;
        this.dbPath = dbPath;
        this.mapPath = mapPath;
        this.notifyOn = notify;
        this.rotateBytes = rotateBytes;
        this.keepLogs = keepLogs;
        this.processEvery = processEvery;
        this.retentionDays = retentionDays;
        this.sightingsRetentionDays = sightingsRetentionDays;
        this.listenEvery = listenEvery;
        this.startupEvery = startupEvery;
        this.extraStartup = new ArrayList<>(extraStartup);
        this.dashboard = dashboard;
        this.dataDir = Py.dirname(Paths.abspath(dbPath));
        try {
            Files.createDirectories(Path.of(dataDir));
        } catch (IOException e) {
            throw new Exit("tattletale: cannot create " + dataDir + ": " + Py.oserror(e, dataDir));
        }
        this.snapDir = Paths.join(dataDir, "startup-snapshots");
        this.db = openDb(dbPath);
    }

    boolean stopped() {
        return stop.getCount() == 0;
    }

    void requestStop() {
        stop.countDown();
        Process p = streamProc;
        if (p != null) p.destroy();
    }

    // ---- persistence ----
    void loadState() throws DbException {
        importMap();
        synchronized (LOCK) {
            knownProgs = new HashSet<>();
            for (Map<String, Object> r : db.query("SELECT exe FROM programs;")) knownProgs.add(Db.asStr(r.get("exe")));
            listeners = new LinkedHashMap<>();
            for (Map<String, Object> r : db.query("SELECT key, present, exposed FROM listeners;"))
                listeners.put(Db.asStr(r.get("key")), new Listener(Py.truthy(r.get("present")), Py.truthy(r.get("exposed"))));
            startup = new LinkedHashMap<>();
            for (Map<String, Object> r : db.query("SELECT path, hash FROM startup_items;"))
                startup.put(Db.asStr(r.get("path")), Db.asStr(r.get("hash")));
            for (Map<String, Object> r : db.query("SELECT exe FROM programs WHERE sha256 IS NULL AND exe LIKE '/%';"))
                identQ.add(Db.asStr(r.get("exe")));
        }
        baseline.put("programs", knownProgs.isEmpty());
        baseline.put("listeners", listeners.isEmpty());
        baseline.put("startup", startup.isEmpty());
    }

    private static Object get(Map<?, ?> m, String k) {
        return m.get(k);
    }

    @SuppressWarnings("unchecked")
    void importMap() throws DbException {
        if (mapPath == null || mapPath.isEmpty() || !Files.exists(Path.of(mapPath))) return;
        synchronized (LOCK) {
            Long n = Db.asLong(db.scalar("SELECT count(*) AS n FROM programs;"));
            if (n != null && n != 0) return;
        }
        Map<String, Object> s;
        try {
            String text = Files.readString(Path.of(mapPath), StandardCharsets.UTF_8);
            s = (Map<String, Object>) Json.parse(text);
        } catch (IOException e) {
            log("ERROR", "cannot import map " + mapPath + ": " + Py.oserror(e, mapPath));
            return;
        } catch (Json.ParseError e) {
            log("ERROR", "cannot import map " + mapPath + ": " + e.getMessage());
            return;
        } catch (java.io.UncheckedIOException e) {
            log("ERROR", "cannot import map " + mapPath + ": " + e.getMessage());
            return;
        }
        Map<String, Object> progs = (Map<String, Object>) s.getOrDefault("programs", Map.of());
        Map<String, Object> ls = (Map<String, Object>) s.getOrDefault("listeners", Map.of());
        List<Object> creds = (List<Object>) s.getOrDefault("credentials", List.of());
        Map<String, Object> st = (Map<String, Object>) s.getOrDefault("startup", Map.of());
        String t = now();
        List<String> sql = new ArrayList<>();
        for (Map.Entry<String, Object> e : progs.entrySet()) {
            Map<?, ?> v = (Map<?, ?>) e.getValue();
            sql.add(Db.bind("INSERT OR IGNORE INTO programs(exe, first_seen, last_seen, user, first_pid, first_args,"
                    + " parent, sha256, size, signer, team, signing_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", e.getKey(),
                    get(v, "firstSeen"), get(v, "lastSeen"), get(v, "user"), get(v, "firstPid"), get(v, "firstArgs"),
                    get(v, "parent"), get(v, "sha256"), get(v, "size"), get(v, "signer"), get(v, "team"),
                    get(v, "signingId")));
        }
        // A map from before the present flag existed says nothing about what is listening now;
        // import those as not present, so the first scan marks the live ones present silently.
        for (Map.Entry<String, Object> e : ls.entrySet()) {
            Map<?, ?> v = (Map<?, ?>) e.getValue();
            String key = e.getKey();
            int sp = key.lastIndexOf(' ');
            String exe = sp < 0 ? "" : key.substring(0, sp);
            String addr = sp < 0 ? key : key.substring(sp + 1);
            int c = addr.lastIndexOf(':');
            String host = c < 0 ? "" : addr.substring(0, c);
            String port = c < 0 ? addr : addr.substring(c + 1);
            sql.add(Db.bind("INSERT OR IGNORE INTO listeners(key, exe, address, port, command, pid, user,"
                    + " args, chain, exposed, present, first_seen, last_seen)"
                    + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", key, exe, host,
                    Py.isDigits(port) ? (Object) Long.parseLong(port) : null, get(v, "command"), get(v, "pid"),
                    get(v, "user"), get(v, "args"), get(v, "chain"), Py.truthy(get(v, "exposed")) ? 1L : 0L,
                    Py.truthy(v.containsKey("present") ? get(v, "present") : Boolean.FALSE) ? 1L : 0L,
                    get(v, "firstSeen"), get(v, "lastSeen")));
        }
        for (Object o : creds) {
            Map<?, ?> v = (Map<?, ?>) o;
            sql.add(Db.bind("INSERT INTO credential_events(time, source, pid, user, exe, args, chain)"
                    + " VALUES (?,?,?,?,?,?,?)", get(v, "time"), v.containsKey("source") ? get(v, "source") : "ps",
                    get(v, "pid"), get(v, "user"), get(v, "exe"), get(v, "args"), get(v, "chain")));
        }
        for (Map.Entry<String, Object> e : st.entrySet())
            sql.add(Db.bind("INSERT OR REPLACE INTO startup_items(path, hash, last_checked) VALUES (?,?,?)", e.getKey(),
                    e.getValue(), t));
        for (Map.Entry<String, Object> e : st.entrySet()) {
            String copy = Paths.join(snapDir, safeName(e.getKey()), Py.cut(Py.str(e.getValue()), 16));
            sql.add(Db.bind("INSERT INTO startup_versions(path, hash, copy_path, seen_at) VALUES (?,?,?,?)", e.getKey(),
                    e.getValue(), Files.exists(Path.of(copy)) ? copy : null, t));
        }
        synchronized (LOCK) {
            db.transaction(sql);
        }
        log("IMPORT", "imported " + mapPath + ": " + progs.size() + " programs, " + ls.size() + " listeners, "
                + creds.size() + " credential events, " + st.size() + " startup items; "
                + "the JSON map is no longer written");
    }

    void retain() throws DbException {
        Map<String, Long> windows = new LinkedHashMap<>();
        windows.put("sightings", sightingsRetentionDays);
        windows.put("events", retentionDays);
        windows.put("credential_events", retentionDays);
        Map<String, Long> counts = new LinkedHashMap<>();
        synchronized (LOCK) {
            List<String> sql = new ArrayList<>();
            for (String tbl : RETAINED_TABLES) {
                long days = windows.get(tbl);
                if (days > 0) {
                    String cutoff = ISO.format(Instant.now().minusSeconds(days * 86400L));
                    sql.add(Db.bind("DELETE FROM " + tbl + " WHERE time < ?", cutoff));
                    sql.add("SELECT '" + tbl + "' AS t, changes() AS n;");
                }
            }
            db.exec("BEGIN;");
            try {
                for (Map<String, Object> r : db.query(String.join("\n", sql)))
                    counts.put(Db.asStr(r.get("t")), Db.asLong(r.get("n")));
            } catch (DbException e) {
                try {
                    db.exec("ROLLBACK;");
                } catch (DbException ignored) {
                    // nothing to roll back
                }
                throw e;
            }
            db.exec("COMMIT;");
        }
        long sum = 0;
        for (long v : counts.values()) sum += v;
        if (sum != 0) {
            List<String> parts = new ArrayList<>();
            for (Map.Entry<String, Long> e : counts.entrySet())
                parts.add(e.getKey() + " " + e.getValue() + " (older than " + windows.get(e.getKey()) + " days)");
            log("RETENTION", "deleted old rows: " + String.join(", ", parts));
        }
    }

    void save() throws DbException, IOException {
        Map<String, Object> m;
        synchronized (LOCK) {
            List<String> sql = new ArrayList<>();
            for (Map.Entry<String, String> e : dirtyProgs.entrySet())
                sql.add(Db.bind("UPDATE programs SET last_seen=? WHERE exe=?", e.getValue(), e.getKey()));
            for (Map.Entry<String, String> e : dirtyListeners.entrySet())
                sql.add(Db.bind("UPDATE listeners SET last_seen=? WHERE key=?", e.getValue(), e.getKey()));
            db.transaction(sql);
            dirtyProgs = new LinkedHashMap<>();
            dirtyListeners = new LinkedHashMap<>();
            m = pageMap();
        }
        writePageData(dataDir, m);
    }

    /** The dashboard's "map" object; identity keys are absent until known. Caller holds the lock. */
    Map<String, Object> pageMap() throws DbException {
        Map<String, Object> programs = new LinkedHashMap<>();
        for (Map<String, Object> r : db.query("SELECT exe, first_seen, last_seen, user, first_pid, first_args, parent,"
                + " sha256, size, signer, team, signing_id FROM programs;")) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("firstSeen", r.get("first_seen"));
            v.put("lastSeen", r.get("last_seen"));
            v.put("user", r.get("user"));
            v.put("firstPid", r.get("first_pid"));
            v.put("firstArgs", r.get("first_args"));
            v.put("parent", r.get("parent"));
            String[][] idk = {{"sha256", "sha256"}, {"size", "size"}, {"signer", "signer"}, {"team", "team"},
                    {"signingId", "signing_id"}};
            for (String[] k : idk) if (r.get(k[1]) != null) v.put(k[0], r.get(k[1]));
            programs.put(Db.asStr(r.get("exe")), v);
        }
        Map<String, Object> ls = new LinkedHashMap<>();
        for (Map<String, Object> r : db.query("SELECT key, first_seen, last_seen, pid, command, exposed, user, args,"
                + " chain, present FROM listeners;")) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("firstSeen", r.get("first_seen"));
            v.put("lastSeen", r.get("last_seen"));
            v.put("pid", r.get("pid"));
            v.put("command", r.get("command"));
            v.put("exposed", Py.truthy(r.get("exposed")));
            v.put("user", r.get("user"));
            v.put("args", r.get("args"));
            v.put("chain", r.get("chain"));
            v.put("present", Py.truthy(r.get("present")));
            ls.put(Db.asStr(r.get("key")), v);
        }
        List<Object> creds = new ArrayList<>();
        for (Map<String, Object> r : db.query("SELECT time, pid, user, exe, args, chain, source FROM"
                + " (SELECT * FROM credential_events ORDER BY id DESC LIMIT 500)" + " ORDER BY id;")) {
            Map<String, Object> v = new LinkedHashMap<>();
            for (String k : List.of("time", "pid", "user", "exe", "args", "chain", "source")) v.put(k, r.get(k));
            creds.add(v);
        }
        Map<String, Object> st = new LinkedHashMap<>();
        for (Map<String, Object> r : db.query("SELECT path, hash FROM startup_items;"))
            st.put(Db.asStr(r.get("path")), r.get("hash"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("programs", programs);
        out.put("listeners", ls);
        out.put("credentials", creds);
        out.put("startup", st);
        return out;
    }

    /** The last 500 log lines (from the last 400 kB), as Python's write_page_data reads them. */
    List<String> logTail() {
        try (RandomAccessFile f = new RandomAccessFile(logPath, "r")) {
            long size = f.length();
            long start = Math.max(0, size - 400_000);
            f.seek(start);
            byte[] b = new byte[(int) (size - start)];
            f.readFully(b);
            List<String> lines = Py.splitlines(new String(b, StandardCharsets.UTF_8));
            return lines.size() > 500 ? lines.subList(lines.size() - 500, lines.size()) : lines;
        } catch (IOException e) {
            return List.of();
        }
    }

    /** tattletale-data.js for tattletale.html, written to a temp file and renamed into place. */
    void writePageData(String d, Map<String, Object> state) throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", now());
        payload.put("version", VERSION);
        payload.put("pid", ProcessHandle.current().pid());
        payload.put("map", state);
        payload.put("log", new ArrayList<Object>(logTail()));
        StringBuilder sb = new StringBuilder("window.TATTLETALE = ");
        Json.write(sb, payload);
        sb.append(";\n");
        Path tmp = Files.createTempFile(Path.of(d), ".tattletale-data.", ".tmp");
        try {
            Files.writeString(tmp, sb, StandardCharsets.UTF_8);
            Files.move(tmp, Path.of(d, "tattletale-data.js"), StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
    }

    // ---- the log ----
    void log(String kind, String msg) {
        String t = now();
        String line = t + "  " + Py.ljust(kind, 9) + " " + msg;
        synchronized (LOCK) {
            rotate();
            try {
                Files.writeString(Path.of(logPath), line + "\n", StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                        StandardOpenOption.APPEND, StandardOpenOption.WRITE);
            } catch (IOException e) {
                // Python would raise out of log(); report and keep the database record.
                ERR.println("tattletale: log not written: " + Py.oserror(e, logPath));
            }
            try {
                db.exec(Db.bind("INSERT INTO events(time, kind, message) VALUES (?,?,?)", t, kind, msg));
            } catch (DbException e) {
                ERR.println("tattletale: event not stored in database: " + e.getMessage());
            }
        }
        OUT.println(line);
        if (NOTIFY_KINDS.containsKey(kind)) notify(kind, msg);
    }

    /** Keep the log under rotate_bytes: tattletale.log -> .1 -> .2 ... keep_logs old files. */
    private void rotate() {
        try {
            if (Files.size(Path.of(logPath)) < rotateBytes) return;
        } catch (IOException e) {
            return;
        }
        for (long i = keepLogs; i > 0; i--) {
            String src = i == 1 ? logPath : logPath + "." + (i - 1);
            if (Files.exists(Path.of(src))) {
                try {
                    Files.move(Path.of(src), Path.of(logPath + "." + i), StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.ATOMIC_MOVE);
                } catch (IOException e) {
                    ERR.println("tattletale: log not rotated: " + Py.oserror(e, src));
                }
            }
        }
    }

    /**
     * A macOS notification, at most one per kind per minute. Text is passed as an argument to
     * osascript (never spliced into the script), so a program name cannot inject AppleScript.
     */
    synchronized void notify(String kind, String msg) {
        if (!notifyOn) return;
        double t = monotonic();
        Double last = lastNotified.get(kind);
        if (last != null && t - last < 60) return;
        lastNotified.put(kind, t);
        String script = "on run argv\n display notification (item 2 of argv) with title \"Tattletale\" "
                + "subtitle (item 1 of argv)\nend run";
        try {
            new ProcessBuilder("osascript", "-e", script, NOTIFY_KINDS.get(kind), Py.cut(msg, 180))
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD)
                    .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        } catch (IOException ignored) {
            // no notification
        }
    }

    // ---- process table ----
    record P(long ppid, String user, String exe, String args) {}

    /**
     * pid -> (ppid, user, exe path, args). ps comm= is the full executable path on macOS; args=
     * is the command line, read separately so a helper started through a shell is still
     * recognised by name.
     */
    static Map<Long, P> processes() throws IOException, Proc.Timeout {
        String out = Proc.run(List.of("ps", "-axo", "pid=,ppid=,user=,comm="), 20).out();
        String argv = Proc.run(List.of("ps", "-axo", "pid=,args="), 20).out();
        Map<Long, String> args = new HashMap<>();
        for (String line : Py.splitlines(argv)) {
            List<String> parts = Py.split(line, 1);
            if (parts.size() == 2 && Py.isDigits(parts.get(0))) args.put(Long.parseLong(parts.get(0)), Py.strip(parts.get(1)));
        }
        Map<Long, P> procs = new LinkedHashMap<>();
        for (String line : Py.splitlines(out)) {
            List<String> parts = Py.split(line, 3);
            if (parts.size() == 4 && Py.isDigits(parts.get(0)) && Py.isDigits(parts.get(1))) {
                long pid = Long.parseLong(parts.get(0));
                String exe = Py.strip(parts.get(3));
                if (!exe.startsWith("/") && !exe.startsWith("(")) {
                    String pp = PidPath.of(pid);
                    if (pp != null && !pp.isEmpty()) exe = pp;
                }
                procs.put(pid, new P(Long.parseLong(parts.get(1)), parts.get(2), exe, args.getOrDefault(pid, "")));
            }
        }
        return procs;
    }

    static String chain(Map<Long, P> procs, long pid, int depth) {
        List<String> names = new ArrayList<>();
        while (procs.containsKey(pid) && depth > 0 && pid > 1) {
            P p = procs.get(pid);
            names.add(Py.basename(p.exe()) + "(" + pid + ")");
            pid = p.ppid();
            depth--;
        }
        return names.isEmpty() ? "?" : String.join(" <- ", names);
    }

    static String chain(Map<Long, P> procs, long pid) {
        return chain(procs, pid, 6);
    }

    private static final Pattern AUTH = Pattern.compile("(?dm)^Authority=(.*)$");
    private static final Pattern TEAM = Pattern.compile("(?dm)^TeamIdentifier=(.*)$");
    private static final Pattern IDENT = Pattern.compile("(?dm)^Identifier=(.*)$");

    /** sha256 and code-signing identity of an executable file; files over 512 MB are not hashed. */
    static Map<String, Object> identity(String exe) throws IOException, Proc.Timeout {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            long size = Files.size(Path.of(exe));
            out.put("size", size);
            if (size <= 512L * 1024 * 1024) {
                MessageDigest h = sha256();
                try (InputStream f = new FileInputStream(exe)) {
                    byte[] buf = new byte[1 << 20];
                    int n;
                    while ((n = f.read(buf)) > 0) h.update(buf, 0, n);
                }
                out.put("sha256", HexFormat.of().formatHex(h.digest()));
            } else out.put("sha256", "not hashed: larger than 512 MB");
        } catch (IOException | java.nio.file.InvalidPathException e) {
            out.put("sha256", "unreadable: " + (e instanceof IOException io ? Py.strerror(io) : e.getMessage()));
        }
        Proc.Result r = Proc.run(List.of("codesign", "-dv", "--verbose=2", exe), 20);
        String text = r.err();
        Matcher auth = AUTH.matcher(text);
        Matcher team = TEAM.matcher(text);
        Matcher ident = IDENT.matcher(text);
        if (r.code() != 0) {
            out.put("signer", "unsigned or unreadable: " + Py.cut(Py.squash(text), 120));
        } else {
            out.put("signer", auth.find() ? auth.group(1)
                    : (text.contains("Signature=adhoc") ? "adhoc" : "signed, no authority"));
            out.put("team", team.find() ? team.group(1) : null);
            out.put("signingId", ident.find() ? ident.group(1) : null);
        }
        return out;
    }

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    void identityWorker() {
        while (!stopped()) {
            String exe;
            try {
                exe = identQ.poll(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                return;
            }
            if (exe == null) continue;
            Map<String, Object> info;
            try {
                info = identity(exe);
            } catch (IOException | Proc.Timeout e) {
                info = new LinkedHashMap<>();
                info.put("sha256", "failed: " + e.getMessage());
            }
            try {
                synchronized (LOCK) {
                    db.exec(Db.bind("UPDATE programs SET sha256=?, size=?, signer=?, team=?, signing_id=? WHERE exe=?",
                            info.get("sha256"), info.get("size"), info.get("signer"), info.get("team"),
                            info.get("signingId"), exe));
                }
            } catch (DbException e) {
                log("ERROR", "identity of " + exe + " not stored: " + e.getMessage());
            }
            baselineLoggedIdentity(exe, info);
        }
    }

    /** Log a NEW program's identity once it is known (baseline programs are not logged). */
    boolean baselineLoggedIdentity(String exe, Map<String, Object> info) {
        String firstArgs;
        synchronized (LOCK) {
            firstArgs = announce.remove(exe);
        }
        if (firstArgs != null) {
            log("IDENTITY", exe + " | signer: " + Py.str(info.get("signer")) + " team: " + Py.str(info.get("team"))
                    + " | sha256: " + Py.str(info.get("sha256")));
            String signer = Py.str(info.containsKey("signer") ? info.get("signer") : "");
            if (signer.startsWith("unsigned") || signer.equals("adhoc"))
                log("UNSIGNED", exe + " ran with no named signer (" + Py.cut(signer, 60) + ") | first command line: "
                        + Py.cut(firstArgs, 200));
            return true;
        }
        return false;
    }

    static String args(String pid) {
        try {
            return Py.cut(Py.squash(Proc.run(List.of("ps", "-o", "args=", "-p", pid)).out()), 300);
        } catch (IOException | Proc.Timeout e) {
            return "";
        }
    }

    // ---- 1 and 3: processes ----
    void checkProcesses() throws IOException, Proc.Timeout, DbException {
        Map<Long, P> procs = processes();
        String t = now();
        boolean firstScan = prevPids == null;
        Map<Long, String> cur = new HashMap<>();
        List<String> newProgs = new ArrayList<>();
        List<String> newProgExes = new ArrayList<>();
        List<String> sightings = new ArrayList<>();
        List<String> creds = new ArrayList<>();
        for (Map.Entry<Long, P> e : procs.entrySet()) {
            long pid = e.getKey();
            P p = e.getValue();
            String exe = p.exe(), user = p.user(), argline = p.args();
            if ((exe.startsWith("(") && exe.endsWith(")")) || exe.equals("<defunct>")) continue;
            cur.put(pid, exe);
            if (firstScan || !exe.equals(prevPids.get(pid))) {
                Object[] row = {t, pid, exe, user, Py.cut(argline, 1000), chain(procs, pid, 8)};
                if (firstScan) {
                    // A restart must not re-record instances the last run already saw.
                    sightings.add(Db.bind("INSERT INTO sightings(time, pid, exe, user, args, chain) SELECT ?,?,?,?,?,?"
                            + " WHERE NOT EXISTS (SELECT 1 FROM sightings WHERE exe=? AND pid=? LIMIT 1)",
                            row[0], row[1], row[2], row[3], row[4], row[5], exe, pid));
                } else {
                    sightings.add(Db.bind("INSERT INTO sightings(time, pid, exe, user, args, chain) VALUES (?,?,?,?,?,?)",
                            row));
                }
            }
            String base = Py.basename(exe).toLowerCase();
            List<String> words = Py.split(argline);
            List<String> hw = new ArrayList<>();
            for (String w : words.subList(0, Math.min(2, words.size()))) hw.add(Py.basename(w));
            String head = String.join(" ", hw).toLowerCase();
            boolean isCred = false;
            for (String c : CRED_NAMES) {
                String lc = c.toLowerCase();
                if (base.contains(lc) || head.contains(lc)) {
                    isCred = true;
                    break;
                }
            }
            if (isCred && !credSeenPids.contains(pid)) {
                credSeenPids.add(pid);
                if (!baseline.get("programs")) {
                    String ch = chain(procs, pid);
                    log("CREDENTIAL", "pid " + pid + " user " + user + " " + exe + " | args: " + Py.cut(argline, 300)
                            + " | chain: " + ch);
                    creds.add(Db.bind("INSERT INTO credential_events(time, source, pid, user, exe, args, chain)"
                            + " VALUES (?,?,?,?,?,?,?)", t, "ps", pid, user, exe, Py.cut(argline, 1000),
                            chain(procs, pid, 12)));
                }
            }
            if (!knownProgs.contains(exe)) {
                knownProgs.add(exe);
                newProgs.add(Db.bind("INSERT OR IGNORE INTO programs(exe, first_seen, last_seen, user, first_pid,"
                        + " first_args, parent) VALUES (?,?,?,?,?,?,?)", exe, t, t, user, pid, Py.cut(argline, 1000),
                        chain(procs, p.ppid(), 6)));
                newProgExes.add(exe);
                if (!baseline.get("programs")) {
                    synchronized (LOCK) {
                        announce.put(exe, Py.cut(argline, 1000));
                    }
                    log("NEW-PROG", "pid " + pid + " user " + user + " " + exe + " | args: " + Py.cut(argline, 300)
                            + " | chain: " + chain(procs, pid));
                }
            } else {
                dirtyProgs.put(exe, t);
            }
        }
        List<String> sql = new ArrayList<>(newProgs);
        sql.addAll(sightings);
        sql.addAll(creds);
        synchronized (LOCK) {
            db.transaction(sql);
        }
        // Queue identity lookups only now, so the program row exists when the worker updates it.
        for (String exe : newProgExes) if (exe.startsWith("/")) identQ.add(exe);
        prevPids = cur;
        credSeenPids.retainAll(procs.keySet());
        if (baseline.get("programs")) {
            log("BASELINE", "programs: " + knownProgs.size() + " recorded");
            baseline.put("programs", false);
        }
    }

    // ---- 2: listeners ----
    void checkListeners() throws IOException, Proc.Timeout, DbException {
        String out = Proc.run(List.of("lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"), 60).out();
        Map<String, Listener> seen = listeners;
        Map<Long, P> procs = processes();
        Set<String> present = new HashSet<>();
        List<String> newRows = new ArrayList<>();
        String pid = null, cmd = null;
        String t = now();
        for (String line : Py.splitlines(out)) {
            if (line.startsWith("p")) pid = line.substring(1);
            else if (line.startsWith("c")) cmd = line.substring(1);
            else if (line.startsWith("n") && pid != null && !pid.isEmpty()) {
                String addr = line.substring(1);
                int c = addr.lastIndexOf(':');
                String host = c < 0 ? "" : addr.substring(0, c);
                String port = c < 0 ? addr : addr.substring(c + 1);
                boolean exposed = host.equals("*") || host.equals("0.0.0.0") || host.equals("[::]") || host.equals("::");
                boolean digit = Py.isDigits(pid);
                // The full path, which may hold spaces ("/Applications/Google Chrome.app/..."); the
                // first word of the command line would cut it at the first space.
                String exe = digit && procs.containsKey(Long.parseLong(pid)) ? procs.get(Long.parseLong(pid)).exe() : "";
                if (exe.isEmpty()) {
                    String pp = digit ? PidPath.of(Long.parseLong(pid)) : null;
                    exe = pp != null && !pp.isEmpty() ? pp : "";
                }
                if (exe.isEmpty()) exe = args(pid).split(" ", -1)[0];
                if (exe.isEmpty()) exe = cmd;
                String key = exe + " " + addr;
                if (present.contains(key)) continue;
                present.add(key);
                if (!seen.containsKey(key)) {
                    long ipid = Long.parseLong(pid);
                    P p = procs.getOrDefault(ipid, new P(0, "?", exe, ""));
                    String ch = chain(procs, ipid, 8);
                    seen.put(key, new Listener(true, exposed));
                    newRows.add(Db.bind("INSERT OR IGNORE INTO listeners(key, exe, address, port, command, pid, user,"
                            + " args, chain, exposed, present, first_seen, last_seen)"
                            + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", key, exe, host,
                            Py.isDigits(port) ? (Object) Long.parseLong(port) : null, cmd, ipid, p.user(),
                            Py.cut(p.args(), 1000), ch, exposed ? 1L : 0L, 1L, t, t));
                    if (!baseline.get("listeners")) {
                        log("LISTEN" + (exposed ? "!" : ""), (exposed ? "EXPOSED on all interfaces " : "") + Py.str(cmd)
                                + " pid " + pid + " listening on " + addr + " (" + exe + ") user " + p.user()
                                + " | chain: " + ch);
                    }
                } else {
                    dirtyListeners.put(key, t);
                }
            }
        }
        List<String> changed = new ArrayList<>();
        for (Map.Entry<String, Listener> e : seen.entrySet()) {
            Listener v = e.getValue();
            boolean was = v.present;
            v.present = present.contains(e.getKey());
            if (was != v.present) changed.add(Db.bind("UPDATE listeners SET present=? WHERE key=?", v.present ? 1L : 0L,
                    e.getKey()));
            if (was && !v.present && !baseline.get("listeners")) log("UNLISTEN", "stopped listening: " + e.getKey());
        }
        List<String> sql = new ArrayList<>(newRows);
        sql.addAll(changed);
        synchronized (LOCK) {
            db.transaction(sql);
        }
        if (baseline.get("listeners")) {
            List<String> exposed = new ArrayList<>();
            for (Map.Entry<String, Listener> e : seen.entrySet()) if (e.getValue().exposed) exposed.add(e.getKey());
            log("BASELINE", "listeners: " + seen.size() + " recorded, " + exposed.size() + " on all interfaces: "
                    + String.join("; ", exposed));
            baseline.put("listeners", false);
        }
    }

    // ---- 4: startup items ----
    Map<String, String> startupSnapshot() throws IOException, Proc.Timeout {
        Map<String, String> snap = new LinkedHashMap<>();
        for (String d : startupDirs()) {
            String[] names = new java.io.File(d).list();
            if (names == null) continue;
            Arrays.sort(names, Watch::codepointCompare);
            for (String n : names) {
                String p = Paths.join(d, n);
                snap.put(p, hashFile(p));
            }
        }
        List<String> files = new ArrayList<>(startupFiles());
        files.addAll(extraStartup);
        for (String p : files) if (Files.exists(Path.of(p))) snap.put(p, hashFile(p));
        Proc.Result r = Proc.run(List.of("crontab", "-l"));
        crontabText = r.code() == 0 ? r.out() : "";
        snap.put("crontab -l", r.code() == 0 ? HexFormat.of().formatHex(sha256().digest(r.out().getBytes(StandardCharsets.UTF_8)))
                : "none");
        return snap;
    }

    static int codepointCompare(String a, String b) {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            int x = a.codePointAt(i), y = b.codePointAt(j);
            if (x != y) return Integer.compare(x, y);
            i += Character.charCount(x);
            j += Character.charCount(y);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    byte[] content(String p) {
        if (p.equals("crontab -l")) return crontabText.getBytes(StandardCharsets.UTF_8);
        try (InputStream f = new FileInputStream(p)) {
            return f.readNBytes(4 * 1024 * 1024);
        } catch (IOException e) {
            return null;
        }
    }

    private static final Pattern UNSAFE = Pattern.compile("[^A-Za-z0-9._-]+");

    static String safeName(String p) {
        int a = 0, b = p.length();
        while (a < b && p.charAt(a) == '/') a++;
        while (b > a && p.charAt(b - 1) == '/') b--;
        String s = UNSAFE.matcher(p.substring(a, b)).replaceAll("_");
        return s.isEmpty() ? "root" : s;
    }

    /** Save a copy of a startup item under startup-snapshots/, named by path and hash. */
    String keepCopy(String p, String digest) throws IOException {
        byte[] data = content(p);
        if (data == null || digest.startsWith("unreadable")) return null;
        String d = Paths.join(snapDir, safeName(p));
        Files.createDirectories(Path.of(d));
        String dest = Paths.join(d, Py.cut(digest, 16));
        if (!Files.exists(Path.of(dest))) Files.write(Path.of(dest), data);
        return dest;
    }

    String diff(String oldCopy, String newCopy, int limit) {
        List<String> a, b;
        try {
            if (oldCopy == null || newCopy == null) throw new IOException("missing");
            a = Py.splitlines(new String(Files.readAllBytes(Path.of(oldCopy)), StandardCharsets.UTF_8));
            b = Py.splitlines(new String(Files.readAllBytes(Path.of(newCopy)), StandardCharsets.UTF_8));
        } catch (IOException e) {
            return "(no text diff: binary or missing copy)";
        }
        List<String> lines = Difflib.unifiedDiff(a, b, "before", "after", 1);
        int more = lines.size() - limit;
        return String.join("\n", lines.subList(0, Math.min(limit, lines.size())))
                + (more > 0 ? "\n... " + more + " more diff lines" : "");
    }

    static String hashFile(String p) {
        try (InputStream f = new FileInputStream(p)) {
            return HexFormat.of().formatHex(sha256().digest(f.readAllBytes()));
        } catch (IOException e) {
            return "unreadable: " + Py.strerror(e);
        }
    }

    void checkStartup() throws IOException, Proc.Timeout, DbException {
        Map<String, String> snap = startupSnapshot();
        Map<String, String> old = startup;
        String t = now();
        List<Object[]> versions = new ArrayList<>();
        if (baseline.get("startup")) {
            for (Map.Entry<String, String> e : snap.entrySet())
                versions.add(new Object[] {e.getKey(), e.getValue(), keepCopy(e.getKey(), e.getValue()), t});
        } else {
            TreeSet<String> all = new TreeSet<>(Watch::codepointCompare);
            all.addAll(snap.keySet());
            all.addAll(old.keySet());
            for (String p : all) {
                if (!old.containsKey(p)) {
                    String c = keepCopy(p, snap.get(p));
                    versions.add(new Object[] {p, snap.get(p), c, t});
                    log("STARTUP+", "added: " + p + " | copy: " + Py.str(c));
                } else if (!snap.containsKey(p)) {
                    log("STARTUP-", "removed: " + p + " | last copy: "
                            + Paths.join(snapDir, safeName(p), Py.cut(old.get(p), 16)));
                } else if (!snap.get(p).equals(old.get(p))) {
                    String oldCopy = Paths.join(snapDir, safeName(p), Py.cut(old.get(p), 16));
                    String newCopy = keepCopy(p, snap.get(p));
                    versions.add(new Object[] {p, snap.get(p), newCopy, t});
                    log("STARTUP~", "changed: " + p + " | before: " + oldCopy + " | after: " + Py.str(newCopy) + "\n"
                            + diff(oldCopy, newCopy, 40));
                }
            }
        }
        List<String> sql = new ArrayList<>();
        for (String p : old.keySet()) if (!snap.containsKey(p)) sql.add(Db.bind("DELETE FROM startup_items WHERE path=?", p));
        for (Map.Entry<String, String> e : snap.entrySet())
            sql.add(Db.bind("INSERT OR REPLACE INTO startup_items(path, hash, last_checked) VALUES (?,?,?)", e.getKey(),
                    e.getValue(), t));
        for (Object[] v : versions)
            sql.add(Db.bind("INSERT INTO startup_versions(path, hash, copy_path, seen_at) VALUES (?,?,?,?)", v));
        synchronized (LOCK) {
            db.transaction(sql);
        }
        startup = snap;
        if (baseline.get("startup")) {
            log("BASELINE", "startup items: " + snap.size() + " recorded, copies in " + snapDir);
            baseline.put("startup", false);
        }
    }

    // ---- 1b: short-lived credential and git network helpers from the unified log ----
    /** Command line and parent chain of a pid, read immediately (it may live under a second). */
    String[] lookupNow(long pid) {
        String a = args(Long.toString(pid));
        List<String> hops = new ArrayList<>();
        long cur = pid;
        for (int k = 0; k < 10; k++) {
            String out;
            try {
                out = Proc.run(List.of("ps", "-o", "ppid=,comm=", "-p", Long.toString(cur))).out();
            } catch (IOException | Proc.Timeout e) {
                break;
            }
            List<String> parts = Py.split(out, 1);
            if (parts.size() < 2 || !Py.isDigits(parts.get(0))) break;
            hops.add(Py.basename(Py.strip(parts.get(1))) + "(" + cur + ")");
            cur = Long.parseLong(parts.get(0));
            if (cur <= 1) break;
        }
        return new String[] {a, hops.isEmpty() ? "exited before lookup" : String.join(" <- ", hops)};
    }

    void logStream() {
        List<String> preds = new ArrayList<>();
        for (String p : STREAM_PROCS) preds.add("process == \"" + p + "\"");
        List<String> cmd = List.of("log", "stream", "--style", "ndjson", "--predicate", String.join(" OR ", preds));
        while (!stopped()) {
            Process p;
            try {
                p = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.DISCARD)
                        .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
            } catch (IOException e) {
                log("NOTE", "log stream unavailable (" + Py.oserror(e, "log")
                        + "); credential checks use the process list only");
                return;
            }
            streamProc = p;
            if (stopped()) p.destroy();
            long lines = 0;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    lines++;
                    if (stopped()) break;
                    Object o;
                    try {
                        o = Json.parse(line);
                    } catch (Json.ParseError e) {
                        continue;
                    }
                    if (!(o instanceof Map<?, ?> ev)) continue;
                    Object pidObj = ev.get("processID");
                    String proc = Py.basename(ev.get("processImagePath") == null ? "" : Py.str(ev.get("processImagePath")));
                    if (!Py.truthy(pidObj) || proc.isEmpty()) continue;
                    Long pid = Db.asLong(pidObj);
                    if (pid == null) continue;
                    double t = monotonic();
                    Double last = streamPids.get(pid);
                    if (last != null && t - last < 300) continue;
                    streamPids.put(pid, t);
                    if (streamPids.size() > 2000) {
                        Map<Long, Double> keep = new HashMap<>();
                        for (Map.Entry<Long, Double> e : streamPids.entrySet()) if (t - e.getValue() < 300) keep.put(e.getKey(), e.getValue());
                        streamPids = keep;
                    }
                    String[] ac = lookupNow(pid);
                    String a = ac[0], ch = ac[1];
                    String kind = proc.equals("SecurityAgent") ? "PASSWORD" : "CRED-NET";
                    Object em = ev.containsKey("eventMessage") ? ev.get("eventMessage") : "";
                    log(kind, proc + " pid " + pid + " | args: " + (a.isEmpty() ? "(exited)" : a) + " | chain: " + ch
                            + " | first log: " + Py.cut(Py.str(em), 160));
                    try {
                        synchronized (LOCK) {
                            db.exec(Db.bind("INSERT INTO credential_events(time, source, pid, user, exe, args,"
                                    + " chain) VALUES (?,?,?,?,?,?,?)", now(), "log", pid, "", proc, Py.cut(a, 1000), ch));
                        }
                    } catch (DbException e) {
                        log("ERROR", "credential event not stored: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                // the stream closed; fall through to the exit check
            }
            p.destroy();
            int code;
            try {
                code = p.waitFor();
            } catch (InterruptedException e) {
                return;
            }
            streamProc = null;
            if (lines == 0 && code != 0 && !stopped()) {
                // An older `log` that rejects --style ndjson exits at once with nothing read; say so
                // once instead of restarting it every 10 seconds forever.
                log("NOTE", "log stream exited with code " + code + " and no output (this macOS may not "
                        + "support --style ndjson); credential checks use the process list only");
                return;
            }
            if (!stopped()) {
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }
    }

    // ---- pid file ----
    /** What a live watcher's command line looks like, for either version. */
    static boolean isTattletaleCommand(String command) {
        if (command.contains("tattletale.py") || command.contains("tattletale.jar")
                || command.contains("dev.tattletale.Main") || command.contains("java/build/tattletale")) return true;
        List<String> w = Py.split(command);
        return !w.isEmpty() && Py.basename(w.get(0)).equals("tattletale");
    }

    static boolean liveTattletale(long pid) {
        try {
            Proc.Result r = Proc.run(List.of("ps", "-p", Long.toString(pid), "-o", "command="));
            return r.code() == 0 && isTattletaleCommand(r.out());
        } catch (IOException | Proc.Timeout e) {
            return false;
        }
    }

    /**
     * One watcher per database. tattletale.pid sits next to the db; a live tattletale (Python or
     * Java) holding it refuses this start. A stale file, or one whose pid now belongs to another
     * program, is taken over.
     */
    void claimPidFile() throws IOException {
        String path = Paths.join(Py.dirname(Paths.abspath(dbPath)), "tattletale.pid");
        long other = 0, me = ProcessHandle.current().pid();
        try {
            String s = Py.strip(Files.readString(Path.of(path)));
            other = s.isEmpty() ? 0 : Py.parseInt(s);
        } catch (IOException | NumberFormatException e) {
            other = 0;
        }
        if (other != 0 && other != me && liveTattletale(other)) {
            throw new Exit("tattletale: already running as pid " + other + " for this database (" + path + "); stop it first: kill "
                    + other);
        }
        Files.writeString(Path.of(path), me + "\n");
        pidFile = path;
    }

    void releasePidFile() {
        if (pidFile == null) return;
        try {
            String s = Py.strip(Files.readString(Path.of(pidFile)));
            if (!s.isEmpty() && Py.parseInt(s) == ProcessHandle.current().pid()) Files.delete(Path.of(pidFile));
        } catch (IOException | NumberFormatException ignored) {
            // not ours or already gone
        }
    }

    /** Copy the shared page next to the data file whenever its bytes differ. */
    void installDashboard() throws IOException {
        Path dst = Path.of(dataDir, "tattletale.html");
        byte[] page;
        try {
            page = Files.readAllBytes(Path.of(dashboard));
        } catch (IOException e) {
            log("NOTE", "dashboard not copied: " + Py.oserror(e, dashboard));
            return;
        }
        try {
            if (Arrays.equals(Files.readAllBytes(dst), page)) return;
        } catch (IOException ignored) {
            // not there yet
        }
        Path tmp = Files.createTempFile(Path.of(dataDir), ".tattletale-page.", ".tmp");
        Files.write(tmp, page);
        Files.move(tmp, dst, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    // ---- main loop ----
    interface Check {
        void run() throws Exception;
    }

    void safe(String name, Check fn) {
        try {
            fn.run();
        } catch (IOException | Proc.Timeout | DbException e) {
            log("ERROR", name + " check failed: " + e.getMessage());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    void run() throws IOException, DbException {
        claimPidFile();
        installDashboard();
        log("START", "tattletale " + VERSION + " pid " + ProcessHandle.current().pid() + " db " + dbPath);
        loadState();
        safe("retention", this::retain);
        Thread ls = new Thread(this::logStream, "log-stream");
        ls.setDaemon(true);
        ls.start();
        Thread iw = new Thread(this::identityWorker, "identity");
        iw.setDaemon(true);
        iw.start();
        double lastListeners = Double.NEGATIVE_INFINITY, lastStartup = Double.NEGATIVE_INFINITY;
        double lastRetention = monotonic();
        while (!stopped()) {
            double t0 = monotonic();
            safe("processes", this::checkProcesses);
            if (t0 - lastListeners >= listenEvery) {
                safe("listeners", this::checkListeners);
                lastListeners = t0;
            }
            if (t0 - lastStartup >= startupEvery) {
                safe("startup", this::checkStartup);
                lastStartup = t0;
                safe("save", this::save);
            }
            if (t0 - lastRetention >= 3600) {
                safe("retention", this::retain);
                lastRetention = t0;
            }
            if (Math.floorMod((long) Math.floor(t0), 60L) < 3) safe("save", this::save);
            try {
                stop.await((long) (processEvery * 1000), TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                break;
            }
        }
        safe("save", this::save);
        log("STOP", "tattletale stopped");
        synchronized (LOCK) {
            db.close();
        }
        releasePidFile();
        Process p = streamProc;
        if (p != null) p.destroy();
    }
}
