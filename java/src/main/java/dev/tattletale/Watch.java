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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The watcher: python/tattletale.py's Watch class, check for check. */
final class Watch {
    static final String VERSION = "0.0.3";
    static final int SCHEMA_VERSION = 1;
    final CollectionHealth collectionHealth = new CollectionHealth();
    final PublicationHealth publicationHealth=new PublicationHealth();
    Map<String,Object> cachedInventory;
    String inventoryAsOf;
    interface Projection {Map<String,Object> read()throws DbException;}
    Projection projection=this::pageMap;
    interface PageReplace {void move(Path from,Path to)throws IOException;}
    PageReplace pageReplace=(from,to)->Files.move(from,to,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
    PageReplace pidReplace=(from,to)->Files.move(from,to,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    java.util.function.Supplier<String> clock = Watch::now;
    interface Sources {
        Proc.Result run(List<String> command, long timeout) throws IOException, Proc.Timeout;
        default String pidPath(long pid) { return PidPath.of(pid); }
        default List<String> dirs() { return startupDirs(); }
        default List<String> files() { return startupFiles(); }
        default List<String> list(String dir) throws IOException {
            List<String> result = new ArrayList<>();
            try (java.nio.file.DirectoryStream<Path> ds = Files.newDirectoryStream(Path.of(dir))) {
                for (Path p : ds) result.add(p.toString());
            } catch (java.nio.file.NoSuchFileException e) { if (!optionalMissing(dir)) throw e; return result; }
            result.sort(Watch::codepointCompare); return result;
        }
        default boolean optionalMissing(String name) {
            Path path=Path.of(name).toAbsolutePath();
            // NIO NoSuchFile can mean ENOTDIR on Darwin. Only stable native ENOENT is optional.
            try {
                List<StartupEntry.Observed> links=StartupEntry.REAL.ancestorLinks(path);
                try{StartupEntry.REAL.metadata(path);return false;}catch(java.nio.file.NoSuchFileException absent){
                    StartupEntry.stable(StartupEntry.REAL,links);
                    try{StartupEntry.REAL.metadata(path);return false;}catch(java.nio.file.NoSuchFileException stillAbsent){return true;}
                }
            }catch(IOException unknown){return false;}
        }
        default String copyRoot(String actual) { return actual; }
        default void copy(String destination, byte[] value) throws IOException {
            Path dest=Path.of(destination), parent=dest.getParent(); Files.createDirectories(parent);
            if(Files.exists(dest,java.nio.file.LinkOption.NOFOLLOW_LINKS)) { compareCopy(dest,value); return; }
            Path tmp=Files.createTempFile(parent,".tattletale-copy-",".tmp");
            try {
                Files.write(tmp,value);
                // Hard-link publication is atomic and never replaces an existing immutable copy.
                try { Files.createLink(dest,tmp); }
                catch(java.nio.file.FileAlreadyExistsException e) { compareCopy(dest,value); }
                compareCopy(dest,value);
            } finally { Files.deleteIfExists(tmp); }
        }
        default void compareCopy(Path dest,byte[] value) throws IOException {
            if(!Files.isRegularFile(dest,java.nio.file.LinkOption.NOFOLLOW_LINKS) || !Arrays.equals(Files.readAllBytes(dest),value))
                throw new IOException("startup-copy");
        }
        default byte[] copyBytes(String file) throws IOException { return Files.readAllBytes(Path.of(file)); }
        default byte[] read(String file) throws IOException {
            try { return Files.readAllBytes(Path.of(file)); }
            catch (java.nio.file.NoSuchFileException e) { if (!optionalMissing(file)) throw e; return null; }
        }
        /** Metadata/type first, then a nonblocking stable regular-handle read. */
        default byte[] entry(String file) throws IOException {return StartupEntry.read(file);}
        default String textDiff(String before,String after,int limit) { return null; }
    }
    static final class Unreadable extends IOException {
        private static final long serialVersionUID=1L;
        final String marker;
        Unreadable(String reason) { super("startup-unreadable"); marker="unreadable: "+reason; }
    }
    Sources sources = Proc::collector;
    record PendingEvent(String kind, String message) {}
    void commitSample(List<String> sql, List<PendingEvent> events, String time) throws DbException {
        List<String> batch = new ArrayList<>(sql);
        for (PendingEvent e : events) batch.add(Db.bind("INSERT INTO events(time,kind,message) VALUES (?,?,?)", time,e.kind(),e.message()));
        synchronized (LOCK) { db.transaction(batch); }
    }
    void publishEvents(List<PendingEvent> events, String time) {
        for (PendingEvent e : events) {
            String line=time+"  "+Py.ljust(e.kind(),9)+" "+e.message();
            synchronized (LOCK) {
                rotate();
                try { Files.writeString(Path.of(logPath),line+"\n",StandardCharsets.UTF_8,StandardOpenOption.CREATE,StandardOpenOption.APPEND); }
                catch(IOException ignored) { ERR.println("tattletale: event log write failed"); }
            }
            OUT.println(line);
            if(NOTIFY_KINDS.containsKey(e.kind())) notify(e.kind(),e.message());
        }
    }
    interface CollectionCheck { void run() throws IOException, Proc.Timeout, DbException; }
    void collect(String key, CollectionCheck check) {
        collectionHealth.attempt(key,clock.get());
        try { check.run(); collectionHealth.success(key,clock.get()); }
        catch(CollectionHealth.Rejected e) {
            boolean warning=key.equals("listeners") && e.code.equals("lsof-warning")
                    && !collectionHealth.degradedWith(key,e.code);
            collectionHealth.fail(key,e.code);
            heartbeat(key,null,e.code);
            if(warning) log("NOTE","listeners collection degraded: lsof-warning");
            return;
        }
        catch(IOException e) { collectionHealth.fail(key,CollectionHealth.ioError(e)); }
        catch(Proc.Timeout e) { collectionHealth.fail(key,"collection-timeout"); }
        catch(DbException e) { collectionHealth.fail(key,"collection-db"); }
        catch(Db.Fatal e) { collectionHealth.fail(key,"collection-db"); throw e; }
        catch(IllegalArgumentException e) { collectionHealth.fail(key,"collection-parse"); }
        Map<?,?> state=(Map<?,?>)collectionHealth.snapshot().get(key);
        if("degraded".equals(state.get("status")))heartbeat(key,null,(String)state.get("error"));
    }

    double cadence(String key) {
        if(key.equals("keychain"))return Coverage.KEYCHAIN_CADENCE;
        if(key.equals("processes"))return 2*processEvery;
        return Math.max(processEvery,key.equals("listeners")?listenEvery:startupEvery)+processEvery;
    }
    static void validatePolling(double process,double listen,double startup) {
        double[] values={process,listen,startup};String[] names={"process_interval","listen_interval","startup_interval"};
        for(int i=0;i<values.length;i++)if(!Double.isFinite(values[i]) || values[i]<0.5 || values[i]>3600)
            throw new Exit("tattletale: "+names[i]+": expected finite seconds between 0.5 and 3600",2);
    }
    String heartbeatSql(String key,Long count,String error,String at) {
        return Db.bind("INSERT INTO collector_heartbeats(version,collector,time,observed_count,status,error,cadence_seconds) VALUES (?,?,?,?,?,?,?)",
                Coverage.VERSION,key,at,error==null?count:null,error==null?"ok":"degraded",error,cadence(key));
    }
    void heartbeat(String key,Long count,String error) {
        synchronized(LOCK) {
            try {db.transaction(List.of(heartbeatSql(key,count,error,clock.get())));}
            catch(DbException e) {
                if(Db.exactShellResponse(e,"cannot start a transaction within a transaction"))return;
                throw new Db.Fatal(e);
            }
        }
    }

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
            CREATE TABLE IF NOT EXISTS heartbeat_schema(version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS coverage_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS collector_heartbeats(
              id INTEGER PRIMARY KEY, version INTEGER NOT NULL, collector TEXT NOT NULL, time TEXT NOT NULL,
              observed_count INTEGER, status TEXT NOT NULL, error TEXT, cadence_seconds REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS collector_heartbeats_time ON collector_heartbeats(collector,time);
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
        NOTIFY_KINDS.put("LISTEN!", "Listener bound to all interfaces");
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
            List<String> existing=new ArrayList<>();for(var row:db.query("SELECT name FROM sqlite_master WHERE type='table';"))existing.add(Db.asStr(row.get("name")));
            for(String table:List.of("schema_version","heartbeat_schema")) {
                if(existing.contains(table) && !db.query("SELECT version FROM "+table+";").isEmpty()
                        && !Coverage.versions(db,table,table.equals("schema_version")?SCHEMA_VERSION:Coverage.VERSION)) {
                    db.close();throw new Exit("tattletale: unsupported "+table);
                }
            }
            if(existing.contains("collector_heartbeats"))for(var row:db.query("SELECT DISTINCT version FROM collector_heartbeats;")) {
                if(!(row.get("version") instanceof Long version) || version!=Coverage.VERSION) {
                    db.close();throw new Exit("tattletale: unsupported heartbeat protocol");
                }
            }
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
            List<Map<String,Object>> versions=db.query("SELECT version FROM heartbeat_schema;");
            if(versions.isEmpty())db.exec("INSERT INTO heartbeat_schema VALUES (1);");
            else if(!Coverage.versions(db,"heartbeat_schema",Coverage.VERSION)) {
                db.close();throw new Exit("tattletale: unsupported heartbeat schema");
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
    volatile OwnedStreamReader streamReader;
    volatile OwnedStreamReader streamDiagnosticsReader;
    byte[] streamDiagnostics=new byte[0];
    static final int STREAM_DIAGNOSTIC_LIMIT=4096;
    volatile String streamWorkerFailure;

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
        validatePolling(processEvery,listenEvery,startupEvery);
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
            for (Map<String, Object> r : db.query("SELECT path, hash FROM startup_items ORDER BY path;"))
                startup.put(Db.asStr(r.get("path")), Db.asStr(r.get("hash")));
            for (Map<String, Object> r : db.query("SELECT exe FROM programs WHERE sha256 IS NULL AND exe LIKE '/%';"))
                identQ.add(Db.asStr(r.get("exe")));
        }
        baseline.put("programs", knownProgs.isEmpty());
        baseline.put("listeners", listeners.isEmpty());
        baseline.put("startup", startup.keySet().stream().noneMatch(p->!p.equals("crontab -l")));
        baseline.put("crontab", !startup.containsKey("crontab -l"));
        synchronized(LOCK){cachedInventory=null;inventoryAsOf=null;}
        try {synchronized(LOCK){cacheInventory(projection.read(),clock.get());}}
        catch(DbException seedFailure) {db.proveRecoveredIdle(seedFailure); /* valid load, no partial projection */ }
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
            if(retentionDays>0) {
                String floor=ISO.format(Instant.now().minusSeconds(retentionDays*86400L));
                sql.add(Db.bind("DELETE FROM collector_heartbeats WHERE time < ?",floor));
                sql.add(Db.bind("INSERT INTO coverage_metadata(key,value) VALUES ('event_floor',?) ON CONFLICT(key) DO UPDATE SET value=max(value,excluded.value)",floor));
            }
            for (Map<String,Object> row:db.transactionQuery(sql))
                counts.put(Db.asStr(row.get("t")),Db.asLong(row.get("n")));
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

    @SuppressWarnings("unchecked")
    static <T> T detached(T value) {
        if(value instanceof Map<?,?> map) {Map<String,Object> copy=new LinkedHashMap<>();for(Map.Entry<?,?> e:map.entrySet())copy.put((String)e.getKey(),detached(e.getValue()));return (T)copy;}
        if(value instanceof List<?> list) {List<Object> copy=new ArrayList<>();for(Object e:list)copy.add(detached(e));return (T)copy;}
        return value; // the projection contains only immutable scalar values
    }
    void cacheInventory(Map<String,Object> complete,String time) {cachedInventory=detached(complete);inventoryAsOf=time;}
    record InventorySnapshot(Map<String,Object> map,String asOf) {}
    InventorySnapshot inventorySnapshot() {
        synchronized(LOCK) {return new InventorySnapshot(cachedInventory==null?null:detached(cachedInventory),inventoryAsOf);}
    }
    void save() throws DbException, IOException {
        publicationHealth.attempt(clock.get());
        try {
            synchronized(LOCK) {
                List<String> sql=new ArrayList<>();
                for(Map.Entry<String,String> e:dirtyProgs.entrySet())sql.add(Db.bind("UPDATE programs SET last_seen=? WHERE exe=?",e.getValue(),e.getKey()));
                for(Map.Entry<String,String> e:dirtyListeners.entrySet())sql.add(Db.bind("UPDATE listeners SET last_seen=? WHERE key=?",e.getValue(),e.getKey()));
                db.transaction(sql);
                // The flush COMMIT is final even if projection/replacement subsequently fails.
                dirtyProgs=new LinkedHashMap<>();dirtyListeners=new LinkedHashMap<>();
                cacheInventory(projection.read(),clock.get());
            }
        } catch(DbException original) {
            db.proveRecoveredIdle(original);
            publicationHealth.fail("collection-db");
            InventorySnapshot held=inventorySnapshot();
            if(held.map()!=null)try {writePageData(dataDir,held.map(),publicationHealth.snapshot(),held.asOf());}
            catch(IOException writeFailure) {publicationHealth.fail("collection-io");original.addSuppressed(writeFailure);}
            throw original;
        }
        Map<String,Object> tentative=publicationHealth.success(clock.get());
        InventorySnapshot held=inventorySnapshot();
        try {writePageData(dataDir,held.map(),tentative,held.asOf());}
        catch(IOException e){publicationHealth.fail("collection-io");throw e;}
        publicationHealth.adopt(tentative);
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
        for (Map<String, Object> r : db.query("SELECT key, address, first_seen, last_seen, pid, command, exposed, user, args,"
                + " chain, present FROM listeners;")) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("firstSeen", r.get("first_seen"));
            v.put("lastSeen", r.get("last_seen"));
            v.put("pid", r.get("pid"));
            v.put("command", r.get("command"));
            v.put("exposed", Py.truthy(r.get("exposed")));
            v.put("bindScope", CollectionHealth.bindScope(Db.asStr(r.get("address"))));
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
        for (Map<String, Object> r : db.query("SELECT path, hash FROM startup_items ORDER BY path;"))
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
        writePageData(d,state,publicationHealth.snapshot(),inventoryAsOf);
    }
    void writePageData(String d,Map<String,Object> state,Map<String,Object> publication,String asOf)throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("generatedAt", clock.get());
        payload.put("formatVersion", 2);
        payload.put("collectionHealth", collectionHealth.snapshot());
        payload.put("publicationHealth",detached(publication));
        payload.put("inventoryAsOf",asOf);
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
            pageReplace.move(tmp,Path.of(d,"tattletale-data.js"));
        } catch (IOException e) {
            try {Files.deleteIfExists(tmp);}catch(IOException cleanup){e.addSuppressed(cleanup);}
            throw e;
        }
    }

    // ---- the log ----
    void log(String kind, String msg) {
        String t = clock.get();
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
    static final String ASCII_WS="[ \t\n\r\f\u000B]";
    static String asciiStrip(String s) { return s.replaceAll("^"+ASCII_WS+"+|"+ASCII_WS+"+$",""); }
    static List<String> asciiSplit(String s,int max) {
        s=asciiStrip(s); return s.isEmpty()?List.of():Arrays.asList(s.split(ASCII_WS+"+",max+1));
    }
    static long pidValue(String value,boolean parent,String error) throws CollectionHealth.Rejected {
        if(!value.matches("[0-9]+")) throw new CollectionHealth.Rejected(error);
        String significant=value.replaceFirst("^0+(?!$)","");
        if(significant.length()>10) throw new CollectionHealth.Rejected(error);
        long n=Long.parseLong(significant);
        if(n<(parent?0:1) || n>Integer.MAX_VALUE) throw new CollectionHealth.Rejected(error);
        return n;
    }
    static boolean absoluteExe(String value) { return value.startsWith("/") && value.length()>1; }
    // C-locale ps uses vis-style escapes. A real name with the same spelling is ambiguous too.
    static final Pattern PS_DISPLAY_ESCAPE=Pattern.compile("\\\\[0-7]{3}|M-[!-~]|\\^[@-_?]");
    static boolean escapedExe(String value) {return PS_DISPLAY_ESCAPE.matcher(value).find();}

    Map<Long, P> processes() throws IOException, Proc.Timeout {
        Proc.Result comm = sources.run(List.of("ps","-axo","pid=,ppid=,user=,comm="),20);
        CollectionHealth.command("ps",comm);
        Map<Long,P> primary=new LinkedHashMap<>();
        // Validate the entire first stream, including bridge bounds, before invoking ps2.
        for(String line:Py.splitlines(comm.out())) {
            if(asciiStrip(line).isEmpty()) continue;
            List<String> parts=asciiSplit(line,3);
            if(parts.size()!=4) throw new CollectionHealth.Rejected("ps-parse");
            long pid=pidValue(parts.get(0),false,"ps-parse"), ppid=pidValue(parts.get(1),true,"ps-parse");
            String exe=asciiStrip(parts.get(3));
            if(exe.isEmpty() || primary.put(pid,new P(ppid,parts.get(2),exe,""))!=null)
                throw new CollectionHealth.Rejected("ps-parse");
        }
        if(primary.isEmpty()) throw new CollectionHealth.Rejected("ps-parse");
        Proc.Result argv = sources.run(List.of("ps","-axo","pid=,args="),20);
        CollectionHealth.command("ps",argv);
        Map<Long,String> args = new HashMap<>();
        for(String line:Py.splitlines(argv.out())) {
            if(asciiStrip(line).isEmpty()) continue;
            List<String> parts=asciiSplit(line,1);
            if(parts.isEmpty()) throw new CollectionHealth.Rejected("ps-parse");
            long pid=pidValue(parts.get(0),false,"ps-parse");
            if(args.put(pid,parts.size()==1?"":asciiStrip(parts.get(1)))!=null) throw new CollectionHealth.Rejected("ps-parse");
        }
        if(args.isEmpty()) throw new CollectionHealth.Rejected("ps-parse");
        Map<Long,P> procs=new LinkedHashMap<>();
        for(Map.Entry<Long,P> e:primary.entrySet()) {
            long pid=e.getKey(); P p=e.getValue(); String exe=p.exe();
            if(!absoluteExe(exe) || escapedExe(exe)) {
                String pp=sources.pidPath(pid);
                if(pp!=null && absoluteExe(pp)) exe=pp;
                else if(escapedExe(exe))throw new CollectionHealth.Rejected("ps-parse");
            }
            if(exe.equals("/"))throw new CollectionHealth.Rejected("ps-parse");
            // The two commands race normally: a missing argv row is not a missing process.
            procs.put(pid,new P(p.ppid(),p.user(),exe,args.getOrDefault(pid,"")));
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
    void checkProcesses() { collect("processes",this::applyProcesses); }
    void applyProcesses() throws IOException, Proc.Timeout, DbException {
        Map<Long, P> procs = processes();
        String t = clock.get();
        Set<String> proposedKnown = new HashSet<>(knownProgs);
        Set<Long> proposedCreds = new HashSet<>(credSeenPids);
        Map<String,String> proposedDirty = new LinkedHashMap<>(dirtyProgs);
        Map<String,String> proposedAnnounce = new LinkedHashMap<>();
        List<PendingEvent> events = new ArrayList<>();
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
            String base = Py.basename(exe).toLowerCase(java.util.Locale.ROOT);
            List<String> words = Py.split(argline);
            List<String> hw = new ArrayList<>();
            for (String w : words.subList(0, Math.min(2, words.size()))) hw.add(Py.basename(w));
            String head = String.join(" ", hw).toLowerCase(java.util.Locale.ROOT);
            boolean isCred = false;
            for (String c : CRED_NAMES) {
                String lc = c.toLowerCase(java.util.Locale.ROOT);
                if (base.contains(lc) || head.contains(lc)) {
                    isCred = true;
                    break;
                }
            }
            if (isCred && !proposedCreds.contains(pid)) {
                proposedCreds.add(pid);
                if (!baseline.get("programs")) {
                    String ch = chain(procs, pid);
                    events.add(new PendingEvent("CREDENTIAL", "pid " + pid + " user " + user + " " + exe + " | args: " + Py.cut(argline, 300)
                            + " | chain: " + ch));
                    creds.add(Db.bind("INSERT INTO credential_events(time, source, pid, user, exe, args, chain)"
                            + " VALUES (?,?,?,?,?,?,?)", t, "ps", pid, user, exe, Py.cut(argline, 1000),
                            chain(procs, pid, 12)));
                }
            }
            if (!proposedKnown.contains(exe)) {
                proposedKnown.add(exe);
                newProgs.add(Db.bind("INSERT OR IGNORE INTO programs(exe, first_seen, last_seen, user, first_pid,"
                        + " first_args, parent) VALUES (?,?,?,?,?,?,?)", exe, t, t, user, pid, Py.cut(argline, 1000),
                        chain(procs, p.ppid(), 6)));
                newProgExes.add(exe);
                if (!baseline.get("programs")) {
                    synchronized (LOCK) {
                        proposedAnnounce.put(exe, Py.cut(argline, 1000));
                    }
                    events.add(new PendingEvent("NEW-PROG", "pid " + pid + " user " + user + " " + exe + " | args: " + Py.cut(argline, 300)
                            + " | chain: " + chain(procs, pid)));
                }
            } else {
                proposedDirty.put(exe, t);
            }
        }
        List<String> sql = new ArrayList<>(newProgs);
        sql.addAll(sightings);
        sql.addAll(creds);
        if (baseline.get("programs")) events.add(new PendingEvent("BASELINE", "programs: " + proposedKnown.size() + " recorded"));
        sql.add(heartbeatSql("processes",(long)procs.size(),null,t));
        commitSample(sql,events,t);
        proposedCreds.retainAll(procs.keySet());
        knownProgs=proposedKnown; credSeenPids.clear(); credSeenPids.addAll(proposedCreds);
        dirtyProgs=proposedDirty;
        synchronized(LOCK) { announce.putAll(proposedAnnounce); }
        // Queue identity lookups only now, so the program row exists when the worker updates it.
        for (String exe : newProgExes) if (exe.startsWith("/")) identQ.add(exe);
        prevPids = cur;
        baseline.put("programs",false);
        publishEvents(events,t);
    }

    // ---- 2: listeners ----
    void checkListeners() { collect("listeners",this::applyListeners); }
    void applyListeners() throws IOException, Proc.Timeout, DbException {
        Proc.Result result=sources.run(List.of("lsof","-nP","-iTCP","-sTCP:LISTEN","-F","pcn"),60);
        CollectionHealth.command("lsof",result);
        record Row(long pid,String command,String address,String host,long port) {}
        List<Row> rows=new ArrayList<>(); String pid=null,cmd=null; boolean addressSeen=false,inFile=false,fileAddressSeen=false;
        for(String line:Py.splitlines(result.out())) {
            if(line.startsWith("p")) {
                if(pid!=null && (!addressSeen || (inFile && !fileAddressSeen))) throw new CollectionHealth.Rejected("lsof-parse");
                pid=line.substring(1); cmd=null; addressSeen=false; inFile=false; fileAddressSeen=false;
                pidValue(pid,false,"lsof-parse");
            } else if(line.startsWith("c") && pid!=null) {
                if(cmd!=null || addressSeen || inFile || line.length()==1) throw new CollectionHealth.Rejected("lsof-parse");
                cmd=line.substring(1);
            } else if(line.startsWith("f") && pid!=null && cmd!=null) {
                if(!line.substring(1).matches("[0-9]+") || (inFile && !fileAddressSeen)) throw new CollectionHealth.Rejected("lsof-parse");
                inFile=true; fileAddressSeen=false;
            } else if(line.startsWith("n") && pid!=null && cmd!=null) {
                String addr=line.substring(1); int colon=addr.lastIndexOf(':');
                if(colon<=0) throw new CollectionHealth.Rejected("lsof-parse");
                long port=pidValue(addr.substring(colon+1),false,"lsof-parse");
                if(port>65535 || Pattern.compile(ASCII_WS).matcher(addr.substring(0,colon)).find()) throw new CollectionHealth.Rejected("lsof-parse");
                rows.add(new Row(Long.parseLong(pid),cmd,addr,addr.substring(0,colon),port)); addressSeen=true; fileAddressSeen=true;
            } else throw new CollectionHealth.Rejected("lsof-parse");
        }
        if(pid!=null && (!addressSeen || (inFile && !fileAddressSeen))) throw new CollectionHealth.Rejected("lsof-parse");
        Map<Long,P> procs=rows.isEmpty()?Map.of():processes();
        Map<String,Listener> seen=new LinkedHashMap<>();
        listeners.forEach((k,v)->seen.put(k,new Listener(v.present,v.exposed)));
        Map<String,String> dirty=new LinkedHashMap<>(dirtyListeners);
        Set<String> present=new HashSet<>(); List<String> sql=new ArrayList<>();
        List<PendingEvent> events=new ArrayList<>(); String t=clock.get();
        for(Row row:rows) {
            P p=procs.get(row.pid()); String exe=p==null?"":p.exe();
            if(!absoluteExe(exe)) { String pp=sources.pidPath(row.pid()); exe=pp==null?"":pp; }
            if(!absoluteExe(exe)) {
                Proc.Result lookup=sources.run(List.of("ps","-o","comm=","-p",Long.toString(row.pid())),20);
                List<String> lines=Py.splitlines(lookup.out());
                if(lookup.code()!=0 || !lookup.err().isEmpty() || lines.size()!=1)
                    throw new CollectionHealth.Rejected("lsof-parse");
                exe=asciiStrip(lines.getFirst());
                if(!absoluteExe(exe) || escapedExe(exe)) throw new CollectionHealth.Rejected("lsof-parse");
                // comm= is the full executable path on macOS, including spaces. Never split it.

            }
            String key=exe+" "+row.address(); if(!present.add(key)) continue;
            boolean exposed=List.of("*","0.0.0.0","::","[::]").contains(row.host());
            if(p==null) p=new P(0,"?",exe,"");
            if(!seen.containsKey(key)) {
                seen.put(key,new Listener(true,exposed)); String ch=chain(procs,row.pid(),8);
                sql.add(Db.bind("INSERT OR IGNORE INTO listeners(key,exe,address,port,command,pid,user,args,chain,exposed,present,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",key,exe,row.host(),row.port(),row.command(),row.pid(),p.user(),Py.cut(p.args(),1000),ch,exposed?1L:0L,1L,t,t));
                if(!baseline.get("listeners")) events.add(new PendingEvent("LISTEN"+(exposed?"!":""),(exposed?"EXPOSED on all interfaces ":"")+row.command()+" pid "+row.pid()+" listening on "+row.address()+" ("+exe+") user "+p.user()+" | chain: "+ch));
            } else dirty.put(key,t);
        }
        for(Map.Entry<String,Listener> e:seen.entrySet()) {
            boolean was=e.getValue().present, next=present.contains(e.getKey()); e.getValue().present=next;
            if(was!=next) sql.add(Db.bind("UPDATE listeners SET present=? WHERE key=?",next?1L:0L,e.getKey()));
            if(was && !next && !baseline.get("listeners")) events.add(new PendingEvent("UNLISTEN","stopped listening: "+e.getKey()));
        }
        if(baseline.get("listeners")) {
            List<String> exposed=new ArrayList<>(); seen.forEach((k,v)->{if(v.exposed) exposed.add(k);});
            events.add(new PendingEvent("BASELINE","listeners: "+seen.size()+" recorded, "+exposed.size()+" on all interfaces: "+String.join("; ",exposed)));
        }
        sql.add(heartbeatSql("listeners",(long)present.size(),null,t));
        commitSample(sql,events,t); listeners=seen; dirtyListeners=dirty; baseline.put("listeners",false); publishEvents(events,t);
    }

    // ---- 4: startup items ----
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
        String fixture=sources.textDiff(oldCopy,newCopy,limit);
        if(fixture!=null) return fixture;
        List<String> a, b;
        try {
            if (oldCopy == null || newCopy == null) throw new IOException("missing");
            a = Py.splitlines(new String(sources.copyBytes(oldCopy), StandardCharsets.UTF_8));
            b = Py.splitlines(new String(sources.copyBytes(newCopy), StandardCharsets.UTF_8));
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

    record StartupSample(Map<String,String> hashes,Map<String,byte[]> bytes,boolean unreadable,String cronText) {}
    StartupSample filesystemStartup() throws IOException {
        Map<String,String> hashes=new LinkedHashMap<>(); Map<String,byte[]> bytes=new LinkedHashMap<>();
        for(String dir:sources.dirs()) for(String file:sources.list(dir)) observeStartup(file,true,hashes,bytes);
        List<String> files=new ArrayList<>(sources.files()); files.addAll(extraStartup);
        for(String file:files) observeStartup(file,false,hashes,bytes);
        return new StartupSample(hashes,bytes,hashes.values().stream().anyMatch(v->v.startsWith("unreadable: ")),null);
    }
    void observeStartup(String file,boolean listed,Map<String,String> hashes,Map<String,byte[]> bytes) throws IOException {
        if(file.equals("crontab -l")) return; // Reserved independent partition, never a filesystem row.
        try {
            byte[] value=sources.entry(file);
            if(value==null) { if(listed) throw new CollectionHealth.Rejected("startup-read"); return; }
            bytes.put(file,value); hashes.put(file,HexFormat.of().formatHex(sha256().digest(value)));
        } catch(Unreadable e) { hashes.put(file,e.marker); bytes.remove(file); }
    }
    StartupSample cronStartup() throws IOException,Proc.Timeout {
        Proc.Result cron=sources.run(List.of("crontab","-l"),20);
        String disposition=CollectionHealth.command("crontab",cron), text=disposition.equals("ok-absent")?"":cron.out();
        byte[] value=text.getBytes(StandardCharsets.UTF_8);
        return new StartupSample(Map.of("crontab -l",disposition.equals("ok-absent")?"none":HexFormat.of().formatHex(sha256().digest(value))),Map.of("crontab -l",value),false,text);
    }
    Map<String,String> startupCopies(StartupSample sample,String partition,String copies) throws IOException {
        Map<String,String> destinations=new HashMap<>();
        for(Map.Entry<String,String> e:sample.hashes().entrySet()) {
            String file=e.getKey(),digest=e.getValue(),old=startup.get(file);
            if((old==null || !old.equals(digest) || baseline.get(partition)) && !digest.startsWith("unreadable: ")) {
                String dest=Paths.join(copies,safeName(file),Py.cut(digest,16));byte[] value=sample.bytes().get(file);
                // Full hash; files save first4MiB, cron has always saved its full text.
                sources.copy(dest,partition.equals("crontab")?value:Arrays.copyOf(value,Math.min(value.length,4*1024*1024)));
                destinations.put(file,dest);
            }
        }
        return destinations;
    }
    static String startupError(Exception e,boolean filesystem) {
        if(e instanceof CollectionHealth.Rejected r) return r.code;
        if(e instanceof Proc.Timeout) return "collection-timeout";
        if(e instanceof IOException io && CollectionHealth.ioError(io).equals("collection-parse")) return "collection-parse";
        return filesystem?"startup-read":"collection-io";
    }
    void checkStartup() {
        StartupSample fs=null,cron=null; Map<String,String> destinations=new HashMap<>();
        String copies=sources.copyRoot(snapDir);
        collectionHealth.attempt("startup",clock.get());
        try { fs=filesystemStartup(); }
        catch(IOException | java.nio.file.InvalidPathException e) {fs=null;collectionHealth.fail("startup",startupError(e,true));}
        if(fs!=null) try {destinations.putAll(startupCopies(fs,"startup",copies));}
        catch(IOException e) {fs=null;collectionHealth.fail("startup",CollectionHealth.ioError(e));}
        // Both observations are attempted independently, in this deterministic order.
        collectionHealth.attempt("crontab",clock.get());
        try { cron=cronStartup();destinations.putAll(startupCopies(cron,"crontab",copies)); }
        catch(IOException | Proc.Timeout e) {cron=null;collectionHealth.fail("crontab",startupError(e,false));}
        if(fs==null)heartbeat("startup",null,(String)((Map<?,?>)collectionHealth.snapshot().get("startup")).get("error"));
        if(cron==null)heartbeat("crontab",null,(String)((Map<?,?>)collectionHealth.snapshot().get("crontab")).get("error"));
        if(fs==null && cron==null) return;
        Map<String,String> proposed=new LinkedHashMap<>(startup);
        if(fs!=null) {proposed.keySet().removeIf(k->!k.equals("crontab -l"));proposed.putAll(fs.hashes());}
        if(cron!=null) proposed.putAll(cron.hashes());
        TreeSet<String> all=new TreeSet<>(Watch::codepointCompare); all.addAll(startup.keySet());all.addAll(proposed.keySet());
        List<String> sql=new ArrayList<>(); List<PendingEvent> events=new ArrayList<>(); String t=clock.get();
        try {
        for(String file:all) {
            String partition=file.equals("crontab -l")?"crontab":"startup";
            if((partition.equals("startup") && fs==null) || (partition.equals("crontab") && cron==null)) continue;
            String digest=proposed.get(file),old=startup.get(file);boolean first=baseline.get(partition);
            if(digest==null) {
                sql.add(Db.bind("DELETE FROM startup_items WHERE path=?",file));
                if(!first) events.add(new PendingEvent("STARTUP-","removed: "+file+" | last copy: "+(old.startsWith("unreadable: ")?"None":Paths.join(copies,safeName(file),Py.cut(old,16)))));
            } else {
                sql.add(Db.bind("INSERT OR REPLACE INTO startup_items(path,hash,last_checked) VALUES (?,?,?)",file,digest,t));
                if(old==null || !old.equals(digest) || first) {
                    String dest=destinations.get(file);
                    sql.add(Db.bind("INSERT INTO startup_versions(path,hash,copy_path,seen_at) VALUES (?,?,?,?)",file,digest,dest,t));
                    if(!first) {
                        if(old==null) events.add(new PendingEvent("STARTUP+","added: "+file+" | copy: "+(dest==null?"None":dest)));
                        else if(!digest.startsWith("unreadable: ")) {
                            String beforeHash=old,before=Paths.join(copies,safeName(file),Py.cut(old,16));
                            if(old.startsWith("unreadable: ")) {
                                List<Map<String,Object>> history=db.query(Db.bind("SELECT hash,copy_path FROM startup_versions WHERE path=? AND copy_path IS NOT NULL AND hash NOT LIKE 'unreadable: %' ORDER BY id DESC LIMIT 1;",file));
                                beforeHash=history.isEmpty()?null:Db.asStr(history.getFirst().get("hash"));before=history.isEmpty()?null:Db.asStr(history.getFirst().get("copy_path"));
                            }
                            if(beforeHash==null || !beforeHash.equals(digest))events.add(new PendingEvent("STARTUP~","changed: "+file+" | before: "+(before==null?"None":before)+" | after: "+dest+"\n"+diff(before,dest,40)));
                        }
                    }
                }
            }
        }
        if(fs!=null && baseline.get("startup")) events.add(new PendingEvent("BASELINE","startup items: "+fs.hashes().size()+" recorded, copies in "+copies));
        if(cron!=null && baseline.get("crontab")) events.add(new PendingEvent("BASELINE","crontab: 1 recorded, copies in "+copies));
        if(fs!=null)sql.add(heartbeatSql("startup",(long)fs.hashes().size(),fs.unreadable()?"startup-unreadable":null,t));
        if(cron!=null)sql.add(heartbeatSql("crontab","none".equals(cron.hashes().get("crontab -l"))?0L:1L,null,t));
        commitSample(sql,events,t);
        } catch(DbException | Db.Fatal e) {
            if(fs!=null)collectionHealth.fail("startup","collection-db");if(cron!=null)collectionHealth.fail("crontab","collection-db");
            if(e instanceof Db.Fatal fatal)throw fatal;
            if(fs!=null)heartbeat("startup",null,"collection-db");if(cron!=null)heartbeat("crontab",null,"collection-db");return;
        }
        Map<String,String> ordered=new LinkedHashMap<>();for(String file:all)if(proposed.containsKey(file))ordered.put(file,proposed.get(file));startup=ordered;
        if(fs!=null) {baseline.put("startup",false);if(fs.unreadable())collectionHealth.fail("startup","startup-unreadable");else collectionHealth.success("startup",clock.get());}
        if(cron!=null) {baseline.put("crontab",false);crontabText=cron.cronText();collectionHealth.success("crontab",clock.get());}
        publishEvents(events,t);
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

    interface StreamFactory { Process start(List<String> command) throws IOException; }
    StreamFactory streamFactory=command->new ProcessBuilder(command).redirectErrorStream(false)
            .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
    java.util.function.DoubleSupplier streamClock=Watch::monotonic;
    interface StreamPause {boolean waitFor(long millis)throws InterruptedException;}
    StreamPause streamPause=millis->stop.await(millis,TimeUnit.MILLISECONDS);
    java.util.function.Consumer<Map<?,?>> streamEvents=this::streamEvent;
    java.util.function.LongFunction<String[]> streamLookup=this::lookupNow;

    /** Owns the sole blocking stdout read, bounded to eight 64-KiB chunks.
     * EOF/failure is independent of the child process's lifetime. No DB access here.
     */
    static final class OwnedStreamReader {
        static final int CHUNK_BYTES=65536, QUEUE_CHUNKS=8;
        final InputStream input;
        final ArrayBlockingQueue<byte[]> chunks=new ArrayBlockingQueue<>(QUEUE_CHUNKS);
        final CountDownLatch entered=new CountDownLatch(1);
        final CountDownLatch ended=new CountDownLatch(1);
        final Thread thread;
        volatile boolean terminal,done,cancelled;
        volatile String error;
        OwnedStreamReader(InputStream input) {
            this(input,"stdout");
        }
        OwnedStreamReader(InputStream input,String channel) {
            this.input=input;thread=new Thread(this::read,"keychain-"+channel);thread.setDaemon(true);
        }
        void start(){thread.start();}
        void read() {
            byte[] buffer=new byte[CHUNK_BYTES];entered.countDown();
            try {
                while(!cancelled) {
                    int count=input.read(buffer);
                    if(Thread.currentThread().isInterrupted() && !cancelled)throw new InterruptedException("stream-reader-interrupted");
                    if(count<0){terminal=true;break;}
                    if(count==0)throw new IOException("stream-no-progress");
                    chunks.put(Arrays.copyOf(buffer,count));
                }
            } catch(IOException e){terminal=true;if(!cancelled)error=Thread.currentThread().isInterrupted()?"keychain-interrupted":"keychain-io";}
            catch(RuntimeException e){terminal=true;if(!cancelled)error="keychain-io";}
            catch(InterruptedException e){terminal=true;if(!cancelled)error="keychain-interrupted";Thread.currentThread().interrupt();}
            finally {terminal=true;done=true;ended.countDown();}
        }
        boolean observing(){return entered.getCount()==0 && thread.isAlive() && !thread.isInterrupted() && !terminal;}
        void cancel()throws IOException {cancelled=true;thread.interrupt();input.close();}
    }
    record StreamCleanup(boolean complete,boolean interrupted) {}
    static boolean joinOwned(Thread worker,long millis) {
        boolean interrupted=false;long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(millis);
        while(worker.isAlive()) {
            long remaining=deadline-System.nanoTime();if(remaining<=0)break;
            try {worker.join(Math.max(1,TimeUnit.NANOSECONDS.toMillis(remaining)));}
            catch(InterruptedException e){interrupted=true;}
        }
        return interrupted;
    }
    StreamCleanup cleanupStream(Process child,OwnedStreamReader reader) {
        return cleanupStream(child,reader,streamDiagnosticsReader);
    }
    StreamCleanup cleanupStream(Process child,OwnedStreamReader reader,OwnedStreamReader diagnostics) {
        boolean interrupted=Thread.interrupted(),closed=true;
        if(child!=null) {
            if(child.isAlive())child.destroy();
            try {child.waitFor(5,TimeUnit.SECONDS);}catch(InterruptedException e){interrupted=true;}
            if(child.isAlive()) {
                child.destroyForcibly();
                try {child.waitFor(5,TimeUnit.SECONDS);}catch(InterruptedException e){interrupted=true;}
            }
        }
        for(OwnedStreamReader owned:new OwnedStreamReader[]{reader,diagnostics})if(owned!=null) {
            try {owned.cancel();}catch(IOException e){closed=false;}
            interrupted|=joinOwned(owned.thread,5000);
        }
        if(child!=null) {
            if(reader==null)try{child.getInputStream().close();}catch(IOException e){closed=false;}
            if(diagnostics==null)try{child.getErrorStream().close();}catch(IOException e){closed=false;}
        }
        boolean complete=closed && (child==null || !child.isAlive()) && (reader==null || !reader.thread.isAlive())
                && (diagnostics==null || !diagnostics.thread.isAlive());
        if(complete){streamProc=null;streamReader=null;streamDiagnosticsReader=null;}
        else {streamWorkerFailure="keychain-cleanup";requestStop();}
        return new StreamCleanup(complete,interrupted);
    }

    void logStream() {
        while(!stopped()) {
            if(!logStreamOnce())return;
            try {if(streamPause.waitFor(10000))return;}
            catch(InterruptedException e){
                boolean expected=stopped();if(!expected){streamWorkerFailure="keychain-interrupted";requestStop();}
                try{heartbeat("keychain",null,expected?"keychain-ended":"keychain-interrupted");}finally{Thread.currentThread().interrupt();}
                return;
            }
        }
    }
    boolean logStreamOnce() {
        // A prior incomplete cleanup never authorizes a second owned child/reader.
        if(streamProc!=null || streamReader!=null || streamDiagnosticsReader!=null) {
            streamWorkerFailure="keychain-cleanup";requestStop();heartbeat("keychain",null,"keychain-cleanup");return false;
        }
        List<String> preds=new ArrayList<>();for(String name:STREAM_PROCS)preds.add("process == \""+name+"\"");
        List<String> command=List.of("log","stream","--style","ndjson","--predicate",String.join(" OR ",preds));
        Process child=null;OwnedStreamReader reader=null,diagnosticReader=null;
        boolean interrupted=false,retry=false,recorded=false,clean=true;
        try {
            try {child=streamFactory.start(command);streamProc=child;}
            catch(IOException e){heartbeat("keychain",null,"keychain-unavailable");log("NOTE","log stream unavailable; credential checks use the process list only; keychain coverage is degraded");return false;}
            reader=new OwnedStreamReader(child.getInputStream());streamReader=reader;reader.start();
            diagnosticReader=new OwnedStreamReader(child.getErrorStream(),"stderr");streamDiagnosticsReader=diagnosticReader;diagnosticReader.start();
            java.io.ByteArrayOutputStream pending=new java.io.ByteArrayOutputStream();
            java.io.ByteArrayOutputStream diagnostics=new java.io.ByteArrayOutputStream();streamDiagnostics=new byte[0];
            KeychainProgress progress=new KeychainProgress();
            double deadline=streamClock.getAsDouble()+Coverage.KEYCHAIN_CADENCE,deadSince=Double.NaN,closedSince=Double.NaN;
            while(!stopped()) {
                byte[] bytes=reader.chunks.poll();
                // Fair, bounded diagnostic drain. Stderr is never JSON record evidence.
                byte[] diagnosticBytes=diagnosticReader.chunks.poll();
                if(diagnosticBytes!=null) {
                    diagnostics.write(diagnosticBytes,0,Math.min(diagnosticBytes.length,STREAM_DIAGNOSTIC_LIMIT-diagnostics.size()));
                    streamDiagnostics=diagnostics.toByteArray();
                }
                if(bytes!=null)for(byte value:bytes) {
                    if(value=='\n') {
                        Map<?,?> event=progress.line(pending.toByteArray());pending.reset();
                        if(event!=null)streamEvents.accept(event);
                    } else pending.write(value);
                    if(pending.size()>1024*1024){heartbeat("keychain",null,"keychain-malformed");recorded=true;break;}
                }
                if(recorded)break;
                boolean alive=child.isAlive();
                if((reader.thread.isInterrupted() && !reader.cancelled)
                        || (diagnosticReader.thread.isInterrupted() && !diagnosticReader.cancelled)) {
                    streamWorkerFailure="keychain-interrupted";requestStop();
                    heartbeat("keychain",null,"keychain-interrupted");recorded=true;break;
                }
                if(diagnosticReader.error!=null) {
                    heartbeat("keychain",null,diagnosticReader.error);recorded=true;
                    if(diagnosticReader.error.equals("keychain-interrupted")){streamWorkerFailure="keychain-interrupted";requestStop();}
                    break;
                }
                // Finished reader + empty queue proves final bytes have been drained.
                // EOF while the child remains alive is a closed stream, never healthy idle.
                boolean stdoutDone=reader.done && reader.chunks.isEmpty();
                boolean diagnosticsDone=diagnosticReader.done && diagnosticReader.chunks.isEmpty();
                if(stdoutDone && reader.error!=null) {
                    heartbeat("keychain",null,reader.error);recorded=true;
                    if(reader.error.equals("keychain-interrupted")){streamWorkerFailure=reader.error;requestStop();}
                    break;
                }
                if(stdoutDone && diagnosticsDone) {
                    if(alive)alive=!child.waitFor(5,TimeUnit.SECONDS);
                    String error=alive?"keychain-closed":"keychain-ended";
                    heartbeat("keychain",null,error);recorded=true;
                    if(error.equals("keychain-interrupted")){streamWorkerFailure=error;requestStop();}
                    if(!alive) {
                        if(progress.recordsSeen==0 && child.exitValue()!=0)log("NOTE","log stream exited without records; credential checks use the process list only; keychain coverage is degraded");
                        retry=progress.recordsSeen>0 || child.exitValue()==0;
                    }
                    break;
                }
                double now=streamClock.getAsDouble();
                if(!alive) {
                    if(Double.isNaN(deadSince))deadSince=now;
                    if(now-deadSince>=5) {
                        streamWorkerFailure="keychain-reader-stalled";requestStop();
                        heartbeat("keychain",null,"keychain-reader-stalled");recorded=true;break;
                    }
                }
                if(stdoutDone && alive) {
                    if(Double.isNaN(closedSince))closedSince=now;
                    if(now-closedSince>=5){heartbeat("keychain",null,"keychain-closed");recorded=true;break;}
                }
                if(alive && reader.observing() && (diagnosticReader.done || diagnosticReader.observing()) && now>=deadline) {
                    KeychainProgress.Cycle cycle=progress.cycle(true,pending.size()!=0);
                    // Recheck terminal state after taking the count: no EOF/failure credit.
                    if(reader.observing() && diagnosticReader.error==null)heartbeat("keychain",cycle.count(),cycle.error());
                    deadline=now+Coverage.KEYCHAIN_CADENCE;
                }
                if(bytes==null && diagnosticBytes==null && streamPause.waitFor(250))break;
            }
            if(!recorded)heartbeat("keychain",null,"keychain-ended");
        } catch(InterruptedException e) {
            interrupted=true;boolean expected=stopped();
            if(!expected){streamWorkerFailure="keychain-interrupted";requestStop();}
            heartbeat("keychain",null,expected?"keychain-ended":"keychain-interrupted");
        } finally {
            StreamCleanup cleanup=cleanupStream(child,reader,diagnosticReader);clean=cleanup.complete();interrupted|=cleanup.interrupted();
            if(cleanup.interrupted() && !stopped()){streamWorkerFailure="keychain-interrupted";requestStop();}
            if(interrupted)Thread.currentThread().interrupt();
        }
        if("keychain-interrupted".equals(streamWorkerFailure))heartbeat("keychain",null,"keychain-interrupted");
        if(!clean)heartbeat("keychain",null,"keychain-cleanup");
        return retry && clean && !stopped();
    }

    void streamEvent(Map<?,?> ev) {
        long pid=(Long)ev.get("processID");String proc=Py.basename((String)ev.get("processImagePath"));
        double t=monotonic();Double last=streamPids.get(pid);if(last!=null && t-last<300)return;
        String[] lookup=streamLookup.apply(pid);String args=lookup[0],chain=lookup[1];
        String kind=proc.equals("SecurityAgent")?"PASSWORD":"CRED-NET";
        String message=proc+" pid "+pid+" | args: "+(args.isEmpty()?"(exited)":args)+" | chain: "+chain
                +" | first log: "+Py.cut(ev.containsKey("eventMessage")?(String)ev.get("eventMessage"):"",160);
        String stamp=clock.get();
        try {
            commitSample(List.of(Db.bind("INSERT INTO credential_events(time,source,pid,user,exe,args,chain) VALUES (?,?,?,?,?,?,?)",
                    stamp,"log",pid,"",proc,Py.cut(args,1000),chain)),List.of(new PendingEvent(kind,message)),stamp);
        }catch(DbException e){throw new Db.Fatal(e);}
        streamPids.put(pid,t);
        if(streamPids.size()>2000)streamPids.entrySet().removeIf(entry->t-entry.getValue()>=300);
        publishEvents(List.of(new PendingEvent(kind,message)),stamp);
    }

    // ---- pid file ----
    /** What a live watcher's command line looks like, for either version. */
    static boolean isTattletaleCommand(String command) {
        if (command.contains("tattletale.py") || command.contains("tattletale.jar")
                || command.contains("dev.tattletale.Main") || command.contains("java/build/tattletale")) return true;
        List<String> w = Py.split(command);
        return !w.isEmpty() && Py.basename(w.get(0)).equals("tattletale");
    }

    interface PidProbe { Proc.Result inspect(long pid) throws IOException,Proc.Timeout; }
    PidProbe pidProbe=pid->Proc.run(List.of("ps","-p",Long.toString(pid),"-o","command="),20);
    enum PidIdentity { WATCHER, OTHER, ABSENT, UNKNOWN }
    static PidIdentity pidIdentity(Proc.Result result) {
        if(result.code()==1 && result.out().isEmpty() && result.err().isEmpty()) return PidIdentity.ABSENT;
        List<String> lines=new ArrayList<>(Arrays.asList(result.out().split("\\n",-1)));
        if(!lines.isEmpty() && lines.getLast().isEmpty()) lines.removeLast();
        if(result.code()!=0 || !result.err().isEmpty() || lines.size()!=1 || asciiStrip(lines.getFirst()).isEmpty()) return PidIdentity.UNKNOWN;
        return isTattletaleCommand(lines.getFirst())?PidIdentity.WATCHER:PidIdentity.OTHER;
    }
    /** A failed identity observation cannot authorize replacement of another watcher's pid. */
    void claimPidFile() throws IOException {
        String path=Paths.join(Py.dirname(Paths.abspath(dbPath)),"tattletale.pid");
        long other=0,me=ProcessHandle.current().pid();boolean stale=false;
        try {
            if(!Files.readAttributes(Path.of(path),java.nio.file.attribute.BasicFileAttributes.class,java.nio.file.LinkOption.NOFOLLOW_LINKS).isRegularFile())
                throw new Exit("tattletale: existing pid identity is unknown");
            // Non-UTF8 bytes are invalid stale content, never a partially parsed PID.
            String value;
            try {value=asciiStrip(Files.readString(Path.of(path)));}
            catch(java.nio.charset.CharacterCodingException invalid){value="";}
            try {other=pidValue(value,false,"pid-identity");}
            catch(CollectionHealth.Rejected e) {stale=true;}
        } catch(java.nio.file.NoSuchFileException e) {
            // A final dangling link is an existing unknown identity, not first-start absence.
            if(Files.exists(Path.of(path),java.nio.file.LinkOption.NOFOLLOW_LINKS))
                throw new Exit("tattletale: existing pid identity is unknown");
        }
        if(other!=0 && other!=me) {
            PidIdentity identity;
            try {identity=pidIdentity(pidProbe.inspect(other));}
            catch(IOException | Proc.Timeout e) {identity=PidIdentity.UNKNOWN;}
            if(identity==PidIdentity.UNKNOWN) throw new Exit("tattletale: existing pid identity is unknown");
            if(identity==PidIdentity.WATCHER) throw new Exit("tattletale: already running as pid "+other+" for this database ("+path+"); stop it first: kill "+other);
        }
        Path destination=Path.of(path),tmp=Files.createTempFile(destination.getParent(),".tattletale-pid-",".tmp");
        try {
            try(java.nio.channels.FileChannel file=java.nio.channels.FileChannel.open(tmp,StandardOpenOption.WRITE)) {
                java.nio.ByteBuffer data=StandardCharsets.UTF_8.encode(me+"\n");while(data.hasRemaining())file.write(data);file.force(true);
            }
            pidReplace.move(tmp,destination);
        } catch(IOException e) {try{Files.deleteIfExists(tmp);}catch(IOException cleanup){e.addSuppressed(cleanup);}throw e;}
        pidFile=path;
        if(stale)log("NOTE","pid file contained invalid stale content; replacing");
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

    volatile Db.Fatal workerDatabaseFailure;
    void ownedWorker(Runnable body) {
        try {body.run();}
        catch(Db.Fatal e) {workerDatabaseFailure=e;requestStop();}
    }
    interface RuntimeBody {void run() throws IOException,DbException;}
    void withOwnedCleanup(RuntimeBody body,Thread... workers) throws IOException,DbException {
        try {body.run();}
        finally {
            requestStop();
            for(Thread worker:workers) worker.interrupt();
            boolean interrupted=false;
            // Terminal wait, terminate/kill, and both owned reader joins are bounded.
            for(Thread worker:workers)interrupted|=joinOwned(worker,30000);
            for(Thread worker:workers)if(worker.isAlive())streamWorkerFailure="worker-cleanup-incomplete";
            synchronized(LOCK) {db.close();}
            releasePidFile();
            if(interrupted) Thread.currentThread().interrupt();
        }
        // A worker can fail after the loop's final check. Join/cleanup first, then
        // preserve NONZERO on an otherwise normal return; never mask a body failure.
        if(workerDatabaseFailure!=null) throw workerDatabaseFailure;
        if(streamWorkerFailure!=null)throw new Exit("tattletale: "+streamWorkerFailure);
    }
    void run() throws IOException, DbException {
        Thread ls=new Thread(()->ownedWorker(this::logStream),"log-stream");ls.setDaemon(true);
        Thread iw=new Thread(()->ownedWorker(this::identityWorker),"identity");iw.setDaemon(true);
        withOwnedCleanup(()->{
        claimPidFile();
        installDashboard();
        log("START", "tattletale " + VERSION + " pid " + ProcessHandle.current().pid() + " db " + dbPath);
        loadState();
        safe("retention", this::retain);
        ls.start(); iw.start();
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
        if(workerDatabaseFailure!=null) throw workerDatabaseFailure;
        safe("save", this::save);
        log("STOP", "tattletale stopped");
        },ls,iw);
    }
}
