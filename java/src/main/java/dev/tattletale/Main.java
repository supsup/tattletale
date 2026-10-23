package dev.tattletale;

import dev.tattletale.Db.DbException;
import dev.tattletale.Watch.Exit;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * tattletale, the Java version: command line, settings and the one-shot modes (--show-settings,
 * --report, --query), then the watcher. Mirrors python/tattletale.py's main().
 */
public final class Main {
    private Main() {}

    // ---- where the repository is ----
    static final String REPO = locateRepo();
    static final String DATA = Paths.join(REPO, "data");
    static final String DASHBOARD = Paths.join(REPO, "dashboard", "tattletale.html");

    /**
     * The repository root: three levels above the jar, the classes directory or the native binary
     * (<repo>/java/build/tattletale.jar, <repo>/java/build/classes, <repo>/java/build/tattletale).
     * If that does not land in a folder holding java/, fall back to the working directory: the
     * working directory itself when it holds java/ or dashboard/, its parent when it is java/.
     */
    static String locateRepo() {
        List<Path> candidates = new ArrayList<>();
        try {
            var cs = Main.class.getProtectionDomain().getCodeSource();
            if (cs != null && cs.getLocation() != null && "file".equals(cs.getLocation().getProtocol()))
                candidates.add(Path.of(cs.getLocation().toURI()));
        } catch (Exception ignored) {
            // no code source (native image)
        }
        ProcessHandle.current().info().command().ifPresent(c -> {
            if (!Py.basename(c).equals("java")) candidates.add(Path.of(c));
        });
        for (Path p : candidates) {
            try {
                Path real = p.toRealPath();
                Path build = real.getParent(), java = build == null ? null : build.getParent();
                Path repo = java == null ? null : java.getParent();
                if (repo != null && java.getFileName().toString().equals("java") && Files.isDirectory(java))
                    return repo.toString();
            } catch (IOException ignored) {
                // try the next
            }
        }
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        if (Files.isDirectory(cwd.resolve("java")) || Files.isDirectory(cwd.resolve("dashboard"))) return cwd.toString();
        if (cwd.getFileName() != null && cwd.getFileName().toString().equals("java") && cwd.getParent() != null)
            return cwd.getParent().toString();
        return cwd.toString();
    }

    // ---- settings: flag > environment variable > config file > default ----
    enum Kind { STR, FLOAT, BOOL, INT, LIST }

    record Setting(String name, Kind kind, Object dflt, String help) {}

    static final List<Setting> SETTINGS = List.of(
            new Setting("log", Kind.STR, Paths.join(DATA, "tattletale.log"), "log file"),
            new Setting("db", Kind.STR, Paths.join(DATA, "tattletale.db"),
                    "state database (SQLite); the page data file and startup copies are kept beside it"),
            new Setting("map", Kind.STR, Paths.join(DATA, "tattletale-map.json"),
                    "old JSON state map, imported once into an empty database; never written"),
            new Setting("process_interval", Kind.FLOAT, 3L, "seconds between process-list scans"),
            new Setting("listen_interval", Kind.FLOAT, 30L, "seconds between listening-port scans"),
            new Setting("startup_interval", Kind.FLOAT, 300L, "seconds between startup-item scans"),
            new Setting("notify", Kind.BOOL, Boolean.TRUE, "show macOS notifications for alerts"),
            new Setting("rotate_mb", Kind.FLOAT, 20L, "rotate the log when it reaches this many MB"),
            new Setting("keep_logs", Kind.INT, 3L, "how many rotated logs to keep"),
            new Setting("extra_startup", Kind.LIST, List.of(),
                    "extra files to treat as startup items (colon-separated in env/config)"),
            new Setting("retention_days", Kind.INT, 30L, "days to keep events and credential events (0 keeps them forever)"),
            new Setting("sightings_retention_days", Kind.INT, 7L,
                    "days to keep process sightings, the busiest table (0 keeps them forever)"));

    static Setting setting(String name) {
        for (Setting s : SETTINGS) if (s.name().equals(name)) return s;
        return null;
    }

    /** KEY=VALUE lines; # comments and blank lines ignored; optional quotes; no shell expansion. */
    static Map<String, String> parseEnvFile(String path) throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        String text = new String(Files.readAllBytes(Path.of(path)), StandardCharsets.UTF_8);
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        int n = 0;
        for (String raw : lines) {
            n++;
            if (n == lines.length && raw.isEmpty()) break;
            String line = Py.strip(raw);
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("export ")) line = lstrip(line.substring(7));
            int eq = line.indexOf('=');
            if (eq < 0) throw new Exit("tattletale: " + path + ":" + n + ": expected KEY=VALUE");
            String key = line.substring(0, eq), val = Py.strip(line.substring(eq + 1));
            if (Py.len(val) >= 2 && val.charAt(0) == val.charAt(val.length() - 1) && (val.charAt(0) == '\'' || val.charAt(0) == '"'))
                val = val.substring(1, val.length() - 1);
            out.put(Py.strip(key), val);
        }
        return out;
    }

    static String lstrip(String s) {
        int a = 0;
        while (a < s.length() && Py.isSpace(s.codePointAt(a))) a += Character.charCount(s.codePointAt(a));
        return s.substring(a);
    }

    static Object convert(String name, Kind kind, Object raw) {
        switch (kind) {
            case BOOL -> {
                String v = Py.strip(Py.str(raw)).toLowerCase();
                if (List.of("1", "true", "yes", "on").contains(v)) return Boolean.TRUE;
                if (List.of("0", "false", "no", "off").contains(v)) return Boolean.FALSE;
                throw new Exit("tattletale: " + name + ": expected true or false, got " + Py.repr(raw));
            }
            case LIST -> {
                List<String> parts = new ArrayList<>();
                if (raw instanceof List<?> l) for (Object o : l) parts.add(Py.str(o));
                else parts.addAll(Arrays.asList(Py.str(raw).split(":", -1)));
                List<String> out = new ArrayList<>();
                for (String x : parts) if (!x.isEmpty()) out.add(Py.expanduser(x));
                return out;
            }
            case STR -> {
                return Py.str(raw);
            }
            case INT -> {
                if (raw instanceof Long l) return l;
                try {
                    return Py.parseInt(Py.str(raw));
                } catch (NumberFormatException e) {
                    throw new Exit("tattletale: " + name + ": expected a whole number, got " + Py.repr(raw));
                }
            }
            default -> {
                if (raw instanceof Double d) return d;
                try {
                    return Py.parseFloat(Py.str(raw));
                } catch (NumberFormatException e) {
                    throw new Exit("tattletale: " + name + ": expected a number, got " + Py.repr(raw));
                }
            }
        }
    }

    record Resolved(Map<String, Object> eff, Map<String, String> src, String cfgPath) {}

    /**
     * Effective settings and where each came from. Config-file keys are checked as
     * TATTLETALE_<NAME> with NAME = the key after the 11-character prefix "TATTLETALE_". (The
     * Python version slices k[9:], two characters short, so it refuses every TATTLETALE_* key in
     * a config file; this version accepts the documented names and refuses everything else.)
     */
    static Resolved resolveSettings(Args a) {
        String cfgPath = a.config != null ? a.config
                : System.getenv("TATTLETALE_CONFIG") != null ? System.getenv("TATTLETALE_CONFIG") : Paths.join(REPO, "tattletale.env");
        Map<String, String> fileVals = new LinkedHashMap<>();
        String exp = Py.expanduser(cfgPath);
        if (Files.exists(Path.of(exp))) {
            try {
                fileVals = parseEnvFile(exp);
            } catch (IOException e) {
                throw new Exit("tattletale: " + Py.oserror(e, exp));
            }
            List<String> unknown = new ArrayList<>();
            for (String k : fileVals.keySet()) {
                if (k.equals("TATTLETALE_CONFIG")) continue;
                if (!(k.startsWith("TATTLETALE_") && setting(k.substring(11).toLowerCase()) != null)) unknown.add(k);
            }
            unknown.sort(Watch::codepointCompare);
            if (!unknown.isEmpty()) throw new Exit("tattletale: " + cfgPath + ": unknown setting(s): " + String.join(", ", unknown));
        } else if (a.config != null) {
            throw new Exit("tattletale: config file not found: " + a.config);
        }
        Map<String, Object> eff = new LinkedHashMap<>();
        Map<String, String> src = new LinkedHashMap<>();
        for (Setting s : SETTINGS) {
            String key = "TATTLETALE_" + s.name().toUpperCase();
            Object flag = a.values.get(s.name());
            if (flag != null && !(flag instanceof List<?> l && l.isEmpty())) {
                eff.put(s.name(), convert(s.name(), s.kind(), flag));
                src.put(s.name(), "flag");
            } else if (System.getenv().containsKey(key)) {
                eff.put(s.name(), convert(s.name(), s.kind(), System.getenv(key)));
                src.put(s.name(), "env");
            } else if (fileVals.containsKey(key)) {
                eff.put(s.name(), convert(s.name(), s.kind(), fileVals.get(key)));
                src.put(s.name(), "config");
            } else {
                eff.put(s.name(), s.dflt());
                src.put(s.name(), "default");
            }
        }
        for (String n : List.of("log", "db", "map")) eff.put(n, Py.expanduser((String) eff.get(n)));
        return new Resolved(eff, src, cfgPath);
    }

    // ---- the command line, as argparse reads it ----
    static final class Args {
        String config, query;
        boolean report, showSettings;
        final Map<String, Object> values = new LinkedHashMap<>();
    }

    static final String PROG = "tattletale";

    static String usage() {
        StringBuilder sb = new StringBuilder("usage: " + PROG
                + " [-h] [--config CONFIG] [--version] [--report] [--query SQL] [--show-settings]");
        for (Setting s : SETTINGS) {
            String f = "--" + s.name().replace('_', '-');
            if (s.kind() == Kind.BOOL) sb.append(" [").append(f).append("] [--no-").append(s.name().replace('_', '-')).append(']');
            else sb.append(" [").append(f).append(' ').append(s.name().toUpperCase()).append(']');
        }
        return sb.toString();
    }

    static String help() {
        StringBuilder sb = new StringBuilder(usage()).append("\n\n");
        sb.append("Watch for credential prompts, new listeners, new programs and startup changes.\n\n");
        sb.append("options:\n");
        sb.append("  -h, --help            show this help message and exit\n");
        sb.append("  --config CONFIG       settings file (default: tattletale.env at the repository root)\n");
        sb.append("  --version             show program's version number and exit\n");
        sb.append("  --report              print a summary of the database and exit\n");
        sb.append("  --query SQL           run one read-only SELECT against the database, print tab-separated rows, and exit\n");
        sb.append("  --show-settings       print the effective settings and where each came from, then exit\n");
        for (Setting s : SETTINGS) {
            String f = "--" + s.name().replace('_', '-');
            String h = switch (s.kind()) {
                case BOOL -> s.help();
                case LIST -> s.help() + " (repeatable)";
                default -> s.help() + " (default " + Py.str(s.dflt()) + ")";
            };
            String left = s.kind() == Kind.BOOL ? f : f + " " + s.name().toUpperCase();
            sb.append("  ").append(left);
            if (left.length() <= 20) sb.append(" ".repeat(22 - left.length())).append(h).append('\n');
            else sb.append("\n                        ").append(h).append('\n');
            if (s.kind() == Kind.BOOL) sb.append("  --no-").append(s.name().replace('_', '-')).append('\n');
        }
        return sb.toString();
    }

    static Exit usageError(String msg) {
        return new Exit(usage() + "\n" + PROG + ": error: " + msg, 2);
    }

    private static final Pattern NEGNUM = Pattern.compile("^-\\d+$|^-\\d*\\.\\d+$");

    static Args parseArgs(String[] argv) {
        // option string -> (dest, kind of action)
        Map<String, String[]> opts = new LinkedHashMap<>();
        opts.put("--help", new String[] {"help", "flag"});
        opts.put("--config", new String[] {"config", "value"});
        opts.put("--version", new String[] {"version", "flag"});
        opts.put("--report", new String[] {"report", "flag"});
        opts.put("--query", new String[] {"query", "value"});
        opts.put("--show-settings", new String[] {"show_settings", "flag"});
        for (Setting s : SETTINGS) {
            String f = "--" + s.name().replace('_', '-');
            switch (s.kind()) {
                case BOOL -> {
                    opts.put(f, new String[] {s.name(), "true"});
                    opts.put("--no-" + s.name().replace('_', '-'), new String[] {s.name(), "false"});
                }
                case LIST -> opts.put(f, new String[] {s.name(), "append"});
                default -> opts.put(f, new String[] {s.name(), "value"});
            }
        }
        Args a = new Args();
        List<String> extras = new ArrayList<>();
        for (int i = 0; i < argv.length; i++) {
            String arg = argv[i];
            if (arg.equals("--")) {
                extras.addAll(Arrays.asList(argv).subList(i + 1, argv.length));
                break;
            }
            if (arg.equals("-h")) {
                Watch.OUT.print(help());
                throw new Exit(null, 0);
            }
            if (!arg.startsWith("--") || NEGNUM.matcher(arg).matches()) {
                extras.add(arg);
                continue;
            }
            String name = arg, explicit = null;
            int eq = arg.indexOf('=');
            if (eq >= 0) {
                name = arg.substring(0, eq);
                explicit = arg.substring(eq + 1);
            }
            String opt;
            if (opts.containsKey(name)) opt = name;
            else {
                List<String> m = new ArrayList<>();
                for (String o : opts.keySet()) if (o.startsWith(name)) m.add(o);
                if (m.size() > 1) throw usageError("ambiguous option: " + name + " could match " + String.join(", ", m));
                if (m.isEmpty()) {
                    extras.add(arg);
                    continue;
                }
                opt = m.get(0);
            }
            String dest = opts.get(opt)[0], act = opts.get(opt)[1];
            if (!act.equals("value") && !act.equals("append")) {
                if (explicit != null) throw usageError("argument " + opt + ": ignored explicit argument " + Py.repr(explicit));
                switch (dest) {
                    case "help" -> {
                        Watch.OUT.print(help());
                        throw new Exit(null, 0);
                    }
                    case "version" -> {
                        Watch.OUT.println("tattletale " + Watch.VERSION);
                        throw new Exit(null, 0);
                    }
                    case "report" -> a.report = true;
                    case "show_settings" -> a.showSettings = true;
                    default -> a.values.put(dest, act.equals("true"));
                }
                continue;
            }
            String val = explicit;
            if (val == null) {
                if (i + 1 >= argv.length || (argv[i + 1].startsWith("-") && !argv[i + 1].equals("-")
                        && !NEGNUM.matcher(argv[i + 1]).matches()))
                    throw usageError("argument " + opt + ": expected one argument");
                val = argv[++i];
            }
            switch (dest) {
                case "config" -> a.config = val;
                case "query" -> a.query = val;
                default -> {
                    Setting s = setting(dest);
                    Object v = val;
                    try {
                        if (s.kind() == Kind.FLOAT) v = Py.parseFloat(val);
                        else if (s.kind() == Kind.INT) v = Py.parseInt(val);
                    } catch (NumberFormatException e) {
                        throw usageError("argument " + opt + ": invalid " + (s.kind() == Kind.INT ? "int" : "float")
                                + " value: " + Py.repr(val));
                    }
                    if (s.kind() == Kind.LIST) {
                        @SuppressWarnings("unchecked")
                        List<Object> l = (List<Object>) a.values.computeIfAbsent(dest, k -> new ArrayList<>());
                        l.add(v);
                    } else a.values.put(dest, v);
                }
            }
        }
        if (!extras.isEmpty()) throw usageError("unrecognized arguments: " + String.join(" ", extras));
        return a;
    }

    // ---- --report ----
    static void report(String dbPath) throws DbException {
        Db conn = Watch.openDbReadonly(dbPath);
        if (conn == null) {
            Watch.OUT.println("no database yet");
            return;
        }
        try (conn) {
            Watch.OUT.println("programs seen: " + Py.str(conn.scalar("SELECT count(*) FROM programs;")));
            Watch.OUT.println("listeners seen: " + Py.str(conn.scalar("SELECT count(*) FROM listeners;")));
            for (Map<String, Object> r : conn.query("SELECT key, first_seen FROM listeners WHERE exposed ORDER BY key;"))
                Watch.OUT.println("  EXPOSED  " + Py.str(r.get("key")) + "  (first seen " + Py.str(r.get("first_seen")) + ")");
            Watch.OUT.println("startup items tracked: " + Py.str(conn.scalar("SELECT count(*) FROM startup_items;")));
            Watch.OUT.println("process sightings kept: " + Py.str(conn.scalar("SELECT count(*) FROM sightings;")));
            Watch.OUT.println("credential events kept: " + Py.str(conn.scalar("SELECT count(*) FROM credential_events;")));
            Watch.OUT.println("log events kept: " + Py.str(conn.scalar("SELECT count(*) FROM events;")));
        }
    }

    // ---- --query ----
    private static final Pattern SELECT_OR_WITH = Pattern.compile("(?is)^(select|with)\\b");
    private static final Pattern RENAMED = Pattern.compile("^(.*):(\\d+)$");
    private static final String COL = "\u001f", ROW = "\u001e";

    /**
     * Run one SELECT (or WITH ... SELECT) against the database opened read-only and print the rows
     * tab-separated, with a header line. Anything else is refused: the statement must start with
     * SELECT or WITH and hold no ';' (as in Python); the shell is started -readonly with
     * query_only on and -safe (no ATTACH, no load_extension, no file functions), and the statement
     * is passed as one argument, so it can never be read as a shell dot-command.
     */
    static void runQuery(String dbPath, String sql) {
        String s = Py.strip(sql);
        while (s.endsWith(";")) s = rstrip(s.substring(0, s.length() - 1));
        if (!SELECT_OR_WITH.matcher(s).find() || s.contains(";"))
            throw new Exit("tattletale: --query takes a single SELECT or WITH statement (no ';' inside)");
        if (!Files.exists(Path.of(dbPath))) throw new Exit("tattletale: no database at " + dbPath);
        String abs = new java.io.File(dbPath).getAbsolutePath();
        Proc.Result r;
        try {
            r = Proc.run(List.of(Db.SQLITE, "-safe", "-batch", "-readonly", "-cmd", ".timeout 30000", "-cmd",
                    "PRAGMA query_only=ON", "-cmd", ".headers on", "-cmd", ".mode list", "-cmd",
                    ".separator \"\\037\" \"\\036\"", "-cmd", ".nullvalue \"\"", abs, s));
        } catch (IOException | Proc.Timeout e) {
            throw new Exit("tattletale: query failed: " + e.getMessage());
        }
        if (r.code() != 0 || !r.err().isEmpty()) {
            List<String> errs = Py.splitlines(r.err());
            throw new Exit("tattletale: query failed: " + (errs.isEmpty() ? "sqlite3 exited " + r.code() : Db.clean(errs)));
        }
        List<String> records = new ArrayList<>(Arrays.asList(r.out().split(ROW, -1)));
        if (!records.isEmpty() && records.get(records.size() - 1).isEmpty()) records.remove(records.size() - 1);
        StringBuilder out = new StringBuilder();
        if (records.isEmpty()) {
            out.append(String.join("\t", columnNames(abs, s))).append('\n');
        } else {
            out.append(String.join("\t", records.get(0).split(COL, -1))).append('\n');
            for (String rec : records.subList(1, records.size())) {
                List<String> cells = new ArrayList<>();
                for (String c : rec.split(COL, -1)) cells.add(c.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n"));
                out.append(String.join("\t", cells)).append('\n');
            }
        }
        Watch.OUT.print(out);
        Watch.OUT.flush();
    }

    /** Column names for a query that returned no rows (the shell prints no header then). */
    static List<String> columnNames(String abs, String s) {
        List<String> names = new ArrayList<>();
        try {
            Proc.Result r = Proc.run(List.of(Db.SQLITE, "-safe", "-batch", "-readonly", "-json", "-cmd", ".timeout 30000", abs,
                    "CREATE TEMP VIEW _tattletale_q AS " + s + "; SELECT name FROM pragma_table_info('_tattletale_q');"));
            if (r.code() != 0 || r.out().isBlank()) return names;
            for (Object o : (List<?>) Json.parse(r.out())) {
                String n = Py.str(((Map<?, ?>) o).get("name"));
                var m = RENAMED.matcher(n);
                // a view renames a repeated column "a" to "a:1"; the statement itself says "a"
                if (m.matches() && names.contains(m.group(1))) n = m.group(1);
                names.add(n);
            }
        } catch (IOException | Proc.Timeout | Json.ParseError | ClassCastException e) {
            // no header names available
        }
        return names;
    }

    static String rstrip(String s) {
        int b = s.length();
        while (b > 0 && Py.isSpace(s.codePointBefore(b))) b -= Character.charCount(s.codePointBefore(b));
        return s.substring(0, b);
    }

    // ---- one-time move of a v0.0.1 data set ----
    static final List<String> V001_FILES = List.of("tattletale.db", "tattletale.db-wal", "tattletale.db-shm",
            "tattletale-data.js", "tattletale.stdout", "tattletale-map.json", "startup-snapshots");

    /**
     * One-time move of a v0.0.1 data set from the repo root into data/. Runs only with the
     * default database path, only when data/ has no database yet, and never while a v0.0.1
     * watcher still holds the old pid file.
     */
    static List<String> migrateV001(String dataDir) throws IOException, DbException {
        String oldDb = Paths.join(REPO, "tattletale.db");
        if (!Files.exists(Path.of(oldDb)) || Files.exists(Path.of(dataDir, "tattletale.db"))) return null;
        String oldPid = Paths.join(REPO, "tattletale.pid");
        try {
            String t = Py.strip(Files.readString(Path.of(oldPid)));
            long pid = t.isEmpty() ? 0 : Py.parseInt(t);
            Proc.Result r = Proc.run(List.of("ps", "-p", Long.toString(pid), "-o", "command="));
            if (pid != 0 && r.code() == 0 && r.out().contains("tattletale.py"))
                throw new Exit("tattletale: a v0.0.1 watcher (pid " + pid + ") is still using " + oldDb + "; stop it first (kill "
                        + pid + "), then start again to move its data into " + dataDir);
        } catch (IOException | NumberFormatException | Proc.Timeout ignored) {
            // no old pid file
        }
        Files.createDirectories(Path.of(dataDir));
        List<String> moved = new ArrayList<>();
        List<String> names = new ArrayList<>(V001_FILES);
        String[] all = new java.io.File(REPO).list();
        List<String> logs = new ArrayList<>();
        if (all != null) for (String n : all) if (n.startsWith("tattletale.log")) logs.add(n);
        logs.sort(Watch::codepointCompare);
        names.addAll(logs);
        for (String name : names) {
            Path src = Path.of(REPO, name);
            if (Files.exists(src)) {
                Files.move(src, Path.of(dataDir, name), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                moved.add(name);
            }
        }
        try {
            Files.delete(Path.of(oldPid));
        } catch (IOException ignored) {
            // dead, checked above
        }
        String oldSnap = Paths.join(REPO, "startup-snapshots");
        String newSnap = Paths.join(dataDir, "startup-snapshots");
        try (Db conn = Db.open(Paths.join(dataDir, "tattletale.db"), false)) {
            conn.transaction(List.of(Db.bind("UPDATE startup_versions SET copy_path = ? || substr(copy_path, ?) "
                    + "WHERE copy_path LIKE ? || '%'", newSnap, (long) (Py.len(oldSnap) + 1), oldSnap)));
        }
        return moved;
    }

    // ---- main ----
    public static void main(String[] argv) {
        int code = 0;
        try {
            code = run(argv);
        } catch (Exit e) {
            if (e.getMessage() != null) Watch.ERR.println(e.getMessage());
            code = e.code;
        }
        Watch.OUT.flush();
        Watch.ERR.flush();
        System.exit(code);
    }

    static int run(String[] argv) {
        Args a = parseArgs(argv);
        Resolved r = resolveSettings(a);
        Map<String, Object> eff = r.eff();
        if (a.showSettings) {
            Watch.OUT.println("config file: " + r.cfgPath()
                    + (Files.exists(Path.of(Py.expanduser(r.cfgPath()))) ? "" : " (not present)"));
            for (Setting s : SETTINGS)
                Watch.OUT.println("  " + Py.ljust(s.name(), 17) + " = " + Py.ljust(Py.repr(eff.get(s.name())), 60) + " ("
                        + r.src().get(s.name()) + ")");
            return 0;
        }
        String dbPath = (String) eff.get("db");
        try {
            if (a.report) {
                report(dbPath);
                return 0;
            }
            if (a.query != null) {
                runQuery(dbPath, a.query);
                return 0;
            }
            if (r.src().get("db").equals("default")) {
                List<String> moved = migrateV001(Py.dirname(dbPath));
                if (moved != null && !moved.isEmpty())
                    Watch.ERR.println("tattletale: moved the v0.0.1 data into " + Py.dirname(dbPath) + ": " + String.join(", ", moved));
            }
        } catch (DbException e) {
            throw new Exit("tattletale: " + e.getMessage());
        } catch (IOException e) {
            throw new Exit("tattletale: " + Py.oserror(e, null));
        }
        double pi = num(eff.get("process_interval"));
        long keep = (Long) eff.get("keep_logs");
        @SuppressWarnings("unchecked")
        List<String> extra = (List<String>) eff.get("extra_startup");
        Watch w = new Watch((String) eff.get("log"), dbPath, num(eff.get("listen_interval")), num(eff.get("startup_interval")),
                extra, (Boolean) eff.get("notify"), (long) (num(eff.get("rotate_mb")) * 1024 * 1024), Math.max(0, keep),
                pi > 0.5 ? pi : 0.5, (String) eff.get("map"), (Long) eff.get("retention_days"),
                (Long) eff.get("sightings_retention_days"), DASHBOARD);
        Signals.install(w::requestStop);
        try {
            w.run();
        } catch (IOException e) {
            throw new Exit("tattletale: " + Py.oserror(e, null));
        } catch (DbException e) {
            throw new Exit("tattletale: " + e.getMessage());
        }
        return 0;
    }

    static double num(Object o) {
        return ((Number) o).doubleValue();
    }
}
