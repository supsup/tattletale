package dev.tattletale;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * One SQLite connection, held as one long-lived /usr/bin/sqlite3 process talking JSON over its
 * stdin and stdout (stderr merged in). After each batch of statements we send `.print` with a
 * unique marker and read up to that line: JSON result lines start with '[' or '{', anything
 * else is an error message from the shell. A long-lived process keeps one connection for the
 * whole run, as the Python version keeps one sqlite3.Connection, so PRAGMAs, the busy timeout
 * and WAL mode are set once.
 *
 * Values are bound by SQL-literal escaping ({@link #lit}). Every caller holds the watcher's
 * lock, as Python does around its connection; the methods are also synchronized.
 */
final class Db implements AutoCloseable {
    static final String SQLITE = "/usr/bin/sqlite3";

    /** Unknown connection disposition must leave the watcher, never a catch-and-loop no-op. */
    static final class Fatal extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Fatal(DbException cause) { super("tattletale: database connection unusable", cause); }
    }

    /** sqlite3.Error. */
    static final class DbException extends Exception {
        private static final long serialVersionUID = 1L;
        final List<String> shellErrors;
        final boolean protocolComplete;

        DbException(String msg) {
            super(msg);
            shellErrors=List.of(); protocolComplete=false;
        }
        DbException(List<String> errors) {
            super(clean(errors));shellErrors=List.copyOf(errors);protocolComplete=true;
        }
    }

    private final Process proc;
    private final BufferedWriter in;
    private final BufferedReader out;
    private long seq;
    private boolean closed;
    interface Rollback {void run()throws DbException;}
    Rollback rollback=()->exec("ROLLBACK;");

    private Db(Process proc) {
        this.proc = proc;
        this.in = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream(), StandardCharsets.UTF_8));
        this.out = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8));
    }

    /**
     * -safe: no ATTACH, no load_extension, no file-touching dot-commands. -batch: no prompts.
     * The path is made absolute so it can never be read as an option or a file: URI.
     */
    static Db open(String path, boolean readOnly) throws DbException {
        List<String> cmd = new ArrayList<>(List.of(SQLITE, "-safe", "-batch", "-json"));
        if (readOnly) cmd.add("-readonly");
        cmd.add(new java.io.File(path).getAbsolutePath());
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
            Db db = new Db(pb.start());
            db.exec(".timeout 30000\n");
            return db;
        } catch (IOException e) {
            throw new DbException("cannot start " + SQLITE + ": " + e.getMessage());
        }
    }

    /** Run statements (each ending in ';'); return the result lines. Errors throw. */
    synchronized List<String> exec(String sql) throws DbException {
        if (closed) throw new Fatal(new DbException("Cannot operate on a closed database."));
        String mark = "__tattletale_" + (++seq) + "__";
        List<String> rows = new ArrayList<>();
        List<String> errs = new ArrayList<>();
        try {
            in.write(sql);
            if (!sql.endsWith("\n")) in.write('\n');
            in.write(".print " + mark + "\n");
            in.flush();
            String line;
            while ((line = out.readLine()) != null) {
                if (line.equals(mark)) break;
                if (line.startsWith("[") || line.startsWith("{")) rows.add(line);
                else errs.add(line);
            }
            if (line == null) {
                DbException failure = new DbException("sqlite3 exited" + (errs.isEmpty() ? "" : ": " + clean(errs)));
                close(); throw new Fatal(failure);
            }
        } catch (IOException e) {
            DbException failure = new DbException("sqlite3 pipe failed"); failure.initCause(e);
            close(); throw new Fatal(failure);
        }
        if (!errs.isEmpty()) throw new DbException(errs);
        return rows;
    }

    private static final Pattern PREFIX = Pattern.compile(
            "^(?:(?:Parse|Runtime) error|Error)(?: near line \\d+| in [^:]*)?:\\s*");
    private static final Pattern CODE = Pattern.compile("\\s*\\(\\d+\\)$");

    /** "Parse error near line 3: no such table: x (1)" -> "no such table: x", as str(sqlite3.Error). */
    static String clean(List<String> errs) {
        String first = errs.get(0);
        first = PREFIX.matcher(first).replaceFirst("");
        return CODE.matcher(first).replaceFirst("");
    }

    /** One SELECT; rows as ordered maps keyed by column name. */
    synchronized List<Map<String, Object>> query(String sql) throws DbException {
        List<String> lines = exec(sql);
        List<Map<String, Object>> out = new ArrayList<>();
        if (lines.isEmpty()) return out;
        try {
            for (String chunk : joinArrays(lines)) {
                for (Object o : (List<?>) Json.parse(chunk)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) o;
                    out.add(m);
                }
            }
        } catch (Json.ParseError | ClassCastException e) {
            throw new DbException("unreadable sqlite3 output: " + e.getMessage());
        }
        return out;
    }

    /** Group result lines into whole JSON arrays (one per statement that returned rows). */
    private static List<String> joinArrays(List<String> lines) {
        List<String> arrays = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String l : lines) {
            if (cur.length() > 0) cur.append('\n');
            cur.append(l);
            if (l.endsWith("]")) {
                arrays.add(cur.toString());
                cur.setLength(0);
            }
        }
        if (cur.length() > 0) arrays.add(cur.toString());
        return arrays;
    }

    Object scalar(String sql) throws DbException {
        List<Map<String, Object>> r = query(sql);
        if (r.isEmpty()) return null;
        return r.get(0).values().iterator().next();
    }

    /**
     * BEGIN; statements; then COMMIT if all succeeded, else ROLLBACK and throw, as Python's
     * transaction() context manager does.
     */
    synchronized void transaction(List<String> statements) throws DbException {
        transactionQuery(statements);
    }

    /** Each statement finishes at its shell marker before the next is sent. */
    synchronized List<Map<String,Object>> transactionQuery(List<String> statements) throws DbException {
        // One round trip per statement, so the FIRST error stops the batch. Sending the whole
        // batch at once let the shell keep executing after an error; if SQLite had rolled the
        // transaction back itself (SQLITE_FULL, IOERR, BUSY) the rest then ran in autocommit
        // and was kept. Stopping here means no later statement runs outside the transaction.
        try {exec("BEGIN;");}
        catch(DbException e) {
            if(exactShellResponse(e,"cannot start a transaction within a transaction"))throw e;
            close();throw new Fatal(e);
        }
        try {
            List<Map<String,Object>> rows=new ArrayList<>();
            for (String s : statements) rows.addAll(query(s));
            exec("COMMIT;");
            return rows;
        } catch (DbException e) {
            try {
                rollback.run();
            } catch (DbException | Fatal rollbackFailure) {
                e.addSuppressed(rollbackFailure);
                if(rollbackFailure instanceof DbException response && noActiveTransaction(response)) {
                    // Exact, single completed ROLLBACK response; verify a NEW owned empty
                    // transaction on this same handle, without a fictitious SQL state API.
                    proveRecoveredIdle(e);
                } else {close();throw new Fatal(e);}
            }
            throw e;
        }
    }

    static boolean noActiveTransaction(DbException e) {
        return exactShellResponse(e,"cannot rollback - no transaction is active");
    }

    /** An optional projection may fail only while this same connection is usable and idle. */
    synchronized void proveRecoveredIdle(DbException original) {
        try {exec("BEGIN;");exec("ROLLBACK;");}
        catch(DbException | Fatal verificationFailure) {
            original.addSuppressed(verificationFailure);close();throw new Fatal(original);
        }
    }
    static boolean exactShellResponse(DbException e,String message) {
        if(!e.protocolComplete || e.shellErrors.size()!=1)return false;
        String body=PREFIX.matcher(e.shellErrors.getFirst()).replaceFirst("");
        // Installed SQLite shells differ: some append SQLITE_ERROR (1), others do not.
        // Match only the complete body, never a substring or an arbitrary result code.
        return body.equals(message) || body.equals(message+" (1)");
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        try {
            in.write(".quit\n");
            in.flush();
            in.close();
        } catch (IOException ignored) {
            // already gone
        }
        try {
            if (!proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) proc.destroy();
        } catch (InterruptedException e) {
            proc.destroy();
            Thread.currentThread().interrupt();
        }
    }

    // ---- binding by SQL literal ----
    /** A value as an SQL literal: NULL, an integer unquoted, text single-quoted with '' doubled. */
    static String lit(Object v) {
        if (v == null) return "NULL";
        if (v instanceof Boolean b) return b ? "1" : "0";
        if (v instanceof Long || v instanceof Integer || v instanceof Short || v instanceof Byte) return v.toString();
        if (v instanceof Double d) {
            if (d.isNaN()) return "NULL";
            if (d.isInfinite()) return d > 0 ? "9e999" : "-9e999";
            return Py.floatRepr(d);
        }
        if (v instanceof Number n) return n.toString();
        return text(v instanceof String s ? s : Json.write(v));
    }

    /**
     * Text literal. A CR or NUL cannot travel inside a quoted literal through the shell (it
     * folds CR LF and stops at NUL), so those characters are spliced in with char().
     */
    static String text(String s) {
        StringBuilder sb = new StringBuilder("'");
        boolean open = true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == 0) {
                if (open) sb.append("'");
                sb.append("||char(").append((int) c).append(")||'");
                open = true;
                continue;
            }
            if (c == '\'') sb.append("''");
            else sb.append(c);
        }
        sb.append("'");
        return sb.toString();
    }

    /** "INSERT ... VALUES (?,?)" with each ? replaced by a literal, in order. */
    static String bind(String sql, Object... args) {
        StringBuilder sb = new StringBuilder();
        int k = 0;
        for (int i = 0; i < sql.length(); i++) {
            char c = sql.charAt(i);
            if (c == '?') sb.append(lit(args[k++]));
            else sb.append(c);
        }
        if (k != args.length) throw new IllegalArgumentException("bind: " + k + " placeholders, " + args.length + " values");
        String r = sb.toString();
        return r.endsWith(";") ? r : r + ";";
    }

    static Long asLong(Object o) {
        if (o == null) return null;
        if (o instanceof Long l) return l;
        if (o instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(o.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static String asStr(Object o) {
        return o == null ? null : (o instanceof String s ? s : Py.str(o));
    }
}
