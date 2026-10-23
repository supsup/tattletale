package dev.tattletale;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small JSON reader and writer. The reader keeps object key order (a later duplicate key
 * wins, as in Python's json.loads), reads integers as Long and other numbers as Double, and
 * accepts NaN/Infinity like Python. The writer matches json.dump(obj, separators=(",", ":"))
 * with ensure_ascii on: every non-ASCII UTF-16 unit is written as a lowercase \\uXXXX escape.
 */
final class Json {
    private Json() {}

    static final class ParseError extends Exception {
        private static final long serialVersionUID = 1L;

        ParseError(String msg) {
            super(msg);
        }
    }

    // ---- reader ----
    static Object parse(String s) throws ParseError {
        Reader r = new Reader(s);
        r.ws();
        Object v = r.value();
        r.ws();
        if (r.i < s.length()) throw r.err("Extra data");
        return v;
    }

    private static final class Reader {
        final String s;
        int i;

        Reader(String s) {
            this.s = s;
        }

        ParseError err(String what) {
            int line = 1, col = 1;
            for (int k = 0; k < i && k < s.length(); k++) {
                if (s.charAt(k) == '\n') {
                    line++;
                    col = 1;
                } else col++;
            }
            return new ParseError(what + ": line " + line + " column " + col + " (char " + i + ")");
        }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
                else break;
            }
        }

        Object value() throws ParseError {
            if (i >= s.length()) throw err("Expecting value");
            char c = s.charAt(i);
            switch (c) {
                case '{':
                    return object();
                case '[':
                    return array();
                case '"':
                    return string();
                default:
                    if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
                    if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
                    if (s.startsWith("null", i)) { i += 4; return null; }
                    if (s.startsWith("NaN", i)) { i += 3; return Double.NaN; }
                    if (s.startsWith("Infinity", i)) { i += 8; return Double.POSITIVE_INFINITY; }
                    if (s.startsWith("-Infinity", i)) { i += 9; return Double.NEGATIVE_INFINITY; }
                    if (c == '-' || (c >= '0' && c <= '9')) return number();
                    throw err("Expecting value");
            }
        }

        Map<String, Object> object() throws ParseError {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"')
                    throw err("Expecting property name enclosed in double quotes");
                String k = string();
                ws();
                if (i >= s.length() || s.charAt(i) != ':') throw err("Expecting ':' delimiter");
                i++;
                ws();
                Object v = value();
                m.remove(k);
                m.put(k, v);
                ws();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
                throw err("Expecting ',' delimiter");
            }
        }

        List<Object> array() throws ParseError {
            List<Object> a = new ArrayList<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
            while (true) {
                ws();
                a.add(value());
                ws();
                if (i < s.length() && s.charAt(i) == ',') { i++; continue; }
                if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
                throw err("Expecting ',' delimiter");
            }
        }

        String string() throws ParseError {
            int start = i;
            i++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    i = start;
                    throw err("Unterminated string starting at");
                }
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (i >= s.length()) { i = start; throw err("Unterminated string starting at"); }
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (i + 4 > s.length()) throw err("Invalid \\uXXXX escape");
                            try {
                                sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            } catch (NumberFormatException x) {
                                throw err("Invalid \\uXXXX escape");
                            }
                            i += 4;
                        }
                        default -> {
                            i -= 2;
                            throw err("Invalid \\escape");
                        }
                    }
                } else if (c < 0x20) {
                    i--;
                    throw err("Invalid control character at");
                } else sb.append(c);
            }
        }

        Object number() throws ParseError {
            int start = i;
            if (s.charAt(i) == '-') i++;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            boolean frac = false;
            if (i < s.length() && s.charAt(i) == '.') {
                frac = true;
                i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                frac = true;
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }
            String t = s.substring(start, i);
            if (t.equals("-")) {
                i = start;
                throw err("Expecting value");
            }
            try {
                if (frac) return Double.parseDouble(t);
                BigInteger b = new BigInteger(t);
                return b.bitLength() < 64 ? (Object) b.longValue() : (Object) b.doubleValue();
            } catch (NumberFormatException x) {
                i = start;
                throw err("Expecting value");
            }
        }
    }

    // ---- writer ----
    static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    static void write(StringBuilder sb, Object v) {
        if (v == null) sb.append("null");
        else if (v instanceof String s) str(sb, s);
        else if (v instanceof Boolean b) sb.append(b ? "true" : "false");
        else if (v instanceof Double d) {
            if (d.isNaN()) sb.append("NaN");
            else if (d.isInfinite()) sb.append(d > 0 ? "Infinity" : "-Infinity");
            else sb.append(Py.floatRepr(d));
        } else if (v instanceof Number n) sb.append(n.toString());
        else if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                str(sb, String.valueOf(e.getKey()));
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List<?> l) {
            sb.append('[');
            for (int k = 0; k < l.size(); k++) {
                if (k > 0) sb.append(',');
                write(sb, l.get(k));
            }
            sb.append(']');
        } else str(sb, String.valueOf(v));
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    static void str(StringBuilder sb, String s) {
        sb.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        sb.append("\\u").append(HEX[(c >> 12) & 15]).append(HEX[(c >> 8) & 15])
                                .append(HEX[(c >> 4) & 15]).append(HEX[c & 15]);
                    } else sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
