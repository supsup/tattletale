package dev.tattletale;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Small helpers that reproduce the Python behaviour the reference depends on: str.split() and
 * strip() whitespace, code-point slicing, str.splitlines(), repr() and str() of values, float()
 * and int() parsing, os.path.basename/expanduser, truthiness, and OSError text.
 */
final class Py {
    private Py() {}

    /** Python's str.isspace() for one code point. */
    static boolean isSpace(int c) {
        return c == ' ' || (c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x1f) || c == 0x85 || c == 0xa0
                || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f
                || c == 0x205f || c == 0x3000;
    }

    /** str.split(None, maxsplit); maxsplit < 0 means no limit. */
    static List<String> split(String s, int maxsplit) {
        List<String> out = new ArrayList<>();
        int i = 0, n = s.length();
        while (true) {
            while (i < n && isSpace(s.codePointAt(i))) i += Character.charCount(s.codePointAt(i));
            if (i >= n) break;
            if (maxsplit >= 0 && out.size() == maxsplit) {
                out.add(s.substring(i));   // the remainder, trailing whitespace kept
                break;
            }
            int j = i;
            while (j < n && !isSpace(s.codePointAt(j))) j += Character.charCount(s.codePointAt(j));
            out.add(s.substring(i, j));
            i = j;
        }
        return out;
    }

    static List<String> split(String s) {
        return split(s, -1);
    }

    static String strip(String s) {
        int a = 0, b = s.length();
        while (a < b && isSpace(s.codePointAt(a))) a += Character.charCount(s.codePointAt(a));
        while (b > a && isSpace(s.codePointBefore(b))) b -= Character.charCount(s.codePointBefore(b));
        return s.substring(a, b);
    }

    /** s[:n] counted in code points, as Python slices a str. */
    static String cut(String s, int n) {
        if (s == null) return null;
        if (s.length() <= n) return s;
        int cps = s.codePointCount(0, s.length());
        if (cps <= n) return s;
        return s.substring(0, s.offsetByCodePoints(0, n));
    }

    static int len(String s) {
        return s.codePointCount(0, s.length());
    }

    /** str.splitlines(): every Python line boundary, \r\n counted once, no trailing empty line. */
    static List<String> splitlines(String s) {
        List<String> out = new ArrayList<>();
        int start = 0, n = s.length(), i = 0;
        while (i < n) {
            char c = s.charAt(i);
            boolean brk = c == '\n' || c == '\r' || c == 0x0b || c == 0x0c || c == 0x1c || c == 0x1d || c == 0x1e
                    || c == 0x85 || c == 0x2028 || c == 0x2029;
            if (brk) {
                out.add(s.substring(start, i));
                if (c == '\r' && i + 1 < n && s.charAt(i + 1) == '\n') i++;
                start = i + 1;
            }
            i++;
        }
        if (start < n) out.add(s.substring(start));
        return out;
    }

    /** "<a> <b>" joined from split(): " ".join(s.split()). */
    static String squash(String s) {
        return String.join(" ", split(s));
    }

    static String basename(String p) {
        if (p == null) return "";
        int i = p.lastIndexOf('/');
        return i < 0 ? p : p.substring(i + 1);
    }

    static String dirname(String p) {
        int i = p.lastIndexOf('/') + 1;
        String head = p.substring(0, i);
        if (!head.isEmpty() && !head.chars().allMatch(ch -> ch == '/')) {
            int e = head.length();
            while (e > 0 && head.charAt(e - 1) == '/') e--;
            head = head.substring(0, e);
        }
        return head;
    }

    static String home() {
        String h = System.getenv("HOME");
        return h != null ? h : System.getProperty("user.home");
    }

    /** posixpath.expanduser for "~" and "~/..."; "~name" is expanded only for this user. */
    static String expanduser(String path) {
        if (path == null || !path.startsWith("~")) return path;
        int i = path.indexOf('/', 1);
        if (i < 0) i = path.length();
        String userhome;
        if (i == 1) {
            userhome = home();
        } else {
            String name = path.substring(1, i);
            if (!name.equals(System.getProperty("user.name"))) return path;
            userhome = System.getProperty("user.home");
        }
        while (userhome.endsWith("/")) userhome = userhome.substring(0, userhome.length() - 1);
        String r = userhome + path.substring(i);
        return r.isEmpty() ? "/" : r;
    }

    static boolean isDigits(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) if (!Character.isDigit(s.charAt(i))) return false;
        return true;
    }

    static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean b) return b;
        if (v instanceof Long l) return l != 0;
        if (v instanceof Double d) return d != 0.0;
        if (v instanceof Number n) return n.doubleValue() != 0.0;
        if (v instanceof String s) return !s.isEmpty();
        if (v instanceof List<?> l) return !l.isEmpty();
        if (v instanceof Map<?, ?> m) return !m.isEmpty();
        return true;
    }

    // ---- float() and int() ----
    private static final String NUM = "\\d(?:_?\\d)*";
    private static final Pattern FLOAT = Pattern.compile(
            "[+-]?(?:(?:(?:" + NUM + ")\\.(?:" + NUM + ")?|\\.(?:" + NUM + ")|(?:" + NUM + "))(?:[eE][+-]?(?:" + NUM
                    + "))?|(?i:inf|infinity|nan))");
    private static final Pattern INT = Pattern.compile("[+-]?" + NUM);

    static double parseFloat(String raw) {
        String s = strip(raw);
        if (!FLOAT.matcher(s).matches()) throw new NumberFormatException(raw);
        String t = s.replace("_", "");
        String low = t.toLowerCase(java.util.Locale.ROOT);
        boolean neg = low.startsWith("-");
        String body = low.replaceFirst("^[+-]", "");
        if (body.equals("inf") || body.equals("infinity")) return neg ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
        if (body.equals("nan")) return Double.NaN;
        return Double.parseDouble(t);
    }

    static long parseInt(String raw) {
        String s = strip(raw);
        if (!INT.matcher(s).matches()) throw new NumberFormatException(raw);
        return Long.parseLong(s.replace("_", "").replaceFirst("^\\+", ""));
    }

    // ---- repr() and str() ----
    static String floatRepr(double d) {
        if (Double.isNaN(d)) return "nan";
        if (Double.isInfinite(d)) return d > 0 ? "inf" : "-inf";
        if (d == 0) return (1 / d < 0) ? "-0.0" : "0.0";
        // Java's Double.toString gives the shortest round-trip digits (JDK 19+), as Python's repr.
        BigDecimal bd = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
        String digits = bd.unscaledValue().toString();
        int decpt = digits.length() - bd.scale();   // position of the decimal point
        String sign = d < 0 ? "-" : "";
        if (decpt > -4 && decpt <= 16) {
            String r;
            if (decpt <= 0) r = "0." + "0".repeat(-decpt) + digits;
            else if (decpt >= digits.length()) r = digits + "0".repeat(decpt - digits.length()) + ".0";
            else r = digits.substring(0, decpt) + "." + digits.substring(decpt);
            return sign + r;
        }
        String mant = digits.length() == 1 ? digits : digits.charAt(0) + "." + digits.substring(1);
        int exp = decpt - 1;
        return sign + mant + "e" + (exp < 0 ? "-" : "+") + (Math.abs(exp) < 10 ? "0" : "") + Math.abs(exp);
    }

    static String repr(Object v) {
        if (v == null) return "None";
        if (v instanceof Boolean b) return b ? "True" : "False";
        if (v instanceof Double d) return floatRepr(d);
        if (v instanceof Number n) return n.toString();
        if (v instanceof String s) return strRepr(s);
        if (v instanceof List<?> l) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(repr(l.get(i)));
            }
            return sb.append(']').toString();
        }
        return String.valueOf(v);
    }

    static String str(Object v) {
        if (v instanceof String s) return s;
        return repr(v);
    }

    static String strRepr(String s) {
        char q = (s.indexOf('\'') >= 0 && s.indexOf('"') < 0) ? '"' : '\'';
        StringBuilder sb = new StringBuilder().append(q);
        for (int i = 0; i < s.length(); ) {
            int c = s.codePointAt(i);
            i += Character.charCount(c);
            if (c == q || c == '\\') sb.append('\\').appendCodePoint(c);
            else if (c == '\t') sb.append("\\t");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c < 0x20 || c == 0x7f) sb.append(String.format("\\x%02x", c));
            else if (c < 0x7f || printable(c)) sb.appendCodePoint(c);
            else if (c <= 0xff) sb.append(String.format("\\x%02x", c));
            else if (c <= 0xffff) sb.append(String.format("\\u%04x", c));
            else sb.append(String.format("\\U%08x", c));
        }
        return sb.append(q).toString();
    }

    private static boolean printable(int c) {
        int t = Character.getType(c);
        return !(t == Character.CONTROL || t == Character.FORMAT || t == Character.SURROGATE
                || t == Character.PRIVATE_USE || t == Character.UNASSIGNED || t == Character.LINE_SEPARATOR
                || t == Character.PARAGRAPH_SEPARATOR || (t == Character.SPACE_SEPARATOR && c != ' '));
    }

    /** Python's left-aligned format: f"{s:<w}". */
    static String ljust(String s, int w) {
        int n = len(s);
        return n >= w ? s : s + " ".repeat(w - n);
    }

    // ---- OSError text ----
    private static final Pattern PAREN = Pattern.compile("\\(([^()]*)\\)\\s*$");

    /** e.strerror, as Python's OSError would carry it. */
    static String strerror(IOException e) {
        if (e instanceof NoSuchFileException) return "No such file or directory";
        if (e instanceof AccessDeniedException) return "Permission denied";
        if (e instanceof FileAlreadyExistsException) return "File exists";
        if (e instanceof DirectoryNotEmptyException) return "Directory not empty";
        if (e instanceof NotDirectoryException) return "Not a directory";
        if (e instanceof FileSystemException fe && fe.getReason() != null) return fe.getReason();
        String m = e.getMessage();
        if (m != null) {
            Matcher mm = PAREN.matcher(m);
            if (e instanceof FileNotFoundException && mm.find()) return mm.group(1);
            int k = m.indexOf("error=");
            if (k >= 0 && m.indexOf(", ", k) > 0) return m.substring(m.indexOf(", ", k) + 2);
        }
        return m == null ? e.getClass().getSimpleName() : m;
    }

    static int errno(String strerror) {
        return switch (strerror) {
            case "No such file or directory" -> 2;
            case "Permission denied" -> 13;
            case "File exists" -> 17;
            case "Not a directory" -> 20;
            case "Is a directory" -> 21;
            case "Directory not empty" -> 66;
            default -> 0;
        };
    }

    /** str(OSError): "[Errno 2] No such file or directory: 'path'". */
    static String oserror(IOException e, String path) {
        String se = strerror(e);
        int no = errno(se);
        String head = no > 0 ? "[Errno " + no + "] " + se : se;
        return path == null ? head : head + ": " + strRepr(path);
    }
}
