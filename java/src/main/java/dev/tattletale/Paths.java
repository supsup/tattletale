package dev.tattletale;

import java.util.ArrayList;
import java.util.List;

/** posixpath.join, normpath and abspath, on plain strings (no symlink resolution). */
final class Paths {
    private Paths() {}

    static String join(String a, String... rest) {
        String path = a;
        for (String b : rest) {
            if (b.startsWith("/")) path = b;
            else if (path.isEmpty() || path.endsWith("/")) path = path + b;
            else path = path + "/" + b;
        }
        return path;
    }

    static String normpath(String path) {
        if (path.isEmpty()) return ".";
        int initial = path.startsWith("/") ? (path.startsWith("//") && !path.startsWith("///") ? 2 : 1) : 0;
        List<String> comps = new ArrayList<>();
        for (String c : path.split("/", -1)) {
            if (c.isEmpty() || c.equals(".")) continue;
            if (!c.equals("..") || (initial == 0 && comps.isEmpty()) || (!comps.isEmpty() && comps.get(comps.size() - 1).equals("..")))
                comps.add(c);
            else if (!comps.isEmpty()) comps.remove(comps.size() - 1);
        }
        String s = String.join("/", comps);
        if (initial > 0) s = "/".repeat(initial) + s;
        return s.isEmpty() ? "." : s;
    }

    static String abspath(String p) {
        if (!p.startsWith("/")) p = join(System.getProperty("user.dir"), p);
        return normpath(p);
    }
}
