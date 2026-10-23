package dev.tattletale;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A line-for-line port of Python's difflib.SequenceMatcher (no junk function, autojunk on) and
 * difflib.unified_diff(a, b, fromfile, tofile, lineterm="", n), so a STARTUP~ diff is the same
 * text the Python version logs. /usr/bin/diff -u uses another algorithm and can group hunks
 * differently, so it is not used.
 */
final class Difflib {
    private Difflib() {}

    private record Match(int a, int b, int size) {}

    private record Op(String tag, int i1, int i2, int j1, int j2) {}

    private static final class Matcher {
        final List<String> a, b;
        final Map<String, List<Integer>> b2j = new LinkedHashMap<>();

        Matcher(List<String> a, List<String> b) {
            this.a = a;
            this.b = b;
            for (int i = 0; i < b.size(); i++) b2j.computeIfAbsent(b.get(i), k -> new ArrayList<>()).add(i);
            int n = b.size();
            if (n >= 200) {
                int ntest = n / 100 + 1;
                Set<String> popular = new HashSet<>();
                for (Map.Entry<String, List<Integer>> e : b2j.entrySet())
                    if (e.getValue().size() > ntest) popular.add(e.getKey());
                for (String p : popular) b2j.remove(p);
            }
        }

        Match longest(int alo, int ahi, int blo, int bhi) {
            int besti = alo, bestj = blo, bestsize = 0;
            Map<Integer, Integer> j2len = new HashMap<>();
            for (int i = alo; i < ahi; i++) {
                Map<Integer, Integer> newj2len = new HashMap<>();
                List<Integer> js = b2j.get(a.get(i));
                if (js != null) {
                    for (int j : js) {
                        if (j < blo) continue;
                        if (j >= bhi) break;
                        int k = j2len.getOrDefault(j - 1, 0) + 1;
                        newj2len.put(j, k);
                        if (k > bestsize) {
                            besti = i - k + 1;
                            bestj = j - k + 1;
                            bestsize = k;
                        }
                    }
                }
                j2len = newj2len;
            }
            // No junk set, so only the non-junk extension applies (popular lines extend here).
            while (besti > alo && bestj > blo && a.get(besti - 1).equals(b.get(bestj - 1))) {
                besti--;
                bestj--;
                bestsize++;
            }
            while (besti + bestsize < ahi && bestj + bestsize < bhi
                    && a.get(besti + bestsize).equals(b.get(bestj + bestsize))) bestsize++;
            return new Match(besti, bestj, bestsize);
        }

        List<Match> matchingBlocks() {
            int la = a.size(), lb = b.size();
            Deque<int[]> queue = new ArrayDeque<>();
            queue.push(new int[] {0, la, 0, lb});
            List<Match> blocks = new ArrayList<>();
            while (!queue.isEmpty()) {
                int[] q = queue.pop();   // list.pop(): the last appended
                int alo = q[0], ahi = q[1], blo = q[2], bhi = q[3];
                Match x = longest(alo, ahi, blo, bhi);
                int i = x.a(), j = x.b(), k = x.size();
                if (k > 0) {
                    blocks.add(x);
                    if (alo < i && blo < j) queue.push(new int[] {alo, i, blo, j});
                    if (i + k < ahi && j + k < bhi) queue.push(new int[] {i + k, ahi, j + k, bhi});
                }
            }
            blocks.sort((p, r) -> p.a() != r.a() ? Integer.compare(p.a(), r.a())
                    : p.b() != r.b() ? Integer.compare(p.b(), r.b()) : Integer.compare(p.size(), r.size()));
            int i1 = 0, j1 = 0, k1 = 0;
            List<Match> out = new ArrayList<>();
            for (Match m : blocks) {
                if (i1 + k1 == m.a() && j1 + k1 == m.b()) k1 += m.size();
                else {
                    if (k1 > 0) out.add(new Match(i1, j1, k1));
                    i1 = m.a();
                    j1 = m.b();
                    k1 = m.size();
                }
            }
            if (k1 > 0) out.add(new Match(i1, j1, k1));
            out.add(new Match(la, lb, 0));
            return out;
        }

        List<Op> opcodes() {
            int i = 0, j = 0;
            List<Op> ans = new ArrayList<>();
            for (Match m : matchingBlocks()) {
                int ai = m.a(), bj = m.b(), size = m.size();
                String tag = "";
                if (i < ai && j < bj) tag = "replace";
                else if (i < ai) tag = "delete";
                else if (j < bj) tag = "insert";
                if (!tag.isEmpty()) ans.add(new Op(tag, i, ai, j, bj));
                i = ai + size;
                j = bj + size;
                if (size > 0) ans.add(new Op("equal", ai, i, bj, j));
            }
            return ans;
        }

        List<List<Op>> grouped(int n) {
            List<Op> codes = new ArrayList<>(opcodes());
            if (codes.isEmpty()) codes.add(new Op("equal", 0, 1, 0, 1));
            Op f = codes.get(0);
            if (f.tag().equals("equal"))
                codes.set(0, new Op("equal", Math.max(f.i1(), f.i2() - n), f.i2(), Math.max(f.j1(), f.j2() - n), f.j2()));
            Op l = codes.get(codes.size() - 1);
            if (l.tag().equals("equal"))
                codes.set(codes.size() - 1,
                        new Op("equal", l.i1(), Math.min(l.i2(), l.i1() + n), l.j1(), Math.min(l.j2(), l.j1() + n)));
            int nn = n + n;
            List<List<Op>> groups = new ArrayList<>();
            List<Op> group = new ArrayList<>();
            for (Op c : codes) {
                int i1 = c.i1(), i2 = c.i2(), j1 = c.j1(), j2 = c.j2();
                if (c.tag().equals("equal") && i2 - i1 > nn) {
                    group.add(new Op("equal", i1, Math.min(i2, i1 + n), j1, Math.min(j2, j1 + n)));
                    groups.add(group);
                    group = new ArrayList<>();
                    i1 = Math.max(i1, i2 - n);
                    j1 = Math.max(j1, j2 - n);
                }
                group.add(new Op(c.tag(), i1, i2, j1, j2));
            }
            if (!group.isEmpty() && !(group.size() == 1 && group.get(0).tag().equals("equal"))) groups.add(group);
            return groups;
        }
    }

    private static String range(int start, int stop) {
        int beginning = start + 1;
        int length = stop - start;
        if (length == 1) return Integer.toString(beginning);
        if (length == 0) beginning -= 1;
        return beginning + "," + length;
    }

    static List<String> unifiedDiff(List<String> a, List<String> b, String fromfile, String tofile, int n) {
        List<String> out = new ArrayList<>();
        boolean started = false;
        for (List<Op> group : new Matcher(a, b).grouped(n)) {
            if (!started) {
                started = true;
                out.add("--- " + fromfile);
                out.add("+++ " + tofile);
            }
            Op first = group.get(0), last = group.get(group.size() - 1);
            out.add("@@ -" + range(first.i1(), last.i2()) + " +" + range(first.j1(), last.j2()) + " @@");
            for (Op c : group) {
                if (c.tag().equals("equal")) {
                    for (String line : a.subList(c.i1(), c.i2())) out.add(" " + line);
                    continue;
                }
                if (c.tag().equals("replace") || c.tag().equals("delete"))
                    for (String line : a.subList(c.i1(), c.i2())) out.add("-" + line);
                if (c.tag().equals("replace") || c.tag().equals("insert"))
                    for (String line : b.subList(c.j1(), c.j2())) out.add("+" + line);
            }
        }
        return out;
    }
}
