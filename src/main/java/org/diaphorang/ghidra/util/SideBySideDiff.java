/*
 * Diaphora, a binary diffing tool
 * Copyright (c) 2015-2026 Joxean Koret
 * Copyright (c) 2026 ClaudeMonkey (Java port, Claude-Rays/diaphora-ng-ghidra)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Port of parts of Python's difflib module:
 *   Copyright (c) 2001 Python Software Foundation; All Rights Reserved
 *   Licensed under the Python Software Foundation License Version 2.
 *   Changes: only SequenceMatcher, unified_diff and a side by side diff similar
 *   to _mdiff were ported, to Java.
 */
package org.diaphorang.ghidra.util;

import java.util.*;
import java.util.function.UnaryOperator;

/**
 * Side by side diff as shown by Diaphora's CHtmlDiff (difflib._mdiff): port of
 * side_by_side_diff() from diaphora-idafree (difflib.cpp).
 *
 * Similar lines (ratio >= 0.75, difflib.Differ._fancy_replace) are paired in
 * the same row and only their changed characters are marked: '^' changed,
 * '-' deleted, '+' added. Lines without a close match are marked as a whole:
 * deleted on the left, added on the right.
 */
public final class SideBySideDiff {

    /** A changed span of a line: [start, end) and its kind ('+', '-' or '^'). */
    public static final class Span {
        public final int start;
        public final int end;
        public final char kind;

        Span(int start, int end, char kind) {
            this.start = start;
            this.end = end;
            this.kind = kind;
        }
    }

    public static final class Row {
        /** 1-based line numbers, 0 when the side has no line in this row. */
        public int lno;
        public int rno;
        public String ltxt = "";
        public String rtxt = "";
        public boolean changed;
        /** Whole line deleted/added (_mdiff marks the left side with NUL '-' and the right side with NUL '+'). */
        public boolean fullChange;
        public final List<Span> lspans = new ArrayList<>();
        public final List<Span> rspans = new ArrayList<>();
    }

    private SideBySideDiff() {}

    // ------------------------------------------------------------------------
    // difflib.SequenceMatcher (isjunk=None) over lists
    // ------------------------------------------------------------------------

    private static final class Opcode {
        final char tag; // 'r'eplace, 'd'elete, 'i'nsert, 'e'qual
        final int i1, i2, j1, j2;

        Opcode(char tag, int i1, int i2, int j1, int j2) {
            this.tag = tag;
            this.i1 = i1;
            this.i2 = i2;
            this.j1 = j1;
            this.j2 = j2;
        }
    }

    private static final class Matcher<T> {
        private final List<T> a;
        private final List<T> b;
        private final Map<T, List<Integer>> b2j = new HashMap<>();
        private List<int[]> blocks;

        Matcher(List<T> a, List<T> b, boolean autojunk) {
            this.a = a;
            this.b = b;
            int n = b.size();
            for (int i = 0; i < n; i++) {
                b2j.computeIfAbsent(b.get(i), k -> new ArrayList<>()).add(i);
            }
            // purge popular elements that are not junk
            if (autojunk && n >= 200) {
                int ntest = n / 100 + 1;
                b2j.values().removeIf(v -> v.size() > ntest);
            }
        }

        private int[] findLongestMatch(int alo, int ahi, int blo, int bhi) {
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
            // popular elements were purged from b2j: extend the match with equal
            // elements on both sides
            while (besti > alo && bestj > blo && Objects.equals(a.get(besti - 1), b.get(bestj - 1))) {
                besti--;
                bestj--;
                bestsize++;
            }
            while (besti + bestsize < ahi && bestj + bestsize < bhi
                    && Objects.equals(a.get(besti + bestsize), b.get(bestj + bestsize))) {
                bestsize++;
            }
            return new int[]{besti, bestj, bestsize};
        }

        List<int[]> getMatchingBlocks() {
            if (blocks != null) return blocks;
            int la = a.size(), lb = b.size();
            Deque<int[]> queue = new ArrayDeque<>();
            queue.push(new int[]{0, la, 0, lb});
            List<int[]> mb = new ArrayList<>();
            while (!queue.isEmpty()) {
                int[] r = queue.pop();
                int[] x = findLongestMatch(r[0], r[1], r[2], r[3]);
                if (x[2] != 0) {
                    mb.add(x);
                    if (r[0] < x[0] && r[2] < x[1]) queue.push(new int[]{r[0], x[0], r[2], x[1]});
                    if (x[0] + x[2] < r[1] && x[1] + x[2] < r[3]) {
                        queue.push(new int[]{x[0] + x[2], r[1], x[1] + x[2], r[3]});
                    }
                }
            }
            mb.sort((x, y) -> x[0] != y[0] ? Integer.compare(x[0], y[0])
                            : x[1] != y[1] ? Integer.compare(x[1], y[1]) : Integer.compare(x[2], y[2]));
            blocks = new ArrayList<>();
            int i1 = 0, j1 = 0, k1 = 0;
            for (int[] m : mb) {
                if (i1 + k1 == m[0] && j1 + k1 == m[1]) {
                    k1 += m[2];
                } else {
                    if (k1 != 0) blocks.add(new int[]{i1, j1, k1});
                    i1 = m[0];
                    j1 = m[1];
                    k1 = m[2];
                }
            }
            if (k1 != 0) blocks.add(new int[]{i1, j1, k1});
            blocks.add(new int[]{la, lb, 0});
            return blocks;
        }

        List<Opcode> getOpcodes() {
            List<Opcode> answer = new ArrayList<>();
            int i = 0, j = 0;
            for (int[] m : getMatchingBlocks()) {
                char tag = 0;
                if (i < m[0] && j < m[1]) tag = 'r';
                else if (i < m[0]) tag = 'd';
                else if (j < m[1]) tag = 'i';
                if (tag != 0) answer.add(new Opcode(tag, i, m[0], j, m[1]));
                i = m[0] + m[2];
                j = m[1] + m[2];
                if (m[2] != 0) answer.add(new Opcode('e', m[0], i, m[1], j));
            }
            return answer;
        }

        double ratio() {
            int matches = 0;
            for (int[] m : getMatchingBlocks()) matches += m[2];
            int length = a.size() + b.size();
            return length != 0 ? 2.0 * matches / length : 1.0;
        }
    }

    private static List<Character> chars(String s) {
        List<Character> l = new ArrayList<>(s.length());
        for (int i = 0; i < s.length(); i++) l.add(s.charAt(i));
        return l;
    }

    // ------------------------------------------------------------------------
    // Side by side rows
    // ------------------------------------------------------------------------

    private static final class Builder {
        final List<String> a;
        final List<String> b;
        /** the comparison keys of the lines (the lines themselves without a key function) */
        final List<String> ka;
        final List<String> kb;
        final List<Row> rows = new ArrayList<>();

        Builder(List<String> a, List<String> b, List<String> ka, List<String> kb) {
            this.a = a;
            this.b = b;
            this.ka = ka;
            this.kb = kb;
        }

        void equalRow(int i, int j) {
            Row r = new Row();
            r.lno = i + 1;
            r.rno = j + 1;
            r.ltxt = a.get(i);
            r.rtxt = b.get(j);
            rows.add(r);
        }

        // lines without a close match: deletions on the left, additions on the right
        void plainReplace(int i1, int i2, int j1, int j2) {
            int n = Math.max(i2 - i1, j2 - j1);
            for (int k = 0; k < n; k++) {
                Row r = new Row();
                r.changed = true;
                r.fullChange = true;
                if (i1 + k < i2) {
                    r.lno = i1 + k + 1;
                    r.ltxt = a.get(i1 + k);
                    r.lspans.add(new Span(0, r.ltxt.length(), '-'));
                }
                if (j1 + k < j2) {
                    r.rno = j1 + k + 1;
                    r.rtxt = b.get(j1 + k);
                    r.rspans.add(new Span(0, r.rtxt.length(), '+'));
                }
                rows.add(r);
            }
        }

        void intralineRow(int i, int j) {
            Row r = new Row();
            r.lno = i + 1;
            r.rno = j + 1;
            r.ltxt = a.get(i);
            r.rtxt = b.get(j);
            r.changed = true;
            Matcher<Character> sm = new Matcher<>(chars(r.ltxt), chars(r.rtxt), false);
            for (Opcode op : sm.getOpcodes()) {
                if (op.tag == 'e') continue;
                if (op.i2 > op.i1) r.lspans.add(new Span(op.i1, op.i2, op.tag == 'r' ? '^' : '-'));
                if (op.j2 > op.j1) r.rspans.add(new Span(op.j1, op.j2, op.tag == 'r' ? '^' : '+'));
            }
            rows.add(r);
        }

        static double charQuickRatio(String x, String y) {
            Map<Character, Integer> cnt = new HashMap<>();
            for (int i = 0; i < y.length(); i++) cnt.merge(y.charAt(i), 1, Integer::sum);
            int matches = 0;
            for (int i = 0; i < x.length(); i++) {
                Integer c = cnt.get(x.charAt(i));
                if (c != null && c > 0) {
                    cnt.put(x.charAt(i), c - 1);
                    matches++;
                }
            }
            int length = x.length() + y.length();
            return length != 0 ? 2.0 * matches / length : 1.0;
        }

        void helper(int i1, int i2, int j1, int j2) {
            if (i1 < i2 && j1 < j2) fancyReplace(i1, i2, j1, j2);
            else if (i1 < i2) plainReplace(i1, i2, j2, j2);
            else if (j1 < j2) plainReplace(i2, i2, j1, j2);
        }

        // simplified difflib.Differ._fancy_replace
        void fancyReplace(int i1, int i2, int j1, int j2) {
            if ((long) (i2 - i1) * (j2 - j1) > 2500) {
                plainReplace(i1, i2, j1, j2);
                return;
            }
            final double cutoff = 0.75;
            double bestRatio = 0.74;
            int bestI = -1, bestJ = -1;
            int eqi = -1, eqj = -1;
            for (int j = j1; j < j2; j++) {
                for (int i = i1; i < i2; i++) {
                    String ai = a.get(i);
                    String bj = b.get(j);
                    if (ka.get(i).equals(kb.get(j))) {
                        if (eqi < 0) {
                            eqi = i;
                            eqj = j;
                        }
                        continue;
                    }
                    int la = ai.length(), lb = bj.length();
                    double rq = (la + lb) != 0 ? 2.0 * Math.min(la, lb) / (la + lb) : 1.0;
                    if (rq <= bestRatio || charQuickRatio(ai, bj) <= bestRatio) continue;
                    double r = new Matcher<>(chars(ai), chars(bj), false).ratio();
                    if (r > bestRatio) {
                        bestRatio = r;
                        bestI = i;
                        bestJ = j;
                    }
                }
            }
            boolean identical = false;
            if (bestRatio < cutoff) {
                if (eqi < 0) {
                    plainReplace(i1, i2, j1, j2);
                    return;
                }
                bestI = eqi;
                bestJ = eqj;
                identical = true;
            }
            helper(i1, bestI, j1, bestJ);
            if (identical) {
                equalRow(bestI, bestJ);
            } else {
                intralineRow(bestI, bestJ);
            }
            helper(bestI + 1, i2, bestJ + 1, j2);
        }
    }

    /**
     * difflib.unified_diff(a, b, lineterm="") returning all the yielded lines.
     */
    public static List<String> unifiedDiff(List<String> a, List<String> b) {
        return unifiedDiff(a, b, null);
    }

    /**
     * The same comparing the lines through 'key' (null: the lines themselves);
     * the lines are shown as they are. Diaphora-ng: normalize_wil() of the
     * Claude diff.
     */
    public static List<String> unifiedDiff(List<String> a, List<String> b, UnaryOperator<String> key) {
        final int n = 3;
        List<String> out = new ArrayList<>();
        List<Opcode> codes = new Matcher<>(keys(a, key), keys(b, key), true).getOpcodes();
        if (codes.isEmpty()) codes.add(new Opcode('e', 0, 1, 0, 1));

        // get_grouped_opcodes(n)
        List<List<Opcode>> groups = new ArrayList<>();
        Opcode first = codes.get(0);
        if (first.tag == 'e') {
            codes.set(0, new Opcode('e', Math.max(first.i1, first.i2 - n), first.i2,
                                    Math.max(first.j1, first.j2 - n), first.j2));
        }
        Opcode last = codes.get(codes.size() - 1);
        if (last.tag == 'e') {
            codes.set(codes.size() - 1, new Opcode('e', last.i1, Math.min(last.i2, last.i1 + n),
                                                   last.j1, Math.min(last.j2, last.j1 + n)));
        }
        int nn = n + n;
        List<Opcode> group = new ArrayList<>();
        for (Opcode c : codes) {
            if (c.tag == 'e' && c.i2 - c.i1 > nn) {
                group.add(new Opcode('e', c.i1, Math.min(c.i2, c.i1 + n), c.j1, Math.min(c.j2, c.j1 + n)));
                groups.add(group);
                group = new ArrayList<>();
                c = new Opcode('e', Math.max(c.i1, c.i2 - n), c.i2, Math.max(c.j1, c.j2 - n), c.j2);
            }
            group.add(c);
        }
        if (!group.isEmpty() && !(group.size() == 1 && group.get(0).tag == 'e')) {
            groups.add(group);
        }

        boolean started = false;
        for (List<Opcode> g : groups) {
            if (!started) {
                started = true;
                out.add("--- ");
                out.add("+++ ");
            }
            Opcode f = g.get(0);
            Opcode l = g.get(g.size() - 1);
            out.add("@@ -" + formatRangeUnified(f.i1, l.i2) + " +" + formatRangeUnified(f.j1, l.j2) + " @@");
            for (Opcode c : g) {
                if (c.tag == 'e') {
                    for (int i = c.i1; i < c.i2; i++) out.add(" " + a.get(i));
                    continue;
                }
                if (c.tag == 'r' || c.tag == 'd') {
                    for (int i = c.i1; i < c.i2; i++) out.add("-" + a.get(i));
                }
                if (c.tag == 'r' || c.tag == 'i') {
                    for (int j = c.j1; j < c.j2; j++) out.add("+" + b.get(j));
                }
            }
        }
        return out;
    }

    private static String formatRangeUnified(int start, int stop) {
        int beginning = start + 1;
        int length = stop - start;
        if (length == 1) return String.valueOf(beginning);
        if (length == 0) beginning--;
        return beginning + "," + length;
    }

    private static List<String> keys(List<String> lines, UnaryOperator<String> key) {
        if (key == null) return lines;
        List<String> out = new ArrayList<>(lines.size());
        for (String l : lines) out.add(key.apply(l));
        return out;
    }

    public static List<Row> diff(List<String> a, List<String> b) {
        return diff(a, b, null);
    }

    /** The same comparing the lines through 'key' (null: the lines themselves). */
    public static List<Row> diff(List<String> a, List<String> b, UnaryOperator<String> key) {
        Builder sb = new Builder(a, b, keys(a, key), keys(b, key));
        Matcher<String> sm = new Matcher<>(sb.ka, sb.kb, true);
        for (Opcode op : sm.getOpcodes()) {
            switch (op.tag) {
                case 'e':
                    for (int k = 0; k < op.i2 - op.i1; k++) sb.equalRow(op.i1 + k, op.j1 + k);
                    break;
                case 'r':
                    sb.fancyReplace(op.i1, op.i2, op.j1, op.j2);
                    break;
                case 'd':
                    sb.plainReplace(op.i1, op.i2, op.j2, op.j2);
                    break;
                case 'i':
                    sb.plainReplace(op.i2, op.i2, op.j1, op.j2);
                    break;
                default:
                    break;
            }
        }
        return sb.rows;
    }
}
