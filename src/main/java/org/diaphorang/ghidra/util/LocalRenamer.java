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
 */
package org.diaphorang.ghidra.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Not in diaphora.py: "level 2" local renaming for the pseudo-code diff views.
 *
 * <p>Level 1 (export/LocalNames) names the locals v1, v2... in the order of
 * first use, as Hex-Rays does; two builds still get different numbers when a
 * local is added or removed. Here the locals of one side (the declarations at
 * the top of the body) are renamed after those of the other: they are matched
 * by where they are used in the lines that line up when the locals are masked,
 * and take the name of their match. A real change of variable is then a
 * change of the line. The locals without a match keep their name, or get a new
 * one if the other side uses it. The declarations are then sorted in the order
 * of the other side.
 *
 * <p>The lines are compared through a normalized key, so what moves between two
 * builds without changing the code does not break the alignment: addresses
 * (sub_180012340, DAT_..., 0x180012345 inside the image), the source line
 * number of the WIL diagnostics and the spacing.
 */
public final class LocalRenamer {

    private LocalRenamer() {
    }

    /** The renamed lines and the renames (new name -> name of the reference side). */
    public static final class Result {
        public final List<String> lines;
        public final Map<String, String> renamed;

        Result(List<String> lines, Map<String, String> renamed) {
            this.lines = lines;
            this.renamed = renamed;
        }
    }

    // ------------------------------------------------------------------------
    // tokens
    // ------------------------------------------------------------------------
    enum Kind { SPACE, IDENT, NUMBER, STRING, COMMENT, PUNCT }

    static final class Token {
        Kind kind;
        int start;
        int end;
        /** normalized text */
        String key;
    }

    /** addresses inside the image: 'base' up to 256 MB above it */
    private static final long IMAGE_SPAN = 0x10000000L;

    private static boolean isIdentStart(char c) {
        return Character.isLetter(c) || c == '_' || c == '$' || c == '?' || c == '@';
    }

    private static boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '?' || c == '@';
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean allHex(String s, int from, int to) {
        if (from >= to) return false;
        for (int i = from; i < to; i++) {
            if (!isHex(s.charAt(i))) return false;
        }
        return true;
    }

    private static boolean allDigits(String s, int from, int to) {
        if (from >= to) return false;
        for (int i = from; i < to; i++) {
            if (s.charAt(i) < '0' || s.charAt(i) > '9') return false;
        }
        return true;
    }

    private static boolean hasDigit(String s, int from, int to) {
        for (int i = from; i < to; i++) {
            if (s.charAt(i) >= '0' && s.charAt(i) <= '9') return true;
        }
        return false;
    }

    /** names that hold an address chosen by Ghidra */
    static String identKey(String s) {
        // code_r0x180012345 -> code_r0x#
        int r = s.indexOf("_r0x");
        if (r >= 0 && allHex(s, r + 4, s.length())) {
            return s.substring(0, r) + "_r0x#";
        }
        // sub_180012340, DAT_180034000, LAB_..., PTR_FUN_..., switchD_... -> sub_#
        int u = s.lastIndexOf('_');
        if (u > 0 && s.length() - u - 1 >= 6 && allHex(s, u + 1, s.length()) && hasDigit(s, u + 1, s.length())) {
            return s.substring(0, u) + "_#";
        }
        return s;
    }

    /** the value of a number token, null if it is not one (unsigned, as strtoull) */
    private static Long numberValue(String s) {
        try {
            if (s.length() > 2 && s.charAt(0) == '0' && (s.charAt(1) == 'x' || s.charAt(1) == 'X')) {
                int e = 2;
                while (e < s.length() && isHex(s.charAt(e))) e++;
                if (e == 2) return null;
                String h = s.substring(2, e);
                return h.length() > 16 ? -1L : Long.parseUnsignedLong(h, 16);
            }
            int e = 0;
            while (e < s.length() && Character.isDigit(s.charAt(e))) e++;
            if (e == 0) return null;
            String d = s.substring(0, e);
            return d.length() > 20 ? -1L : Long.parseUnsignedLong(d);
        }
        catch (NumberFormatException ex) {
            return -1L;
        }
    }

    private static String numberKey(String s, long base) {
        Long v = numberValue(s);
        if (base != 0 && v != null && Long.compareUnsigned(v, base) >= 0
            && Long.compareUnsigned(v - base, IMAGE_SPAN) < 0) {
            return "ADDR#";
        }
        return s;
    }

    /** a comment with its addresses masked */
    private static String commentKey(String text, long base) {
        StringBuilder key = new StringBuilder();
        for (Token t : tokenize(text, base, true)) {
            key.append(t.kind == Kind.SPACE ? " " : t.key);
        }
        return key.toString();
    }

    private static final List<String> SOURCE_EXTS =
        Arrays.asList(".c\"", ".cc\"", ".cpp\"", ".cxx\"", ".h\"", ".hpp\"", ".hxx\"", ".inl\"");

    static List<Token> tokenize(String line, long base) {
        return tokenize(line, base, false);
    }

    /** plainText: inside a comment (no strings, no nested comments) */
    static List<Token> tokenize(String line, long base, boolean plainText) {
        List<Token> out = new ArrayList<>();
        int i = 0;
        int n = line.length();
        while (i < n) {
            char c = line.charAt(i);
            int s = i;
            Token t = new Token();
            if (c == ' ' || c == '\t') {
                while (i < n && (line.charAt(i) == ' ' || line.charAt(i) == '\t')) i++;
                t.kind = Kind.SPACE;
                t.key = " ";
            } else if (!plainText && c == '/' && i + 1 < n && (line.charAt(i + 1) == '/' || line.charAt(i + 1) == '*')) {
                if (line.charAt(i + 1) == '/') {
                    i = n;
                } else {
                    int e = line.indexOf("*/", i + 2);
                    i = e < 0 ? n : e + 2;
                }
                t.kind = Kind.COMMENT;
                t.key = commentKey(line.substring(s, i), base);
            } else if (!plainText && (c == '"' || c == '\'')) {
                i++;
                while (i < n && line.charAt(i) != c) {
                    if (line.charAt(i) == '\\' && i + 1 < n) i++;
                    i++;
                }
                if (i < n) i++;
                t.kind = Kind.STRING;
                t.key = line.substring(s, i);
            } else if (Character.isDigit(c)) {
                while (i < n && (Character.isLetterOrDigit(line.charAt(i)) || line.charAt(i) == '.'
                    || line.charAt(i) == '_')) {
                    i++;
                }
                t.kind = Kind.NUMBER;
                t.key = numberKey(line.substring(s, i), base);
            } else if (isIdentStart(c)) {
                while (i < n && isIdentChar(line.charAt(i))) i++;
                // a string prefix: L"...", u"..."
                if (!plainText && i < n && (line.charAt(i) == '"' || line.charAt(i) == '\'') && i - s <= 2) {
                    char q = line.charAt(i++);
                    while (i < n && line.charAt(i) != q) {
                        if (line.charAt(i) == '\\' && i + 1 < n) i++;
                        i++;
                    }
                    if (i < n) i++;
                    t.kind = Kind.STRING;
                    t.key = line.substring(s, i);
                } else {
                    t.kind = Kind.IDENT;
                    t.key = identKey(line.substring(s, i));
                }
            } else {
                i++;
                t.kind = Kind.PUNCT;
                t.key = line.substring(s, s + 1);
            }
            t.start = s;
            t.end = i;
            out.add(t);
        }
        if (plainText) return out;

        // WIL diagnostics: the number right before the source file name,
        // Return_Hr(retaddr, 0x339, "...\\file.cxx", hr)
        for (int k = 0; k < out.size(); k++) {
            if (out.get(k).kind != Kind.NUMBER) continue;
            int j = k + 1;
            while (j < out.size() && out.get(j).kind == Kind.SPACE) j++;
            if (j >= out.size() || !out.get(j).key.equals(",")) continue;
            j++;
            while (j < out.size() && out.get(j).kind == Kind.SPACE) j++;
            if (j >= out.size() || out.get(j).kind != Kind.STRING) continue;
            String f = out.get(j).key.toLowerCase();
            for (String e : SOURCE_EXTS) {
                if (f.endsWith(e)) {
                    out.get(k).key = "#";
                    break;
                }
            }
        }
        return out;
    }

    private static String keyOf(List<Token> toks) {
        StringBuilder key = new StringBuilder();
        for (Token t : toks) {
            if (t.kind == Kind.SPACE) continue;
            if (key.length() > 0) key.append(' ');
            key.append(t.key);
        }
        return key.toString();
    }

    /** the comparison key of a line; imageBase masks the addresses of its image */
    public static String normalizeLine(String line, long imageBase) {
        return keyOf(tokenize(line, imageBase));
    }

    private static String raw(String line, Token t) {
        return line.substring(t.start, t.end);
    }

    // ------------------------------------------------------------------------
    // line alignment: patience diff, LCS inside the gaps without anchors
    // ------------------------------------------------------------------------
    private static final long MAX_DP_CELLS = 4000000;

    private static void lcsDp(int[] a, int[] b, int a0, int a1, int b0, int b1, List<int[]> out) {
        int n = a1 - a0;
        int m = b1 - b0;
        if (n <= 0 || m <= 0 || (long) n * m > MAX_DP_CELLS) return;
        int[] l = new int[(n + 1) * (m + 1)];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                l[i * (m + 1) + j] = a[a0 + i] == b[b0 + j] ? l[(i + 1) * (m + 1) + j + 1] + 1
                    : Math.max(l[(i + 1) * (m + 1) + j], l[i * (m + 1) + j + 1]);
            }
        }
        int i = 0;
        int j = 0;
        while (i < n && j < m) {
            if (a[a0 + i] == b[b0 + j]) {
                out.add(new int[]{a0 + i, b0 + j});
                i++;
                j++;
            } else if (l[(i + 1) * (m + 1) + j] >= l[i * (m + 1) + j + 1]) {
                i++;
            } else {
                j++;
            }
        }
    }

    static void patience(int[] a, int[] b, int a0, int a1, int b0, int b1, List<int[]> out) {
        while (a0 < a1 && b0 < b1 && a[a0] == b[b0]) out.add(new int[]{a0++, b0++});
        List<int[]> tail = new ArrayList<>();
        while (a0 < a1 && b0 < b1 && a[a1 - 1] == b[b1 - 1]) tail.add(new int[]{--a1, --b1});
        if (a0 < a1 && b0 < b1) {
            // occurrences: count and last position in each side
            Map<Integer, int[]> occ = new HashMap<>();     // {ca, pa, cb, pb}
            for (int i = a0; i < a1; i++) {
                int[] o = occ.computeIfAbsent(a[i], k -> new int[4]);
                o[0]++;
                o[1] = i;
            }
            for (int j = b0; j < b1; j++) {
                int[] o = occ.get(b[j]);
                if (o != null) {
                    o[2]++;
                    o[3] = j;
                }
            }
            List<int[]> uniq = new ArrayList<>();          // (pos in A, pos in B), sorted by A
            for (int i = a0; i < a1; i++) {
                int[] o = occ.get(a[i]);
                if (o[0] == 1 && o[2] == 1) uniq.add(new int[]{i, o[3]});
            }
            // longest increasing subsequence of the positions in B
            List<Integer> tailIdx = new ArrayList<>();
            int[] prev = new int[uniq.size()];
            Arrays.fill(prev, -1);
            for (int k = 0; k < uniq.size(); k++) {
                int lo = 0;
                int hi = tailIdx.size();
                while (lo < hi) {
                    int mid = (lo + hi) / 2;
                    if (uniq.get(tailIdx.get(mid))[1] < uniq.get(k)[1]) lo = mid + 1;
                    else hi = mid;
                }
                if (lo > 0) prev[k] = tailIdx.get(lo - 1);
                if (lo == tailIdx.size()) tailIdx.add(k);
                else tailIdx.set(lo, k);
            }
            List<int[]> anchors = new ArrayList<>();
            for (int k = tailIdx.isEmpty() ? -1 : tailIdx.get(tailIdx.size() - 1); k >= 0; k = prev[k]) {
                anchors.add(uniq.get(k));
            }
            Collections.reverse(anchors);
            if (anchors.isEmpty()) {
                lcsDp(a, b, a0, a1, b0, b1, out);
            } else {
                int pa = a0;
                int pb = b0;
                for (int[] an : anchors) {
                    patience(a, b, pa, an[0], pb, an[1], out);
                    out.add(an);
                    pa = an[0] + 1;
                    pb = an[1] + 1;
                }
                patience(a, b, pa, a1, pb, b1, out);
            }
        }
        for (int k = tail.size() - 1; k >= 0; k--) out.add(tail.get(k));
    }

    // ------------------------------------------------------------------------
    // the lines of a replaced block: pairs of similar lines
    // ------------------------------------------------------------------------
    static final class LineInfo {
        List<Token> toks;
        /** ids of the keys of the non-space tokens */
        final List<Integer> words = new ArrayList<>();
        /** their index in toks */
        final List<Integer> wordTok = new ArrayList<>();
        String key;
    }

    private static double similarity(LineInfo a, LineInfo b) {
        int n = a.words.size();
        int m = b.words.size();
        if (n == 0 && m == 0) return 1.0;
        if (n == 0 || m == 0) return 0.0;
        if ((long) n * m > 90000) return a.key.equals(b.key) ? 1.0 : 0.0;
        int[] row = new int[m + 1];
        int[] next = new int[m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                row[j] = a.words.get(i).equals(b.words.get(j)) ? next[j + 1] + 1 : Math.max(next[j], row[j + 1]);
            }
            int[] t = row;
            row = next;
            next = t;
        }
        return 2.0 * next[0] / (n + m);
    }

    private static final double PAIR_MIN = 0.5;
    private static final long MAX_PAIR_CELLS = 40000;

    /** monotonic pairing of the lines of a block, maximizing the similarity of the pairs */
    private static List<int[]> pairLines(List<LineInfo> l, List<LineInfo> r, int a0, int a1, int b0, int b1) {
        List<int[]> out = new ArrayList<>();
        int n = a1 - a0;
        int m = b1 - b0;
        if (n <= 0 || m <= 0 || (long) n * m > MAX_PAIR_CELLS) return out;
        double[] sim = new double[n * m];
        double[] s = new double[(n + 1) * (m + 1)];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                sim[i * m + j] = similarity(l.get(a0 + i), r.get(b0 + j));
            }
        }
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                double best = Math.max(s[(i + 1) * (m + 1) + j], s[i * (m + 1) + j + 1]);
                double v = sim[i * m + j];
                if (v >= PAIR_MIN) best = Math.max(best, v + s[(i + 1) * (m + 1) + j + 1]);
                s[i * (m + 1) + j] = best;
            }
        }
        int i = 0;
        int j = 0;
        while (i < n && j < m) {
            double v = sim[i * m + j];
            if (v >= PAIR_MIN && s[i * (m + 1) + j] == v + s[(i + 1) * (m + 1) + j + 1]) {
                out.add(new int[]{a0 + i, b0 + j});
                i++;
                j++;
            } else if (s[i * (m + 1) + j] == s[(i + 1) * (m + 1) + j]) {
                i++;
            } else {
                j++;
            }
        }
        return out;
    }

    /** the equal words of two paired lines (indexes in words) */
    private static List<int[]> wordMatches(LineInfo a, LineInfo b) {
        int n = a.words.size();
        int m = b.words.size();
        List<int[]> tm = new ArrayList<>();
        if ((long) n * m <= 90000) {
            int[] l = new int[(n + 1) * (m + 1)];
            for (int i = n - 1; i >= 0; i--) {
                for (int j = m - 1; j >= 0; j--) {
                    l[i * (m + 1) + j] = a.words.get(i).equals(b.words.get(j)) ? l[(i + 1) * (m + 1) + j + 1] + 1
                        : Math.max(l[(i + 1) * (m + 1) + j], l[i * (m + 1) + j + 1]);
                }
            }
            int i = 0;
            int j = 0;
            while (i < n && j < m) {
                if (a.words.get(i).equals(b.words.get(j))) {
                    tm.add(new int[]{i, j});
                    i++;
                    j++;
                } else if (l[(i + 1) * (m + 1) + j] >= l[i * (m + 1) + j + 1]) {
                    i++;
                } else {
                    j++;
                }
            }
        }
        return tm;
    }

    // ------------------------------------------------------------------------
    // the locals
    // ------------------------------------------------------------------------
    private static final String LOCAL_KEY = "\u0002local";

    /** the token k is a member: x.name, p->name */
    private static boolean isMember(List<Token> toks, int k) {
        int j = k;
        while (j > 0 && toks.get(j - 1).kind == Kind.SPACE) j--;
        if (j == 0) return false;
        if (toks.get(j - 1).key.equals(".")) return true;
        return toks.get(j - 1).key.equals(">") && j >= 2 && toks.get(j - 2).key.equals("-");
    }

    /**
     * The names declared at the top of the body: the lines after the first one
     * that ends in "{" (any brace style) up to the first one that is not a
     * declaration ("  uint v1 [2];"). Returns the index of the first
     * declaration; 'names' gets the name of each one.
     */
    static int declarations(List<String> lines, List<String> names) {
        int i = 0;
        for (; i < lines.size(); i++) {
            String key = normalizeLine(lines.get(i), 0);
            if (!key.isEmpty() && key.charAt(key.length() - 1) == '{') break;
        }
        int first = i + 1;
        for (i++; i < lines.size(); i++) {
            String name = declaredName(lines.get(i));
            if (name.isEmpty()) break;
            names.add(name);
        }
        return first;
    }

    /** words that start a statement ending in ";" with a name: return v1; */
    private static final Set<String> STATEMENT_WORDS = new TreeSet<>(Arrays.asList("return", "goto", "break",
        "continue", "do", "else", "case", "default", "if", "while", "for", "switch", "sizeof", "delete", "throw"));

    /**
     * The name declared by a line ("  uint v1 [2];", "  void (*v1)(int);"), or
     * "" if it is a statement: a type and a name (two words at least) made of
     * names, '*', '&amp;', '::' and template arguments only. With no locals the
     * first line of the body is a statement: "return *(int *)(p + 0x10);",
     * "FUN_1(a);", "x = 0;".
     */
    static String declaredName(String line) {
        List<Token> toks = tokenize(line, 0);
        while (!toks.isEmpty() && (toks.get(toks.size() - 1).kind == Kind.SPACE
            || toks.get(toks.size() - 1).kind == Kind.COMMENT)) {
            toks.remove(toks.size() - 1);
        }
        if (toks.isEmpty() || !toks.get(toks.size() - 1).key.equals(";")) return "";
        String name = "";
        int words = 0;
        boolean fnPtr = false, first = true;
        for (int k = 0; k < toks.size(); k++) {
            Token t = toks.get(k);
            if (t.kind == Kind.SPACE || t.kind == Kind.COMMENT) continue;
            if (first && (t.kind != Kind.IDENT || STATEMENT_WORDS.contains(t.key))) return "";
            first = false;
            if (t.key.equals("[") || t.key.equals(";") || t.key.equals("=") || (t.key.equals(")") && fnPtr)) break;
            if (t.key.equals("(")) {
                int j = k + 1;
                while (j < toks.size() && toks.get(j).kind == Kind.SPACE) j++;
                if (fnPtr || j >= toks.size() || !toks.get(j).key.equals("*")) return "";
                fnPtr = true;   // void (*v1)(int)
                continue;
            }
            if (t.kind == Kind.IDENT) {
                name = raw(line, t);
                words++;
            } else if (t.kind != Kind.NUMBER && !t.key.equals("*") && !t.key.equals("&") && !t.key.equals(":")
                && !t.key.equals("<") && !t.key.equals(">") && !t.key.equals(",")) {
                return "";
            }
        }
        return words >= 2 ? name : "";
    }

    static Set<String> declaredLocals(List<String> lines) {
        List<String> names = new ArrayList<>();
        declarations(lines, names);
        return new TreeSet<>(names);
    }

    /**
     * The declarations of 'lines' (renamed) in the order of those of 'ref', the
     * others after them: Ghidra sorts them by name, and the order changes nothing.
     */
    static void sortDeclarations(List<String> ref, List<String> lines) {
        List<String> refNames = new ArrayList<>();
        List<String> names = new ArrayList<>();
        declarations(ref, refNames);
        int first = declarations(lines, names);
        Map<String, Integer> rank = new HashMap<>();
        for (int i = 0; i < refNames.size(); i++) rank.putIfAbsent(refNames.get(i), i);
        List<Object[]> decls = new ArrayList<>();
        for (int i = 0; i < names.size(); i++) {
            decls.add(new Object[]{rank.getOrDefault(names.get(i), refNames.size()), lines.get(first + i)});
        }
        decls.sort((x, y) -> Integer.compare((Integer) x[0], (Integer) y[0]));    // stable
        for (int i = 0; i < decls.size(); i++) lines.set(first + i, (String) decls.get(i)[1]);
    }

    private static final class Builder {
        final Map<String, Integer> ids = new HashMap<>();

        int idOf(String k) {
            return ids.computeIfAbsent(k, x -> ids.size());
        }

        /** locals: names that compare equal to each other */
        void info(List<String> lines, long base, Set<String> locals, List<LineInfo> out, List<Integer> keys) {
            for (String l : lines) {
                LineInfo li = new LineInfo();
                li.toks = tokenize(l, base);
                if (locals != null) {
                    for (int k = 0; k < li.toks.size(); k++) {
                        Token t = li.toks.get(k);
                        if (t.kind == Kind.IDENT && locals.contains(raw(l, t)) && !isMember(li.toks, k)) {
                            t.key = LOCAL_KEY;
                        }
                    }
                }
                for (int k = 0; k < li.toks.size(); k++) {
                    if (li.toks.get(k).kind != Kind.SPACE) {
                        li.words.add(idOf("\u0001" + li.toks.get(k).key));
                        li.wordTok.add(k);
                    }
                }
                li.key = keyOf(li.toks);
                keys.add(idOf(li.key));
                out.add(li);
            }
        }
    }

    private static int[] ints(List<Integer> l) {
        int[] out = new int[l.size()];
        for (int i = 0; i < out.length; i++) out[i] = l.get(i);
        return out;
    }

    /** the lines that line up: the anchors of the patience diff and the similar lines paired in the gaps */
    private static List<int[]> alignedLines(List<LineInfo> l, List<LineInfo> r, int[] a, int[] b) {
        List<int[]> matches = new ArrayList<>();
        List<int[]> out = new ArrayList<>();
        patience(a, b, 0, a.length, 0, b.length, matches);
        matches.add(new int[]{a.length, b.length});
        int pa = 0;
        int pb = 0;
        for (int[] mt : matches) {
            if (mt[0] > pa || mt[1] > pb) {
                out.addAll(pairLines(l, r, pa, mt[0], pb, mt[1]));
            }
            if (mt[0] < a.length) out.add(mt);
            pa = mt[0] + 1;
            pb = mt[1] + 1;
        }
        return out;
    }

    /**
     * Name in 'lines' -> name in 'ref': a pair of locals gets a vote for every
     * place where both are used in two lines that line up (with the locals
     * masked); the pairs with the most votes win.
     */
    static Map<String, String> matchLocals(List<String> ref, List<String> lines, long refBase, long base,
                                           Set<String> refLocals, Set<String> locals) {
        Builder bld = new Builder();
        List<LineInfo> l = new ArrayList<>();
        List<LineInfo> r = new ArrayList<>();
        List<Integer> a = new ArrayList<>();
        List<Integer> b = new ArrayList<>();
        bld.info(ref, refBase, refLocals, l, a);
        bld.info(lines, base, locals, r, b);

        // (ref name, name) -> votes, in the order of the names (std::map)
        Map<String, Map<String, Integer>> votes = new TreeMap<>();
        for (int[] ln : alignedLines(l, r, ints(a), ints(b))) {
            LineInfo la = l.get(ln[0]);
            LineInfo lb = r.get(ln[1]);
            for (int[] w : wordMatches(la, lb)) {
                Token ta = la.toks.get(la.wordTok.get(w[0]));
                Token tb = lb.toks.get(lb.wordTok.get(w[1]));
                if (!ta.key.equals(LOCAL_KEY) || !tb.key.equals(LOCAL_KEY)) continue;
                votes.computeIfAbsent(raw(ref.get(ln[0]), ta), k -> new TreeMap<>())
                    .merge(raw(lines.get(ln[1]), tb), 1, Integer::sum);
            }
        }
        List<Object[]> ranked = new ArrayList<>();      // {votes, ref name, name}
        for (Map.Entry<String, Map<String, Integer>> e : votes.entrySet()) {
            for (Map.Entry<String, Integer> v : e.getValue().entrySet()) {
                ranked.add(new Object[]{v.getValue(), e.getKey(), v.getKey()});
            }
        }
        // the most votes first; on a tie the same name, then the order of the names (stable)
        ranked.sort((x, y) -> {
            int c = Integer.compare((Integer) y[0], (Integer) x[0]);
            if (c != 0) return c;
            boolean sx = x[1].equals(x[2]);
            boolean sy = y[1].equals(y[2]);
            return Boolean.compare(sy, sx);
        });
        Map<String, String> out = new TreeMap<>();
        Set<String> taken = new TreeSet<>();
        for (Object[] v : ranked) {
            String refName = (String) v[1];
            String name = (String) v[2];
            if (!out.containsKey(name) && !taken.contains(refName)) {
                out.put(name, refName);
                taken.add(refName);
            }
        }
        return out;
    }

    /**
     * 'lines' with its locals renamed; those without a match whose name 'ref'
     * uses get a new one (v1, v2... used by neither side).
     */
    static List<String> renameLocals(List<String> ref, List<String> lines, Set<String> refLocals,
                                     Set<String> locals, Map<String, String> names) {
        Set<String> used = new TreeSet<>();
        for (List<String> ls : List.of(ref, lines)) {
            for (String l : ls) {
                for (Token t : tokenize(l, 0)) {
                    if (t.kind == Kind.IDENT) used.add(raw(l, t));
                }
            }
        }
        Set<String> targets = new TreeSet<>(names.values());
        int next = 1;
        for (String n : locals) {
            if (names.containsKey(n) || (!refLocals.contains(n) && !targets.contains(n))) continue;
            String nn;
            do {
                nn = "v" + next++;
            } while (used.contains(nn) || targets.contains(nn));
            names.put(n, nn);
            targets.add(nn);
        }
        if (names.isEmpty()) return new ArrayList<>(lines);

        List<String> out = new ArrayList<>();
        for (String l : lines) {
            List<Token> toks = tokenize(l, 0);
            StringBuilder r = new StringBuilder();
            for (int k = 0; k < toks.size(); k++) {
                String w = raw(l, toks.get(k));
                String to = toks.get(k).kind == Kind.IDENT && !isMember(toks, k) ? names.get(w) : null;
                r.append(to != null ? to : w);
            }
            out.add(r.toString());
        }
        return out;
    }

    /**
     * 'lines' with its locals renamed after those of 'ref' and its declarations
     * in the order of those of 'ref'. The bases are the image bases of each side
     * (0: unknown), used to mask the addresses when lining up the code.
     */
    public static Result rename(List<String> ref, List<String> lines, long refBase, long base) {
        Set<String> refLocals = declaredLocals(ref);
        Set<String> locals = declaredLocals(lines);
        Map<String, String> names = new TreeMap<>();
        if (!refLocals.isEmpty() && !locals.isEmpty()) {
            names = matchLocals(ref, lines, refBase, base, refLocals, locals);
        }
        List<String> renamed = renameLocals(ref, lines, refLocals, locals, names);
        if (!names.isEmpty()) sortDeclarations(ref, renamed);
        Map<String, String> changed = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : names.entrySet()) {
            if (!e.getKey().equals(e.getValue())) changed.put(e.getKey(), e.getValue());
        }
        return new Result(renamed, changed);
    }

    /** The same on whole texts ("\n" separated). */
    public static String renameText(String ref, String text, long refBase, long base) {
        return String.join("\n", rename(Arrays.asList(ref.split("\n", -1)),
            Arrays.asList(text.split("\n", -1)), refBase, base).lines);
    }
}
