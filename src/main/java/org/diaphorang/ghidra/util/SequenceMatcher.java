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

/**
 * Clean Java port of Python's difflib.SequenceMatcher.
 * Used by Diaphora for calculating similarity ratios and diffs.
 */
public class SequenceMatcher {

    public static double ratio(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return 0.0;
        }
        if (s1.equals(s2)) {
            return 1.0;
        }
        int len1 = s1.length();
        int len2 = s2.length();
        if (len1 == 0 || len2 == 0) {
            return 0.0;
        }

        int matches = getMatchingBlocksLength(s1, s2);
        return 2.0 * matches / (len1 + len2);
    }

    public static double quickRatio(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return 0.0;
        }
        if (s1.equals(s2)) {
            return 1.0;
        }
        int len1 = s1.length();
        int len2 = s2.length();
        if (len1 == 0 || len2 == 0) {
            return 0.0;
        }

        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < len1; i++) {
            char c = s1.charAt(i);
            counts.put(c, counts.getOrDefault(c, 0) + 1);
        }

        int availableMatches = 0;
        for (int i = 0; i < len2; i++) {
            char c = s2.charAt(i);
            Integer count = counts.get(c);
            if (count != null && count > 0) {
                counts.put(c, count - 1);
                availableMatches++;
            }
        }

        return 2.0 * availableMatches / (len1 + len2);
    }

    public static double realQuickRatio(String s1, String s2) {
        if (s1 == null || s2 == null) {
            return 0.0;
        }
        int len1 = s1.length();
        int len2 = s2.length();
        if (len1 == 0 && len2 == 0) {
            return 1.0;
        }
        return 2.0 * Math.min(len1, len2) / (len1 + len2);
    }

    /**
     * Equivalent of Diaphora's quick_ratio(): difflib.SequenceMatcher over the
     * LINES of both buffers (not characters), using quick_ratio() which is the
     * size of the multiset intersection of lines.
     */
    public static double quickRatioLines(String buf1, String buf2) {
        if (buf1 == null || buf2 == null || buf1.isEmpty() || buf2.isEmpty()) {
            return 0.0;
        }
        String[] a = buf1.split("\n", -1);
        String[] b = buf2.split("\n", -1);

        Map<String, Integer> counts = new HashMap<>();
        for (String line : b) {
            counts.merge(line, 1, Integer::sum);
        }
        int matches = 0;
        for (String line : a) {
            Integer c = counts.get(line);
            if (c != null && c > 0) {
                counts.put(line, c - 1);
                matches++;
            }
        }
        return 2.0 * matches / (a.length + b.length);
    }

    /**
     * Equivalent of Diaphora's real_quick_ratio(): upper bound based only on the
     * number of lines of both buffers.
     */
    public static double realQuickRatioLines(String buf1, String buf2) {
        if (buf1 == null || buf2 == null || buf1.isEmpty() || buf2.isEmpty()) {
            return 0.0;
        }
        int la = buf1.split("\n", -1).length;
        int lb = buf2.split("\n", -1).length;
        return 2.0 * Math.min(la, lb) / (la + lb);
    }

    private static int getMatchingBlocksLength(String s1, String s2) {
        int n = s1.length();
        int m = s2.length();
        if (n > 5000 || m > 5000) {
            // For very large strings fallback to fast token/character approximation
            return (int) (quickRatio(s1, s2) * (n + m) / 2.0);
        }

        // Longest Common Subsequence DP table (space optimized)
        int[] prev = new int[m + 1];
        int[] curr = new int[m + 1];

        for (int i = 1; i <= n; i++) {
            char c1 = s1.charAt(i - 1);
            for (int j = 1; j <= m; j++) {
                if (c1 == s2.charAt(j - 1)) {
                    curr[j] = prev[j - 1] + 1;
                } else {
                    curr[j] = Math.max(prev[j], curr[j - 1]);
                }
            }
            int[] temp = prev;
            prev = curr;
            curr = temp;
            Arrays.fill(curr, 0);
        }

        return prev[m];
    }

    public static List<DiffLine> diffLines(List<String> lines1, List<String> lines2) {
        List<DiffLine> result = new ArrayList<>();
        int n = lines1.size();
        int m = lines2.size();

        int[][] dp = new int[n + 1][m + 1];
        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= m; j++) {
                if (lines1.get(i - 1).trim().equals(lines2.get(j - 1).trim())) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        int i = n, j = m;
        List<DiffLine> stack = new ArrayList<>();
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 && lines1.get(i - 1).trim().equals(lines2.get(j - 1).trim())) {
                stack.add(new DiffLine(DiffType.EQUAL, lines1.get(i - 1), lines2.get(j - 1), i, j));
                i--;
                j--;
            } else if (j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j])) {
                stack.add(new DiffLine(DiffType.ADDED, null, lines2.get(j - 1), -1, j));
                j--;
            } else if (i > 0 && (j == 0 || dp[i][j - 1] < dp[i - 1][j])) {
                stack.add(new DiffLine(DiffType.DELETED, lines1.get(i - 1), null, i, -1));
                i--;
            }
        }

        Collections.reverse(stack);
        return stack;
    }

    public enum DiffType {
        EQUAL,
        ADDED,
        DELETED,
        MODIFIED
    }

    public static class DiffLine {
        public final DiffType type;
        public final String line1;
        public final String line2;
        public final int lineNum1;
        public final int lineNum2;

        public DiffLine(DiffType type, String line1, String line2, int lineNum1, int lineNum2) {
            this.type = type;
            this.line1 = line1;
            this.line2 = line2;
            this.lineNum1 = lineNum1;
            this.lineNum2 = lineNum2;
        }
    }
}
