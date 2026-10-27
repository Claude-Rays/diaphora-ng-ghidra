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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Text normalization utility for assembly and decompiled pseudo-code.
 * Matches Diaphora's get_cmp_asm and get_cmp_pseudo_lines.
 */
public final class TextCleaner {

    private static final String[] CLEANING_CMP_REPS = {
        "loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
        "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
        "stru_", "dbl_", "locret_", "flt_", "jpt_", "LAB_", "FUN_", "DAT_", "PTR_"
    };

    private static final String[] CLEANING_CMP_REMS = {
        // Longest first: "word ptr " is a suffix of "dword ptr " and "qword ptr "
        "xmmword ptr ", "ymmword ptr ", "zmmword ptr ", "tword ptr ",
        "dword ptr ", "qword ptr ", "byte ptr ", "word ptr ", "short ptr"
    };

    private static final Pattern HEX_OFFSET_PATTERN = Pattern.compile("\\+[a-fA-F0-9]+h\\+");
    private static final Pattern COMPILER_HEX_PATTERN = Pattern.compile("\\.\\.[a-fA-F0-9]{8}");
    private static final Pattern IDENT_NUM_PATTERN = Pattern.compile("a[A-Za-z0-9]+_[0-9]+");
    private static final Pattern HASH_HEX_PATTERN = Pattern.compile("#0x[A-Za-z0-9]+");

    private TextCleaner() {}

    /** prettify_asm(): indent every line except the loc_ labels. */
    public static String prettifyAsm(String asmSource) {
        if (asmSource == null) return "";
        String[] lines = asmSource.split("\n", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) sb.append('\n');
            if (!lines[i].startsWith("loc_")) sb.append('\t');
            sb.append(lines[i]);
        }
        return sb.toString();
    }

    public static String getCmpAsm(String asmLine) {
        if (asmLine == null) return "";

        // Remove comments
        int idx = asmLine.indexOf(';');
        String tmp = (idx != -1) ? asmLine.substring(0, idx) : asmLine;
        idx = tmp.indexOf(" # ");
        if (idx != -1) {
            tmp = tmp.substring(0, idx);
        }
        idx = tmp.indexOf("//");
        if (idx != -1) {
            tmp = tmp.substring(0, idx);
        }

        // Replace address labels (sub_, LAB_, FUN_, etc.) with XXXX
        for (String rep : CLEANING_CMP_REPS) {
            tmp = replacePrefixHex(tmp, rep, "XXXX");
        }

        // Remove type casts/size prefixes
        for (String rem : CLEANING_CMP_REMS) {
            tmp = tmp.replace(rem, "");
        }

        // Replace hex patterns
        tmp = HEX_OFFSET_PATTERN.matcher(tmp).replaceAll("+XXXX+");
        tmp = COMPILER_HEX_PATTERN.matcher(tmp).replaceAll("XXX");
        tmp = IDENT_NUM_PATTERN.matcher(tmp).replaceAll("aXXX");
        tmp = HASH_HEX_PATTERN.matcher(tmp).replaceAll("0xXXX");
        tmp = GHIDRA_STACK_PATTERN.matcher(tmp).replaceAll("$1_XXX");

        return tmp.stripTrailing();
    }

    public static String getCmpAsmLines(String asmText) {
        if (asmText == null || asmText.isEmpty()) return "";
        String[] lines = asmText.split("\n");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            String cleaned = getCmpAsm(lines[i]);
            if (!cleaned.isEmpty()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(cleaned);
            }
        }
        return sb.toString();
    }

    public static String getCmpPseudoLines(String pseudo) {
        if (pseudo == null || pseudo.isEmpty()) return "";

        // Remove all comments " // .*"
        String[] rawLines = pseudo.split("\n");
        StringBuilder sb = new StringBuilder();
        for (String line : rawLines) {
            int cIdx = line.indexOf("//");
            String code = (cIdx != -1) ? line.substring(0, cIdx) : line;
            code = code.stripTrailing();
            if (!code.isEmpty()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(code);
            }
        }
        String tmp = sb.toString();

        // Replace labels
        for (String rep : CLEANING_CMP_REPS) {
            tmp = replacePrefixHex(tmp, rep, rep + "XXXX");
        }

        // Ghidra auto-generated variable names (uVar1, pcVar12, local_28, uStack_30...)
        // are renumbered whenever a function changes slightly; normalize them first.
        tmp = cleanGhidraVariables(tmp);

        tmp = replacePrefixDigits(tmp, "v", "vXXX");
        tmp = replacePrefixDigits(tmp, "a", "aXXX");
        tmp = replacePrefixDigits(tmp, "arg_", "aXXX");

        return tmp;
    }

    private static final Pattern GHIDRA_VAR_PATTERN = Pattern.compile("\\b([a-z]{0,6}Var)[0-9]+\\b");
    private static final Pattern GHIDRA_STACK_PATTERN = Pattern.compile("\\b(local|[a-z]{0,6}Stack)_(res_?)?[0-9a-fA-F]+\\b");

    /**
     * Normalize the variable names generated by Ghidra's decompiler and listing.
     */
    public static String cleanGhidraVariables(String s) {
        if (s == null || s.isEmpty()) return s;
        s = GHIDRA_VAR_PATTERN.matcher(s).replaceAll("$1XXX");
        s = GHIDRA_STACK_PATTERN.matcher(s).replaceAll("$1_XXX");
        return s;
    }

    private static String replacePrefixHex(String s, String prefix, String repl) {
        int plen = prefix.length();
        if (s.length() <= plen) return s;

        StringBuilder out = new StringBuilder();
        int i = 0, n = s.length();
        while (i < n) {
            if (i + plen < n && s.regionMatches(true, i, prefix, 0, plen) && isHex(s.charAt(i + plen))) {
                int j = i + plen;
                while (j < n && isHex(s.charAt(j))) {
                    j++;
                }
                out.append(repl);
                i = j;
            } else {
                out.append(s.charAt(i++));
            }
        }
        return out.toString();
    }

    private static String replacePrefixDigits(String s, String prefix, String repl) {
        int plen = prefix.length();
        if (s.length() <= plen) return s;

        StringBuilder out = new StringBuilder();
        int i = 0, n = s.length();
        while (i < n) {
            if (i + plen < n && s.regionMatches(true, i, prefix, 0, plen) && Character.isDigit(s.charAt(i + plen))) {
                int j = i + plen;
                while (j < n && Character.isDigit(s.charAt(j))) {
                    j++;
                }
                out.append(repl);
                i = j;
            } else {
                out.append(s.charAt(i++));
            }
        }
        return out.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
