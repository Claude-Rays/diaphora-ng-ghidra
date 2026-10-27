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
package org.diaphorang.ghidra.export;

import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.IllegalCharCppTransformer;
import ghidra.program.model.symbol.NameTransformer;

import java.util.*;

/**
 * Canonical names of the local variables of a decompilation (v1, v2...), as Hex-Rays names them.
 * Ghidra names locals by internal position (uVar3) or stack offset (local_28, auStack_48), so two
 * builds of the same function would not line up in the pseudocode diff or its hashes.
 * Not in diaphora.py: "level 1" of the pseudo-code diff (util/DiffSettings).
 */
public final class LocalNames {

    private LocalNames() {}

    /** A use of a local variable: its name and whether it is inside a declaration. */
    public static final class Occurrence {
        final String name;
        final boolean inDecl;

        public Occurrence(String name, boolean inDecl) {
            this.name = name;
            this.inDecl = inDecl;
        }
    }

    private static boolean allOf(String s, int from, int to, java.util.function.IntPredicate pred) {
        if (from >= to) return false;
        for (int i = from; i < to; i++)
            if (!pred.test(s.charAt(i))) return false;
        return true;
    }

    private static boolean isDigit(int c) { return c >= '0' && c <= '9'; }

    private static boolean isXDigit(int c) {
        return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isTypeChar(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    }

    // without the suffix of ScopeInternal::makeNameUnique: _00 or _x00000
    private static String withoutUniqueSuffix(String s) {
        int n = s.length();
        if (n > 3 && s.charAt(n - 3) == '_' && allOf(s, n - 2, n, LocalNames::isDigit))
            return s.substring(0, n - 3);
        if (n > 7 && s.charAt(n - 7) == '_' && s.charAt(n - 6) == 'x' && allOf(s, n - 5, n, LocalNames::isDigit))
            return s.substring(0, n - 7);
        return s;
    }

    // the prefix of the type of ScopeInternal::buildVariableName: 'p' and 'a' for
    // pointers and arrays, then the first letter of the type (uVar, pcVar, ppHVar)
    private static boolean typePrefix(String s, int len) {
        return len <= 12 && (len == 0 || allOf(s, 0, len, LocalNames::isTypeChar));
    }

    private static boolean isAutoBase(String s) {
        // uVar3, pcVar12, Var1
        int v = s.lastIndexOf("Var");
        if (v >= 0 && typePrefix(s, v) && allOf(s, v + 3, s.length(), LocalNames::isDigit))
            return true;
        // auStack_48, uStackX_8, StackY_10 (ScopeLocal::buildVariableName)
        int st = s.lastIndexOf("Stack");
        if (st >= 0 && typePrefix(s, st)) {
            int i = st + 5;
            if (i < s.length() && (s.charAt(i) == 'X' || s.charAt(i) == 'Y')) i++;
            if (i < s.length() && s.charAt(i) == '_' && allOf(s, i + 1, s.length(), LocalNames::isXDigit))
                return true;
        }
        // local_28, local_res8
        if (s.startsWith("local_")) {
            int i = s.startsWith("res", 6) ? 9 : 6;
            if (allOf(s, i, s.length(), LocalNames::isXDigit))
                return true;
        }
        // in_stack_00000028
        if (s.startsWith("in_stack_") && allOf(s, 9, s.length(), LocalNames::isXDigit))
            return true;
        // IDA frame members without a name: var_28, arg_18
        if ((s.startsWith("var_") || s.startsWith("arg_")) && allOf(s, 4, s.length(), LocalNames::isXDigit))
            return true;
        // extraout_var: a register without a name, numbered by the suffix
        return s.equals("extraout_var");
    }

    /** True for the names the decompiler makes up for a local; user and register names are kept. */
    public static boolean isAutoLocalName(String name) {
        // local_28 also ends like a suffix
        return isAutoBase(name) || isAutoBase(withoutUniqueSuffix(name));
    }

    /**
     * The new names of the automatic locals: v1, v2... in the order of their first use outside
     * the declarations, then the ones only declared. A name in use (or reserved) is never produced.
     */
    public static Map<String, String> canonicalNames(List<Occurrence> occurrences, Set<String> reserved) {
        List<String> order = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (int pass = 0; pass < 2; pass++)
            for (Occurrence o : occurrences)
                if (o.inDecl == (pass == 1) && isAutoLocalName(o.name) && seen.add(o.name))
                    order.add(o.name);

        // the names that stay as they are can not be produced
        Set<String> taken = new HashSet<>(reserved);
        for (Occurrence o : occurrences)
            if (!seen.contains(o.name)) taken.add(o.name);

        Map<String, String> out = new HashMap<>();
        int next = 1;
        for (String name : order) {
            String nn;
            do nn = "v" + next++; while (taken.contains(nn));
            out.put(name, nn);
        }
        return out;
    }

    // a local variable: var_color, not a parameter or a global
    private static boolean isLocalVariable(ClangToken t) {
        return t instanceof ClangVariableToken && t.getSyntaxType() == ClangToken.VARIABLE_COLOR;
    }

    private static boolean isName(ClangToken t) {
        return t instanceof ClangVariableToken || t instanceof ClangFuncNameToken || t instanceof ClangTypeToken
            || t instanceof ClangFieldToken || t instanceof ClangLabelToken;
    }

    // the declaration of the function (a child of the ClangFunction) holding the token, or null
    private static ClangVariableDecl topDecl(ClangToken t) {
        ClangVariableDecl decl = null;
        for (ClangNode n = t.Parent(); n != null; n = n.Parent()) {
            if (n instanceof ClangVariableDecl) decl = (ClangVariableDecl) n;
            if (n instanceof ClangFunction) return decl != null && decl.Parent() == n ? decl : null;
        }
        return null;
    }

    private static boolean isBlank(ClangToken t) {
        return t.getText() == null || t.getText().trim().isEmpty();
    }

    // the declaration of a line that is "<vardecl>;", null otherwise (PrintC::emitVarDeclStatement)
    private static ClangVariableDecl declOfLine(ClangLine line) {
        ClangVariableDecl decl = null;
        boolean semicolon = false;
        for (ClangToken t : line.getAllTokens()) {
            if (isBlank(t)) continue;
            ClangVariableDecl d = topDecl(t);
            if (d != null && !semicolon) {
                if (decl != null && decl != d) return null;
                decl = d;
            } else if (decl != null && !semicolon && t instanceof ClangSyntaxToken && ";".equals(t.getText())) {
                semicolon = true;
            } else {
                return null;
            }
        }
        return semicolon ? decl : null;
    }

    // the number of the canonical local declared by a line, 0 if it keeps its name
    private static int declaredLocal(ClangLine line, Map<String, String> names) {
        for (ClangToken t : line.getAllTokens()) {
            if (isLocalVariable(t)) {
                String nn = names.get(t.getText());
                return nn == null ? 0 : Integer.parseInt(nn.substring(1));
            }
        }
        return 0;
    }

    /**
     * The C text of the decompilation, as {@code DecompileResults.getDecompiledFunction().getC()}
     * prints it, with the automatic locals renamed v1, v2... and their declarations in that order.
     */
    public static String canonicalC(Function function, ClangTokenGroup markup) {
        List<ClangLine> lines = new PrettyPrinter(function, markup, null).getLines();

        List<Occurrence> occ = new ArrayList<>();
        Set<String> reserved = new HashSet<>();
        for (ClangLine line : lines) {
            for (ClangToken t : line.getAllTokens()) {
                if (isLocalVariable(t))
                    occ.add(new Occurrence(t.getText(), inDecl(t)));
                else if (isName(t))
                    reserved.add(t.getText());
            }
        }
        Map<String, String> names = canonicalNames(occ, reserved);

        // Ghidra sorts the declarations by its own names: sort each run by the new ones
        List<ClangLine> sorted = new ArrayList<>(lines);
        if (!names.isEmpty()) {
            int i = 0;
            while (i < sorted.size()) {
                int j = i;
                while (j < sorted.size() && declOfLine(sorted.get(j)) != null) j++;
                if (j == i) {
                    i++;
                    continue;
                }
                List<ClangLine> run = new ArrayList<>(sorted.subList(i, j));
                run.sort(Comparator.comparingInt(l -> declaredLocal(l, names)));
                for (int k = 0; k < run.size(); k++) sorted.set(i + k, run.get(k));
                i = j;
            }
        }

        // PrettyPrinter.print with the transformer of DecompileResults.getDecompiledFunction
        NameTransformer transformer = new IllegalCharCppTransformer();
        StringBuilder buff = new StringBuilder();
        for (ClangLine line : sorted) {
            buff.append(line.getIndentString());
            for (ClangToken token : line.getAllTokens()) {
                String text = token.getText();
                if (isLocalVariable(token) && names.containsKey(text)) {
                    buff.append(names.get(text));
                    continue;
                }
                boolean clean = isName(token) && token.getSyntaxType() != ClangToken.CONST_COLOR;
                buff.append(clean ? transformer.simplify(text) : text);
            }
            buff.append('\n');
        }
        return buff.toString();
    }

    // inside any variable declaration (also the ones nested in a block)
    private static boolean inDecl(ClangToken t) {
        for (ClangNode n = t.Parent(); n != null; n = n.Parent())
            if (n instanceof ClangVariableDecl) return true;
        return false;
    }
}
