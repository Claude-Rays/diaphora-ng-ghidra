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
package org.diaphorang.ghidra.ui;

import docking.widgets.OptionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import org.diaphorang.ghidra.claude.ClaudeDiff;
import org.diaphorang.ghidra.diff.DiffDatabases;
import org.diaphorang.ghidra.model.MatchItem;

import java.awt.Component;
import java.io.File;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

/**
 * Diaphora-ng: the "Claude diff pseudo-code" commands of the results. Not in
 * the Python version. Version A is the open program, version B comes from the
 * secondary database. The view does not navigate.
 */
public final class ClaudeDiffCommands {

    /** Whether the open program is the new version, asked once per results (null: not asked yet). */
    private Boolean aIsNew;

    /** Forget the orientation (new results). */
    public void reset() {
        aIsNew = null;
    }

    /** The orientation, asked now if needed or 'askAgain'; null if cancelled. */
    public Boolean orientation(Component parent, MatchItem item, File diffDb, boolean askAgain) {
        if (aIsNew == null || askAgain) {
            String other = diffDb != null ? diffDb.getName() : "the other database";
            int r = OptionDialog.showYesNoCancelDialog(parent, "Claude diff pseudo-code",
                "<html>Is the open program the <b>NEW</b> version (after the patch)?<br><br>" +
                "Yes: the open program (" + escape(item.getName1()) + ") is NEW and the other database (" +
                escape(other) + ") is OLD.<br>" +
                "No: the open program is OLD and the other database is NEW.<br><br>" +
                "The answer is kept for these results (<i>Set the new version for Claude...</i> changes it).");
            if (r == OptionDialog.CANCEL_OPTION) {
                return null;
            }
            aIsNew = r == OptionDialog.YES_OPTION;
        }
        return aIsNew;
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * WIL diagnostics carry the source line number, which moves whenever the
     * source file changes: wil::details::in1diag3::Return_Hr(_ReturnAddress(),
     * 0x339, "file.cxx", hr). It is masked for the comparison, so those lines
     * only count as changed when something else changed.
     */
    public static String normalizeWil(String line) {
        int from = line.indexOf("_ReturnAddress()");
        if (from >= 0) {
            from += "_ReturnAddress()".length();
        } else {
            int d = line.indexOf("in1diag");
            if (d < 0) {
                return line;
            }
            from = line.indexOf('(', d);
            if (from < 0) {
                return line;
            }
        }
        // the first number after it
        for (int i = from; i < line.length(); i++) {
            if (!Character.isDigit(line.charAt(i))) {
                continue;
            }
            char p = i > 0 ? line.charAt(i - 1) : ' ';
            if (Character.isLetterOrDigit(p) || p == '_') {
                return line;    // part of an identifier: not the argument we want
            }
            int e = i;
            while (e < line.length() && (Character.digit(line.charAt(e), 16) >= 0 || line.charAt(e) == 'x'
                || line.charAt(e) == 'X')) {
                e++;
            }
            return line.substring(0, i) + "#" + line.substring(e);
        }
        return line;
    }

    /**
     * "public: virtual long CZoneIdentifier::Load(unsigned short const *,unsigned
     * long)" -> "CZoneIdentifier::Load": without the arguments, the access, the
     * storage class and the return type.
     */
    public static String shortFuncName(String name) {
        if (name == null) {
            return "";
        }
        int p = name.indexOf('(');
        String s = p >= 0 ? name.substring(0, p) : name;
        int depth = 0;
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') {
                depth++;
            } else if (c == '>') {
                depth--;
            } else if (c == ' ' && depth == 0 && i + 1 < s.length()) {
                start = i + 1;
            }
        }
        String out = s.substring(start).trim();
        return out.isEmpty() ? name : out;
    }

    private static String addressList(List<String> v) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < v.size() && i < 6; i++) {
            out.append(i == 0 ? "" : ", ").append(v.get(i));
        }
        if (v.size() > 6) {
            out.append(" (+").append(v.size() - 6).append(")");
        }
        return out.length() == 0 ? "-" : out.toString();
    }

    /** The header of the view (the "// ..." notes of show_claude_pseudo_diff()). */
    static List<DiaphoraNote> notes(ClaudeDiff.Result d, String nameOld, String nameNew, boolean aIsNew) {
        List<DiaphoraNote> n = new ArrayList<>();
        String model = d.model;
        if (!d.modelId.isEmpty() && !d.modelId.equals(d.model)) {
            model += " -> " + d.modelId;
        }
        if (!d.effort.isEmpty()) {
            model += ", effort " + d.effort;
        }
        n.add(DiaphoraNote.comment(String.format("Claude diff pseudo-code: OLD = %s (%s), NEW = %s (%s)",
            nameOld, aIsNew ? "other database" : "open program", nameNew, aIsNew ? "open program" : "other database")));
        n.add(DiaphoraNote.comment("The diff ignores the source line numbers of the WIL diagnostics (Return_Hr, " +
            "Log_Hr...): they move whenever the source file changes."));
        n.add(DiaphoraNote.comment(String.format("Claude-Rays Decompiler: C reconstructed by Claude (%s, %s) from " +
            "the two disassemblies%s. Plausible, not proven: check it against the listings.",
            model, d.date, d.cached ? ", from the cache" : "")));
        if (d.inputTokens > 0 || d.outputTokens > 0) {
            n.add(DiaphoraNote.comment(String.format("Usage: %d input / %d output tokens, $%.4f at API prices " +
                "(on a subscription it counts against the plan usage).", d.inputTokens, d.outputTokens, d.costUsd)));
        }
        n.add(DiaphoraNote.macro(String.format("ASSESSMENT (a hypothesis): security relevant: %s, class: %s, " +
            "confidence: %s", d.securityRelevant, d.fixClass, d.confidence)));
        if (!d.reasoning.isEmpty()) {
            n.add(DiaphoraNote.macro("  " + d.reasoning));
        }
        for (String f : d.followUp) {
            n.add(DiaphoraNote.macro("  Follow up: " + f));
        }
        n.add(DiaphoraNote.comment(d.changes.isEmpty() ? "CHANGES: none reported."
            : "CHANGES (" + d.changes.size() + "):"));
        for (int i = 0; i < d.changes.size(); i++) {
            ClaudeDiff.Change c = d.changes.get(i);
            n.add(DiaphoraNote.comment(String.format("  %d. [%s] %s (old: %s; new: %s)", i + 1, c.kind,
                c.description, addressList(c.oldAddresses), addressList(c.newAddresses))));
        }
        for (String w : d.warnings) {
            n.add(DiaphoraNote.error("WARNING: " + w));
        }
        for (String w : d.notes) {
            n.add(DiaphoraNote.error("NOTE: " + w));
        }
        for (ClaudeDiff.Uncertain u : d.oldSide.uncertain) {
            n.add(DiaphoraNote.macro("UNCERTAIN old " + u.address() + ": " + u.reason()));
        }
        for (ClaudeDiff.Uncertain u : d.newSide.uncertain) {
            n.add(DiaphoraNote.macro("UNCERTAIN new " + u.address() + ": " + u.reason()));
        }
        if (!d.oldSide.summary.isEmpty()) {
            n.add(DiaphoraNote.comment("OLD: " + d.oldSide.summary));
        }
        if (!d.newSide.summary.isEmpty()) {
            n.add(DiaphoraNote.comment("NEW: " + d.newSide.summary));
        }
        return n;
    }

    /**
     * show_claude_pseudo_diff(): side by side ('html') or patch; 'force' asks
     * Claude again instead of using the cache. From the Swing thread:
     * Claude-Rays Decompiler shows its modal task dialog while it runs.
     */
    public void show(PluginTool tool, Program program, Component parent, DiffDatabases dbs, MatchItem item,
                     boolean html, boolean force) throws Exception {
        if (program == null) {
            Msg.showWarn(this, parent, "Diaphora-ng", "Claude diff pseudo-code needs the program of the primary " +
                "database open in this tool: Claude-Rays Decompiler reads that version from Ghidra.");
            return;
        }
        String why = ClaudeDiff.unavailableReason(tool);
        if (why != null) {
            Msg.showWarn(this, parent, "Diaphora-ng", "Claude diff pseudo-code: " + why);
            return;
        }
        Boolean isNew = orientation(parent, item, dbs.getSecondary(), false);
        if (isNew == null) {
            return;
        }
        ClaudeDiff.Result d;
        try (Connection conn = dbs.open()) {
            d = ClaudeDiff.run(tool, program, conn, DiffDatabases.toDecimal(item.getAddress1()),
                DiffDatabases.toDecimal(item.getAddress2()), isNew, force, dbs.getSecondary());
        } catch (IllegalStateException e) {
            if ("cancelled".equals(e.getMessage())) {
                Msg.info(this, "Diaphora-ng: Claude diff cancelled.");
            } else {
                Msg.showWarn(this, parent, "Diaphora-ng", "Claude diff pseudo-code: " + e.getMessage());
            }
            return;
        }

        String nameOld = shortFuncName(isNew ? item.getName2() : item.getName1());
        String nameNew = shortFuncName(isNew ? item.getName1() : item.getName2());
        List<DiaphoraNote> header = notes(d, nameOld, nameNew, isNew);
        String oldCode = String.join("\n", d.oldSide.text());
        String newCode = String.join("\n", d.newSide.text());
        String title = "Claude diff pseudo-code " + nameOld + " - " + nameNew;
        if (html) {
            tool.showDialog(new DiaphoraDiffDialog(title, oldCode, newCode, ClaudeDiffCommands::normalizeWil, header));
        } else {
            tool.showDialog(DiaphoraTextDialog.unifiedDiff("Patch: " + title, oldCode, newCode,
                ClaudeDiffCommands::normalizeWil, header));
        }
    }
}
