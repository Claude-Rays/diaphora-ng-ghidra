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
package org.diaphorang.ghidra.claude;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import org.diaphorang.ghidra.util.SideBySideDiff;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Diaphora-ng - "Claude diff pseudo-code": the request to Claude-Rays
 * Decompiler for Ghidra (the other version, from its SQLite, and the assembly
 * diff) and its response. Not in the Python version.
 *
 * <p>The connection is Diaphora's: the primary database as "main" with the
 * secondary one attached as "diff" (GraphDiff.openDiff). Addresses are the
 * decimal strings stored by Diaphora; instructions and basic blocks are RVAs.
 */
public final class ClaudeDiff {

    public static final int CLAUDERAYS_API_VERSION = 1;

    private ClaudeDiff() {
    }

    /** One line of shaped code, without address annotations. */
    public record Line(String text, String address) {
    }

    public record Uncertain(String address, String reason) {
    }

    public static final class Side {
        public String summary = "";
        public String prototype = "";
        public final List<Line> lines = new ArrayList<>();
        public final List<Uncertain> uncertain = new ArrayList<>();

        /** The code as the diff views compare it. */
        public List<String> text() {
            List<String> out = new ArrayList<>();
            for (Line l : lines) {
                out.add(l.text());
            }
            return out;
        }
    }

    public static final class Change {
        /** added, removed, modified, compiler */
        public String kind = "";
        public final List<String> oldAddresses = new ArrayList<>();
        public final List<String> newAddresses = new ArrayList<>();
        public String description = "";
    }

    public static final class Result {
        public final Side oldSide = new Side();
        public final Side newSide = new Side();
        public final List<Change> changes = new ArrayList<>();
        /** likely, possible, unlikely */
        public String securityRelevant = "";
        public String fixClass = "";
        public String reasoning = "";
        public String confidence = "";
        public final List<String> followUp = new ArrayList<>();
        /** validator, "old:" / "new:" prefixes */
        public final List<String> warnings = new ArrayList<>();
        /** about the data Diaphora could send */
        public final List<String> notes = new ArrayList<>();
        public String model = "";
        public String modelId = "";
        public String effort = "";
        public String date = "";
        public long inputTokens;
        public long outputTokens;
        public double costUsd;
        public boolean cached;
    }

    /**
     * Claude-Rays Decompiler is installed, enabled and has a compatible API; otherwise
     * the reason. Adds its plugin to the tool if needed.
     */
    public static String unavailableReason(PluginTool tool) {
        int v = ClaudeRaysLink.version(tool, true);
        if (v < 0) {
            return ClaudeRaysLink.installed()
                ? "Claude-Rays Decompiler for Ghidra is installed but its plugin (ClaudeRaysPlugin) is not enabled in this tool: "
                    + "File > Configure > Analysis."
                : "Claude-Rays Decompiler for Ghidra is not installed: File > Install Extensions in the Ghidra project window.";
        }
        if (v != CLAUDERAYS_API_VERSION) {
            return v == 0
                ? "the installed Claude-Rays Decompiler for Ghidra is too old: it has no API for Diaphora-ng."
                : "the installed Claude-Rays Decompiler for Ghidra has the API version " + v + ", Diaphora-ng needs "
                    + CLAUDERAYS_API_VERSION + ".";
        }
        return null;
    }

    //--------------------------------------------------------------------------
    // SQL helpers (strings, as Diaphora's rows are used)
    //--------------------------------------------------------------------------
    static List<Map<String, String>> query(Connection conn, String sql, Object... args) throws SQLException {
        List<Map<String, String>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) {
                ps.setObject(i + 1, args[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                ResultSetMetaData md = rs.getMetaData();
                while (rs.next()) {
                    Map<String, String> row = new LinkedHashMap<>();
                    for (int i = 1; i <= md.getColumnCount(); i++) {
                        row.put(md.getColumnLabel(i), rs.getString(i));
                    }
                    rows.add(row);
                }
            }
        }
        return rows;
    }

    static String str(Map<String, String> row, String key) {
        String v = row != null ? row.get(key) : null;
        return v != null ? v : "";
    }

    static long num(String s) {
        try {
            return s == null || s.isBlank() ? 0 : Long.parseLong(s.trim());
        }
        catch (NumberFormatException e) {
            return (long) Double.parseDouble(s.trim());
        }
    }

    static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    /**
     * The absolute address of an instruction or basic block: Diaphora stores RVAs
     * (diaphora_ida.py, current diaphora-ghidra), older diaphora-ghidra exports
     * stored absolute addresses; both are accepted.
     */
    static long absolute(long base, long v) {
        return base != 0 && Long.compareUnsigned(v, base) >= 0 ? v : base + v;
    }

    //--------------------------------------------------------------------------
    // the request: version B from the diff database
    //--------------------------------------------------------------------------
    /** The short demangled name, without arguments ("" if not mangled). */
    static String demangledShort(Program program, String name) {
        if (name == null || name.isEmpty() || !(name.startsWith("?") || name.startsWith("_Z"))) {
            return "";
        }
        try {
            List<DemangledObject> all = DemanglerUtil.demangle(program, name, null);
            DemangledObject d = all == null || all.isEmpty() ? null : all.get(0);
            if (d == null) {
                return "";
            }
            String s = d.getNamespaceString();
            if (s == null || s.isEmpty()) {
                s = d.getName();
            }
            int p = s.indexOf('(');
            return p >= 0 ? s.substring(0, p) : s;
        }
        catch (Exception | LinkageError e) {
            // no demangler (outside a running Ghidra): the name as it is
            return "";
        }
    }

    private static JsonObject lineJson(long base, long rva, String text, Map<Long, String> comments) {
        JsonObject l = new JsonObject();
        l.addProperty("address", hex(absolute(base, rva)));
        l.addProperty("text", text != null ? text : "");
        l.addProperty("comment", comments.getOrDefault(rva, ""));
        return l;
    }

    /**
     * [{address, succs, lines: [{address, text, comment}]}] from the exported basic
     * blocks; from the plain assembly if the blocks were not exported
     * (function_summaries_only): noBlocks[0] tells which.
     */
    static JsonArray sideBBlocks(Connection conn, Map<String, String> row, long base, boolean[] noBlocks)
        throws SQLException {
        String ea2 = str(row, "address");

        // the instruction comments
        Map<Long, String> comments = new HashMap<>();
        for (Map<String, String> r : query(conn, "select address, comment1, comment2 from diff.instructions "
            + "where func_id = (select id from diff.functions where address = ?) "
            + "and (asm_type = 'native' or asm_type is null)", ea2)) {
            String c = str(r, "comment1");
            String c2 = str(r, "comment2");
            if (!c2.isEmpty() && !c2.equals(c)) {
                c += (c.isEmpty() ? "" : " / ") + c2;
            }
            if (!c.isEmpty() && r.get("address") != null) {
                comments.put(num(r.get("address")), c);
            }
        }

        // get_graph(): blocks with their instructions, and the relations
        Map<Long, List<long[]>> blockInsns = new TreeMap<>();
        Map<Long, String> disasm = new HashMap<>();
        for (Map<String, String> r : query(conn, "select bb.address bb_address, ins.address ins_address, "
            + "ins.disasm ins_disasm "
            + "from diff.instructions ins, diff.bb_instructions bbins, diff.basic_blocks bb, "
            + "diff.function_bblocks fb, diff.functions f "
            + "where ins.id = bbins.instruction_id and bbins.basic_block_id = bb.id and bb.id = fb.basic_block_id "
            + "and f.id = fb.function_id and (bb.asm_type = 'native' or bb.asm_type is null) "
            + "and f.address = ? and ins.address is not null "
            + "order by cast(bb.address as integer) asc, cast(ins.address as integer) asc", ea2)) {
            long bb = num(r.get("bb_address"));
            long ins = num(r.get("ins_address"));
            if (disasm.containsKey(ins)) {
                continue;
            }
            disasm.put(ins, str(r, "ins_disasm"));
            blockInsns.computeIfAbsent(bb, k -> new ArrayList<>()).add(new long[]{ins});
        }
        Map<Long, TreeSet<Long>> relations = new HashMap<>();
        for (Map<String, String> r : query(conn, "select (select address from diff.basic_blocks where id = bbr.parent_id) ea1, "
            + "(select address from diff.basic_blocks where id = bbr.child_id) ea2 "
            + "from diff.bb_relations bbr, diff.function_bblocks fbs, diff.basic_blocks bbs, diff.functions f "
            + "where f.id = fbs.function_id and bbs.id = fbs.basic_block_id and fbs.basic_block_id = bbr.child_id "
            + "and f.address = ? and (fbs.asm_type = 'native' or fbs.asm_type is null) order by 1 asc, 2 asc", ea2)) {
            if (r.get("ea1") == null || r.get("ea2") == null) {
                continue;
            }
            relations.computeIfAbsent(num(r.get("ea1")), k -> new TreeSet<>()).add(num(r.get("ea2")));
        }

        JsonArray out = new JsonArray();
        if (!blockInsns.isEmpty()) {
            noBlocks[0] = false;
            for (Map.Entry<Long, List<long[]>> e : blockInsns.entrySet()) {
                JsonObject b = new JsonObject();
                b.addProperty("address", hex(absolute(base, e.getKey())));
                JsonArray succs = new JsonArray();
                for (long s : relations.getOrDefault(e.getKey(), new TreeSet<>())) {
                    succs.add(hex(absolute(base, s)));
                }
                b.add("succs", succs);
                JsonArray lines = new JsonArray();
                for (long[] ins : e.getValue()) {
                    lines.add(lineJson(base, ins[0], disasm.get(ins[0]), comments));
                }
                b.add("lines", lines);
                out.add(b);
            }
            return out;
        }

        // function_summaries_only: one pseudo block with the assembly in order
        noBlocks[0] = true;
        List<String> asmLines = Arrays.asList(str(row, "assembly").split("\n", -1));
        List<Long> rvas = new ArrayList<>();
        try {
            JsonElement addrs = JsonParser.parseString(str(row, "assembly_addrs"));
            if (addrs.isJsonArray()) {
                for (JsonElement a : addrs.getAsJsonArray()) {
                    rvas.add(num(a.getAsString()));
                }
            }
        }
        catch (RuntimeException e) {
            // no addresses: no listing
        }
        JsonArray lines = new JsonArray();
        for (int i = 0; i < asmLines.size() && i < rvas.size(); i++) {
            lines.add(lineJson(base, rvas.get(i), asmLines.get(i), comments));
        }
        JsonObject b = new JsonObject();
        b.addProperty("address", rvas.isEmpty() ? hex(num(ea2)) : hex(absolute(base, rvas.get(0))));
        b.add("succs", new JsonArray());
        b.add("lines", lines);
        out.add(b);
        return out;
    }

    static JsonArray sideBCalls(Connection conn, String ea2) throws SQLException {
        JsonArray out = new JsonArray();
        for (Map<String, String> r : query(conn, "select f.address address, f.name name, f.prototype prototype "
            + "from diff.callgraph c, diff.functions f "
            + "where c.func_id = (select id from diff.functions where address = ?) and c.type = 'callee' "
            + "and cast(f.address as integer) = cast(c.address as integer) order by c.id", ea2)) {
            JsonObject c = new JsonObject();
            c.addProperty("address", hex(num(r.get("address"))));
            c.addProperty("name", str(r, "name"));
            c.addProperty("prototype", str(r, "prototype"));
            out.add(c);
        }
        return out;
    }

    /** The hunks of the diff of the cleaned assembly (no addresses), OLD -> NEW. */
    static JsonArray asmDiff(String oldAsm, String newAsm) {
        List<String> lines = SideBySideDiff.unifiedDiff(Arrays.asList(oldAsm.split("\n", -1)),
            Arrays.asList(newAsm.split("\n", -1)));
        JsonArray out = new JsonArray();
        // the first two lines are the file headers
        for (int i = 2; i < lines.size(); i++) {
            String l = lines.get(i);
            while (l.endsWith("\n")) {
                l = l.substring(0, l.length() - 1);
            }
            out.add(l);
        }
        return out;
    }

    /**
     * The request for the match ea1 (main) / ea2 (diff), decimal addresses as
     * Diaphora stores them. 'aIsNew': the open program is the new version;
     * 'diffDb' names the other database in the prompt; 'program' (the open
     * one, may be null) only helps the demangler.
     */
    public static String buildRequest(Program program, Connection conn, String ea1, String ea2, boolean aIsNew,
                                      boolean force, File diffDb, List<String> notes) throws SQLException {
        List<Map<String, String>> rows2 = query(conn, "select name, address, rva, prototype, comment, "
            + "mangled_function, bytes_hash, assembly, assembly_addrs, clean_assembly, constants "
            + "from diff.functions where address = ?", ea2);
        if (rows2.isEmpty()) {
            throw new IllegalArgumentException("the function " + hex(num(ea2)) + " is not in the diff database.");
        }
        Map<String, String> row2 = rows2.get(0);
        List<Map<String, String>> rows1 = query(conn, "select clean_assembly from main.functions where address = ?", ea1);
        String clean1 = rows1.isEmpty() ? "" : str(rows1.get(0), "clean_assembly");
        String clean2 = str(row2, "clean_assembly");
        if (clean1.isEmpty() || clean2.isEmpty()) {
            notes.add("no cleaned assembly for one of the versions: the model got no assembly diff.");
        }

        long address = num(row2.get("address"));
        long base = row2.get("rva") == null ? 0 : address - num(row2.get("rva"));
        boolean[] noBlocks = {false};
        JsonArray blocks = sideBBlocks(conn, row2, base, noBlocks);
        if (noBlocks[0]) {
            notes.add("the other database has no basic blocks (exported with 'function summaries only'): "
                + "its version was sent as plain assembly.");
        }

        String name = str(row2, "name");
        String mangled = str(row2, "mangled_function");
        String demangled = demangledShort(program, mangled.isEmpty() ? name : mangled);
        JsonArray consts = new JsonArray();
        try {
            JsonElement jc = JsonParser.parseString(str(row2, "constants"));
            if (jc.isJsonArray()) {
                for (JsonElement c : jc.getAsJsonArray()) {
                    consts.add(c.isJsonPrimitive() ? c.getAsString() : c.toString());
                }
            }
        }
        catch (RuntimeException e) {
            // no constants
        }

        JsonObject b = new JsonObject();
        b.addProperty("name", mangled.isEmpty() ? name : mangled);
        b.addProperty("demangled", demangled.isEmpty() ? name : demangled);
        b.addProperty("prototype", str(row2, "prototype"));
        b.addProperty("address", hex(address));
        b.addProperty("image_base", hex(base));
        b.addProperty("bytes_hash", str(row2, "bytes_hash"));
        b.addProperty("comment", str(row2, "comment"));
        b.addProperty("no_blocks", noBlocks[0]);
        b.add("blocks", blocks);
        b.add("calls", sideBCalls(conn, str(row2, "address")));
        b.add("constants", consts);
        b.addProperty("source", "diaphora-ng:" + (diffDb != null ? diffDb.getName() : "the other database"));

        JsonObject a = new JsonObject();
        a.addProperty("ea", hex(num(ea1)));
        JsonObject req = new JsonObject();
        req.add("a", a);
        req.add("b", b);
        req.addProperty("a_is_new", aIsNew);
        req.add("asm_diff", asmDiff(aIsNew ? clean2 : clean1, aIsNew ? clean1 : clean2));
        req.addProperty("force", force);
        return req.toString();
    }

    //--------------------------------------------------------------------------
    // the response
    //--------------------------------------------------------------------------
    private static String s(JsonObject j, String key) {
        JsonElement v = j != null ? j.get(key) : null;
        return v == null || v.isJsonNull() ? "" : v.isJsonPrimitive() ? v.getAsString() : v.toString();
    }

    private static List<String> list(JsonObject j, String key) {
        List<String> out = new ArrayList<>();
        JsonElement v = j != null ? j.get(key) : null;
        if (v != null && v.isJsonArray()) {
            for (JsonElement x : v.getAsJsonArray()) {
                out.add(x.isJsonPrimitive() ? x.getAsString() : x.toString());
            }
        }
        return out;
    }

    private static JsonObject obj(JsonObject j, String key) {
        JsonElement v = j != null ? j.get(key) : null;
        return v != null && v.isJsonObject() ? v.getAsJsonObject() : null;
    }

    private static void decodeSide(JsonObject j, Side out) {
        out.summary = s(j, "summary");
        out.prototype = s(j, "prototype");
        JsonElement lines = j != null ? j.get("lines") : null;
        if (lines != null && lines.isJsonArray()) {
            for (JsonElement l : lines.getAsJsonArray()) {
                if (l.isJsonObject()) {
                    out.lines.add(new Line(s(l.getAsJsonObject(), "text"), s(l.getAsJsonObject(), "address")));
                }
            }
        }
        JsonElement u = j != null ? j.get("uncertain") : null;
        if (u != null && u.isJsonArray()) {
            for (JsonElement x : u.getAsJsonArray()) {
                if (x.isJsonObject()) {
                    out.uncertain.add(new Uncertain(s(x.getAsJsonObject(), "address"), s(x.getAsJsonObject(), "reason")));
                }
            }
        }
    }

    /** The response of Claude-Rays Decompiler; throws IllegalStateException with its error. */
    public static Result decode(String response) {
        JsonObject j;
        try {
            JsonElement e = JsonParser.parseString(response);
            j = e.isJsonObject() ? e.getAsJsonObject() : null;
        }
        catch (RuntimeException e) {
            j = null;
        }
        if (j == null) {
            throw new IllegalStateException("the response of Claude-Rays Decompiler is not valid JSON.");
        }
        JsonElement ok = j.get("ok");
        if (ok == null || !ok.isJsonPrimitive() || !ok.getAsBoolean()) {
            String err = s(j, "error");
            throw new IllegalStateException(err.isEmpty() ? "Claude-Rays Decompiler gave no answer." : err);
        }
        Result out = new Result();
        decodeSide(obj(j, "old"), out.oldSide);
        decodeSide(obj(j, "new"), out.newSide);
        JsonElement ch = j.get("changes");
        if (ch != null && ch.isJsonArray()) {
            for (JsonElement c : ch.getAsJsonArray()) {
                if (!c.isJsonObject()) {
                    continue;
                }
                Change cc = new Change();
                cc.kind = s(c.getAsJsonObject(), "kind");
                cc.oldAddresses.addAll(list(c.getAsJsonObject(), "old_addresses"));
                cc.newAddresses.addAll(list(c.getAsJsonObject(), "new_addresses"));
                cc.description = s(c.getAsJsonObject(), "description");
                out.changes.add(cc);
            }
        }
        JsonObject as = obj(j, "assessment");
        out.securityRelevant = s(as, "security_relevant");
        out.fixClass = s(as, "class");
        out.reasoning = s(as, "reasoning");
        out.confidence = s(as, "confidence");
        out.followUp.addAll(list(as, "follow_up"));
        out.warnings.addAll(list(j, "warnings"));
        out.model = s(j, "model");
        out.modelId = s(j, "model_id");
        out.effort = s(j, "effort");
        out.date = s(j, "date");
        JsonObject u = obj(j, "usage");
        out.inputTokens = (long) Double.parseDouble(s(u, "input_tokens").isEmpty() ? "0" : s(u, "input_tokens"));
        out.outputTokens = (long) Double.parseDouble(s(u, "output_tokens").isEmpty() ? "0" : s(u, "output_tokens"));
        out.costUsd = Double.parseDouble(s(u, "cost_usd").isEmpty() ? "0" : s(u, "cost_usd"));
        JsonElement cached = j.get("cached");
        out.cached = cached != null && cached.isJsonPrimitive() && cached.getAsBoolean();
        return out;
    }

    /**
     * Run the query (Claude-Rays Decompiler shows its modal task dialog) or take it
     * from its cache. Throws IllegalStateException on failure or when cancelled
     * ("cancelled").
     */
    public static Result run(PluginTool tool, Program program, Connection conn, String ea1, String ea2,
                             boolean aIsNew, boolean force, File diffDb) throws SQLException {
        String why = unavailableReason(tool);
        if (why != null) {
            throw new IllegalStateException(why);
        }
        List<String> notes = new ArrayList<>();
        String req = buildRequest(program, conn, ea1, ea2, aIsNew, force, diffDb, notes);
        String resp = ClaudeRaysLink.diff(tool, req);
        if (resp == null) {
            throw new IllegalStateException("the call to Claude-Rays Decompiler failed.");
        }
        Result r = decode(resp);
        r.notes.addAll(notes);
        return r;
    }
}
