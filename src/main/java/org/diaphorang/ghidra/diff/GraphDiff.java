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
package org.diaphorang.ghidra.diff;

import org.diaphorang.ghidra.util.TextCleaner;

import java.io.File;
import java.sql.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Basic block level comparison of two matched functions, port of
 * compare_graphs() / compare_graphs_pass() (diaphora.py, diaphora-idafree).
 *
 * Every basic block starts as "none" (new or deleted), then blocks with the same
 * cleaned assembly are marked "perfect" and blocks with the same mnemonics but
 * different operands are marked "partial".
 */
public final class GraphDiff {

    public enum BlockMatch { PERFECT, PARTIAL, NONE }

    /** Result of the comparison: basic block start address (decimal, as in the database) -> match. */
    public static final class Result {
        public final Map<String, BlockMatch> primary = new LinkedHashMap<>();
        public final Map<String, BlockMatch> secondary = new LinkedHashMap<>();
    }

    /** Addresses printed by Ghidra in the listing (not replaced by labels). */
    private static final Pattern RAW_ADDRESS = Pattern.compile("0x[0-9a-fA-F]{7,16}\\b");

    private static final class Ins {
        final String ea;
        final String mnem;
        final String disasm;
        final String cmpAsm;

        Ins(String ea, String mnem, String disasm) {
            this.ea = ea;
            this.mnem = mnem;
            this.disasm = disasm != null ? disasm : "";
            String s = TextCleaner.getCmpAsm(this.disasm);
            this.cmpAsm = RAW_ADDRESS.matcher(s).replaceAll("0xXXXX");
        }
    }

    /**
     * Basic blocks of a function as returned by get_graph(): blocks in address
     * order with their instructions, and the relations between blocks.
     */
    public static final class Graph {
        final List<String> order = new ArrayList<>();
        final Map<String, List<Ins>> blocks = new HashMap<>();
        final List<String> relOrder = new ArrayList<>();
        final Map<String, TreeSet<String>> relations = new HashMap<>();

        public boolean isEmpty() {
            return blocks.isEmpty();
        }

        /** Basic block addresses (decimal, as in the database), in address order. */
        public List<String> getBlockOrder() {
            return Collections.unmodifiableList(order);
        }

        /** Disassembly lines of a basic block. */
        public List<String> getBlockText(String bbEa) {
            List<String> lines = new ArrayList<>();
            for (Ins ins : blocks.getOrDefault(bbEa, List.of())) {
                lines.add(ins.disasm);
            }
            return lines;
        }

        /** Parents with children, in the order of the bb_relations query. */
        public List<String> getRelationOrder() {
            return Collections.unmodifiableList(relOrder);
        }

        public Set<String> getChildren(String bbEa) {
            return relations.getOrDefault(bbEa, new TreeSet<>());
        }
    }

    private GraphDiff() {}

    /** Open the primary database with the secondary one attached as "diff". */
    public static Connection openDiff(File primaryDb, File secondaryDb) throws SQLException {
        // A null primary database is an in-memory one (import_definitions_only)
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" +
            (primaryDb != null ? primaryDb.getAbsolutePath() : ":memory:"));
        try (Statement st = conn.createStatement()) {
            st.execute("ATTACH DATABASE '" + secondaryDb.getAbsolutePath().replace("'", "''") + "' AS diff");
        }
        return conn;
    }

    /**
     * @param ea1 decimal address of the function in the primary database
     * @param ea2 decimal address of the function in the secondary database
     */
    public static Result compare(File primaryDb, File secondaryDb, String ea1, String ea2) throws SQLException {
        Graph g1;
        Graph g2;
        try (Connection conn = openDiff(primaryDb, secondaryDb)) {
            g1 = getGraph(conn, "main", ea1);
            g2 = getGraph(conn, "diff", ea2);
        }
        return compare(g1, g2);
    }

    /** compare_graphs(): the colour of every basic block of both graphs. */
    public static Result compare(Graph g1, Graph g2) {
        Result result = new Result();
        // Consider, by default, all blocks added (new)
        for (String k : g1.order) result.primary.put(k, BlockMatch.NONE);
        for (String k : g2.order) result.secondary.put(k, BlockMatch.NONE);
        comparePass(g1, g2, result, false);
        comparePass(g1, g2, result, true);
        return result;
    }

    /** get_graph(): basic blocks, instructions and relations of the native assembly graph. */
    public static Graph getGraph(Connection conn, String db, String ea) throws SQLException {
        String sql = "select bb.address bb_address, ins.address ins_address, ins.mnemonic ins_mnem, " +
                     "       ins.disasm ins_disasm " +
                     "  from " + db + ".instructions ins, " + db + ".bb_instructions bbins, " +
                     "       " + db + ".basic_blocks bb, " + db + ".function_bblocks fb, " + db + ".functions f " +
                     " where ins.id = bbins.instruction_id " +
                     "   and bbins.basic_block_id = bb.id " +
                     "   and bb.id = fb.basic_block_id " +
                     "   and f.id = fb.function_id " +
                     "   and (bb.asm_type = 'native' or bb.asm_type is null) " +
                     "   and f.address = ? " +
                     "   and ins.address is not null " +
                     " order by cast(bb.address as integer) asc, cast(ins.address as integer) asc";
        Graph g = new Graph();
        Set<String> dones = new HashSet<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ea);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String bbEa = rs.getString("bb_address");
                    String insEa = rs.getString("ins_address");
                    if (!dones.add(insEa)) continue;
                    List<Ins> block = g.blocks.get(bbEa);
                    if (block == null) {
                        block = new ArrayList<>();
                        g.blocks.put(bbEa, block);
                        g.order.add(bbEa);
                    }
                    block.add(new Ins(insEa, rs.getString("ins_mnem"), rs.getString("ins_disasm")));
                }
            }
        }

        sql = "select (select address from " + db + ".basic_blocks where id = bbr.parent_id) ea1, " +
              "       (select address from " + db + ".basic_blocks where id = bbr.child_id) ea2 " +
              "  from " + db + ".bb_relations bbr, " + db + ".function_bblocks fbs, " +
              "       " + db + ".basic_blocks bbs, " + db + ".functions f " +
              " where f.id = fbs.function_id " +
              "   and bbs.id = fbs.basic_block_id " +
              "   and fbs.basic_block_id = bbr.child_id " +
              "   and f.address = ? " +
              "   and (fbs.asm_type = 'native' or fbs.asm_type is null) " +
              " order by 1 asc, 2 asc";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ea);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String bb1 = rs.getString("ea1");
                    String bb2 = rs.getString("ea2");
                    if (bb1 == null || bb2 == null) continue;
                    TreeSet<String> children = g.relations.get(bb1);
                    if (children == null) {
                        children = new TreeSet<>();
                        g.relations.put(bb1, children);
                        g.relOrder.add(bb1);
                    }
                    children.add(bb2);
                }
            }
        }
        return g;
    }

    private static void comparePass(Graph g1, Graph g2, Result result, boolean isSecond) {
        Set<String> dones1 = new HashSet<>();
        Set<String> dones2 = new HashSet<>();
        for (String key1 : g1.order) {
            if (dones1.contains(key1)) continue;
            List<Ins> b1 = g1.blocks.get(key1);
            for (String key2 : g2.order) {
                if (dones2.contains(key2)) continue;
                List<Ins> b2 = g2.blocks.get(key2);
                // Same number of instructions?
                if (b1.size() != b2.size()) continue;

                boolean mod = false;
                boolean partial = true;
                int i = 0;
                for (Ins ins1 : b1) {
                    Ins ins2 = b2.get(Math.min(i, b2.size() - 1));
                    // Same mnemonic? The change can be only partial
                    if (!Objects.equals(ins1.mnem, ins2.mnem)) {
                        partial = false;
                    }
                    // Compare the assembly after doing some cleaning
                    if (!ins1.cmpAsm.equals(ins2.cmpAsm)) {
                        mod = true;
                        if (!partial) continue;
                    }
                    i++;
                }

                if (!mod) {
                    // Perfect match, a basic block equal in both functions
                    result.primary.put(key1, BlockMatch.PERFECT);
                    result.secondary.put(key2, BlockMatch.PERFECT);
                    dones1.add(key1);
                    dones2.add(key2);
                    break;
                } else if (!isSecond && partial) {
                    // Partial match, same mnemonics but something changed. Not added
                    // to the dones lists: there can be complete matches later.
                    result.primary.put(key1, BlockMatch.PARTIAL);
                    result.secondary.put(key2, BlockMatch.PARTIAL);
                    break;
                }
            }
        }
    }
}
