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

import java.io.File;
import java.sql.*;
import java.util.*;

import org.diaphorang.ghidra.util.DiffSettings;

/**
 * The two databases of a diff (primary as "main", secondary attached as "diff")
 * and the queries the results choosers run against them (get_sources_diff_data,
 * get_function_row_by_ea, get_calls_graph...).
 */
public final class DiffDatabases {

    private final File primary;
    private final File secondary;

    public DiffDatabases(File primary, File secondary) {
        this.primary = primary;
        this.secondary = secondary;
    }

    public File getPrimary() {
        return primary;
    }

    public File getSecondary() {
        return secondary;
    }

    public Connection open() throws SQLException {
        return GraphDiff.openDiff(primary, secondary);
    }

    /** A row as column name -> value (strings, as Diaphora's sqlite rows are used). */
    public static Map<String, String> readRow(ResultSet rs) throws SQLException {
        ResultSetMetaData md = rs.getMetaData();
        Map<String, String> row = new LinkedHashMap<>();
        for (int i = 1; i <= md.getColumnCount(); i++) {
            row.put(md.getColumnLabel(i), rs.getString(i));
        }
        return row;
    }

    public List<Map<String, String>> query(String sql, Object... args) throws SQLException {
        try (Connection conn = open()) {
            return query(conn, sql, args);
        }
    }

    public static List<Map<String, String>> query(Connection conn, String sql, Object... args) throws SQLException {
        List<Map<String, String>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < args.length; i++) {
                ps.setObject(i + 1, args[i]);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.add(readRow(rs));
                }
            }
        }
        return rows;
    }

    /**
     * get_sources_diff_data(): the rows (prototype, field, name) of both functions,
     * or null if either side lacks the field.
     */
    public List<Map<String, String>> getSourcesDiffData(String ea1, String ea2, String field) throws SQLException {
        String sql = "select * " +
                     "  from (select prototype, " + field + ", name, 1 as side " +
                     "          from functions " +
                     "         where address = ? " +
                     "           and " + field + " is not null " +
                     "         union " +
                     "        select prototype, " + field + ", name, 2 as side " +
                     "          from diff.functions " +
                     "         where address = ? " +
                     "           and " + field + " is not null) " +
                     " order by side asc";
        List<Map<String, String>> rows = query(sql, ea1, ea2);
        return rows.size() == 2 ? rows : null;
    }

    /**
     * Diaphora-ng: the image base of a database ("main" or "diff"), from the
     * address and RVA of one of its functions; 0 if unknown.
     */
    public long imageBase(String db, String ea) {
        try {
            List<Map<String, String>> rows = query("select cast(address as integer) - cast(rva as integer) base " +
                "from " + db + ".functions where address = ? and rva is not null", ea);
            String v = rows.isEmpty() ? null : rows.get(0).get("base");
            return v != null ? Long.parseLong(v) : 0;
        } catch (SQLException | NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Diaphora-ng: whether database 'db' ("main" or "diff") was exported with the
     * locals named v1, v2... (level 1, util/DiffSettings); true if unknown.
     */
    public boolean canonicalNames(String db) {
        try (Connection conn = open()) {
            return DiffSettings.exportedCanonical(conn, db);
        } catch (SQLException e) {
            return true;
        }
    }

    /** get_function_row_by_ea() */
    public Map<String, String> getFunctionRowByEa(String ea, String db) throws SQLException {
        List<Map<String, String>> rows = query("select * from " + db + ".functions where address = ?", ea);
        return rows.isEmpty() ? null : rows.get(0);
    }

    /** get_calls_graph(): callers or callees ("caller"/"callee") of the function @name. */
    public List<Map<String, String>> getCallsGraph(String name, String type, String db) throws SQLException {
        String sql = "select cg.type type, f2.address ea1, f2.name name1, " +
                     "       f1.address ea2, f1.name name2 " +
                     "  from " + db + ".callgraph cg, " +
                     "       " + db + ".functions f1, " +
                     "       " + db + ".functions f2 " +
                     " where f1.name = ? " +
                     "   and cg.func_id = f1.id " +
                     "   and cg.type = ? " +
                     "   and f2.address = cg.address ";
        return query(sql, name, type);
    }

    /** The functions of the secondary database, for the manual match chooser (CBasicChooser). */
    public List<Map<String, String>> getDiffFunctions() throws SQLException {
        return query("select cast(id as text) id, name, address from diff.functions order by id");
    }

    /** Decimal address as stored by Diaphora, from the hexadecimal one shown in the UI. */
    public static String toDecimal(String addr) {
        if (addr == null || addr.isEmpty()) return addr;
        String s = addr.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.toUnsignedString(Long.parseUnsignedLong(s.substring(2), 16));
        }
        return s;
    }

    /** Hexadecimal address shown in the UI, from the decimal one stored by Diaphora. */
    public static String toHex(String ea) {
        if (ea == null || ea.isEmpty()) return "";
        if (ea.startsWith("0x") || ea.startsWith("0X")) return ea;
        try {
            return "0x" + Long.toHexString(Long.parseUnsignedLong(ea.trim()));
        } catch (NumberFormatException e) {
            return ea;
        }
    }
}
