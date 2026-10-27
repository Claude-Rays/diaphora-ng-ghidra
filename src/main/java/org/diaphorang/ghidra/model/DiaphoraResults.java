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
package org.diaphorang.ghidra.model;

import java.io.File;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Diffing results files (*.diaphora): port of CBinDiff.save_results() and
 * CIDABinDiff.load_results() / populate_choosers(). The SQLite format is the
 * one of the original, so results can be exchanged with diaphora.py and
 * diaphora-idafree.
 *
 * Note: the python version stores the functions unmatched in the secondary
 * database with the 'primary' type (and vice versa). Kept for compatibility.
 */
public final class DiaphoraResults {

    /** Contents of the config table. */
    public static final class Config {
        public String mainDb;
        public String diffDb;
        public String version;
        public String date;
    }

    private DiaphoraResults() {}

    private static String hexEa(String addr) {
        if (addr == null || addr.isEmpty()) return "";
        String s = addr.trim();
        long v = (s.startsWith("0x") || s.startsWith("0X"))
            ? Long.parseUnsignedLong(s.substring(2), 16)
            : Long.parseUnsignedLong(s, 16);
        return String.format("%08x", v);
    }

    private static String uiAddress(String hex) {
        if (hex == null || hex.isEmpty()) return "";
        return "0x" + Long.toHexString(Long.parseUnsignedLong(hex.trim(), 16));
    }

    /** save_results() */
    public static void save(File file, Map<MatchCategory, List<MatchItem>> results,
                            String mainDb, String diffDb) throws SQLException {
        if (file.exists()) {
            file.delete();
        }
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath())) {
            try (Statement st = conn.createStatement()) {
                st.execute("create table config (main_db text, diff_db text, version text, date text)");
                st.execute("create table results (type, line, address, name, address2, name2,\n" +
                           "                   ratio, nodes1, nodes2, description)");
                st.execute("create unique index uq_results on results(address, address2)");
                st.execute("create table unmatched (type, line, address, name)");
            }
            try (PreparedStatement ps = conn.prepareStatement("insert into config values (?, ?, ?, ?)")) {
                ps.setString(1, mainDb);
                ps.setString(2, diffDb);
                ps.setString(3, DiaphoraSchema.VERSION_VALUE);
                // time.asctime()
                ps.setString(4, new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy", Locale.ENGLISH).format(new java.util.Date()));
                ps.executeUpdate();
            }

            conn.setAutoCommit(false);
            try (PreparedStatement res = conn.prepareStatement(
                     "insert or ignore into results values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                 PreparedStatement unm = conn.prepareStatement("insert into unmatched values (?, ?, ?, ?)")) {
                Object[][] cats = {
                    {"best", MatchCategory.BEST},
                    {"partial", MatchCategory.PARTIAL},
                    {"unreliable", MatchCategory.UNRELIABLE},
                    {"multimatch", MatchCategory.PROBLEMATIC},
                    {"primary", MatchCategory.UNMATCHED_SECONDARY},
                    {"secondary", MatchCategory.UNMATCHED_PRIMARY},
                };
                for (Object[] c : cats) {
                    String type = (String) c[0];
                    MatchCategory cat = (MatchCategory) c[1];
                    int line = 0;
                    for (MatchItem item : results.getOrDefault(cat, List.of())) {
                        String lineStr = String.format("%05d", line++);
                        if (cat == MatchCategory.UNMATCHED_SECONDARY) {
                            unm.setString(1, type);
                            unm.setString(2, lineStr);
                            unm.setString(3, hexEa(item.getAddress2()));
                            unm.setString(4, item.getName2());
                            unm.executeUpdate();
                        } else if (cat == MatchCategory.UNMATCHED_PRIMARY) {
                            unm.setString(1, type);
                            unm.setString(2, lineStr);
                            unm.setString(3, hexEa(item.getAddress1()));
                            unm.setString(4, item.getName1());
                            unm.executeUpdate();
                        } else {
                            res.setString(1, type);
                            res.setString(2, lineStr);
                            res.setString(3, hexEa(item.getAddress1()));
                            res.setString(4, item.getName1());
                            res.setString(5, hexEa(item.getAddress2()));
                            res.setString(6, item.getName2());
                            res.setString(7, String.format(Locale.ROOT, "%.7f", item.getRatio()));
                            res.setString(8, String.valueOf(item.getNodes1()));
                            res.setString(9, String.valueOf(item.getNodes2()));
                            res.setString(10, item.getDescription());
                            res.executeUpdate();
                        }
                    }
                }
            }
            conn.commit();
        }
    }

    /** read_results_config(): null if the file is not a results database. */
    public static Config readConfig(File file) {
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath());
             Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("select main_db, diff_db, version, date from config")) {
            if (!rs.next()) return null;
            Config c = new Config();
            c.mainDb = rs.getString(1);
            c.diffDb = rs.getString(2);
            c.version = rs.getString(3);
            c.date = rs.getString(4);
            return rs.next() ? null : c;
        } catch (SQLException e) {
            return null;
        }
    }

    /**
     * populate_choosers(): @minRatio < 0 loads everything; without @multimatch the
     * multimatches go to the unreliable chooser.
     */
    public static Map<MatchCategory, List<MatchItem>> load(File file, double minRatio, boolean multimatch)
            throws SQLException {
        Map<MatchCategory, List<MatchItem>> results = new EnumMap<>(MatchCategory.class);
        for (MatchCategory cat : MatchCategory.values()) {
            results.put(cat, new ArrayList<>());
        }
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + file.getAbsolutePath());
             Statement st = conn.createStatement()) {
            try (ResultSet rs = st.executeQuery("select * from results")) {
                while (rs.next()) {
                    String rtype = rs.getString("type");
                    MatchCategory cat;
                    if ("best".equals(rtype)) {
                        cat = MatchCategory.BEST;
                    } else if ("partial".equals(rtype)) {
                        cat = MatchCategory.PARTIAL;
                    } else if ("multimatch".equals(rtype) && multimatch) {
                        cat = MatchCategory.PROBLEMATIC;
                    } else {
                        cat = MatchCategory.UNRELIABLE;
                    }
                    double ratio = rs.getDouble("ratio");
                    if (minRatio >= 0 && ratio < minRatio) {
                        continue;
                    }
                    MatchItem item = new MatchItem(uiAddress(rs.getString("address")), rs.getString("name"),
                        uiAddress(rs.getString("address2")), rs.getString("name2"),
                        rs.getString("description"), ratio, rs.getInt("nodes1"), rs.getInt("nodes2"));
                    results.get(cat).add(item);
                }
            }
            try (ResultSet rs = st.executeQuery("select * from unmatched")) {
                while (rs.next()) {
                    String addr = uiAddress(rs.getString("address"));
                    String name = rs.getString("name");
                    if ("primary".equals(rs.getString("type"))) {
                        results.get(MatchCategory.UNMATCHED_SECONDARY)
                               .add(new MatchItem("", "", addr, name, "Unmatched", 0.0, 0, 0));
                    } else {
                        results.get(MatchCategory.UNMATCHED_PRIMARY)
                               .add(new MatchItem(addr, name, "", "", "Unmatched", 0.0, 0, 0));
                    }
                }
            }
        }
        return results;
    }
}
