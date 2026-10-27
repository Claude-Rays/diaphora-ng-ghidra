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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import ghidra.framework.preferences.Preferences;

/**
 * The two phases that make the pseudo-code diff of two builds readable, both
 * optional and on by default (not in the Python version):
 * <ul>
 * <li>canonical names ("level 1", export/LocalNames): the locals named v1,
 * v2... in the order of first use, as Hex-Rays does, instead of Ghidra's
 * uVar3, local_28... It is applied when the pseudo-code is exported, so it
 * also changes the pseudo-code hashes. The secondary side of a diff comes from
 * its database, so the diff views follow what each database was exported with
 * (program_data), not this setting; it applies to new exports and to Local
 * diff.</li>
 * <li>rename locals ("level 2", util/LocalRenamer): the diff views rename the
 * locals of one side after the other's. Only what the views show.</li>
 * </ul>
 * Off, the views show what Ghidra's decompiler gives, as Diaphora would.
 */
public final class DiffSettings {

    private DiffSettings() {
    }

    private static final String CANONICAL_PREF = "diaphora-ng.canonicalLocalNames";
    private static final String RENAME_PREF = "diaphora-ng.renameLocals";

    /** The program_data row (type, name) that records level 1 in a database. */
    public static final String EXPORT_OPTION = "export_option";
    public static final String CANONICAL_ROW = "canonical_local_names";

    private static boolean get(String key) {
        String v = Preferences.getProperty(key);
        return v == null || Boolean.parseBoolean(v);
    }

    private static void set(String key, boolean value) {
        Preferences.setProperty(key, Boolean.toString(value));
        Preferences.store();
    }

    public static boolean canonicalNames() {
        return get(CANONICAL_PREF);
    }

    public static void setCanonicalNames(boolean value) {
        set(CANONICAL_PREF, value);
    }

    public static boolean renameLocals() {
        return get(RENAME_PREF);
    }

    public static void setRenameLocals(boolean value) {
        set(RENAME_PREF, value);
    }

    /**
     * Whether database 'db' ("main", "diff") was exported with canonical names;
     * true for the databases exported before the setting existed, which always
     * applied it.
     */
    public static boolean exportedCanonical(Connection conn, String db) throws SQLException {
        String sql = "select value from " + db + ".program_data where type = ? and name = ? order by id desc limit 1";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, EXPORT_OPTION);
            ps.setString(2, CANONICAL_ROW);
            try (ResultSet rs = ps.executeQuery()) {
                return !rs.next() || !"0".equals(rs.getString(1));
            }
        }
    }
}
