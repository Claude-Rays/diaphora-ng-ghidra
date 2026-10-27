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

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Diaphora database schema definitions and setup.
 * The schema (version 3.4) of Diaphora (Python).
 */
public final class DiaphoraSchema {

    public static final String VERSION_VALUE = "3.4";

    public static final String[] TABLES = {
        "CREATE TABLE IF NOT EXISTS functions (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    name VARCHAR(255),\n" +
        "    address TEXT UNIQUE,\n" +
        "    nodes INTEGER,\n" +
        "    edges INTEGER,\n" +
        "    indegree INTEGER,\n" +
        "    outdegree INTEGER,\n" +
        "    size INTEGER,\n" +
        "    instructions INTEGER,\n" +
        "    mnemonics TEXT,\n" +
        "    names TEXT,\n" +
        "    prototype TEXT,\n" +
        "    cyclomatic_complexity INTEGER,\n" +
        "    primes_value TEXT,\n" +
        "    comment TEXT,\n" +
        "    mangled_function TEXT,\n" +
        "    bytes_hash TEXT,\n" +
        "    pseudocode TEXT,\n" +
        "    pseudocode_lines INTEGER,\n" +
        "    pseudocode_hash1 TEXT,\n" +
        "    pseudocode_primes TEXT,\n" +
        "    function_flags INTEGER,\n" +
        "    assembly TEXT,\n" +
        "    prototype2 TEXT,\n" +
        "    pseudocode_hash2 TEXT,\n" +
        "    pseudocode_hash3 TEXT,\n" +
        "    strongly_connected INTEGER,\n" +
        "    loops INTEGER,\n" +
        "    rva TEXT UNIQUE,\n" +
        "    tarjan_topological_sort TEXT,\n" +
        "    strongly_connected_spp TEXT,\n" +
        "    clean_assembly TEXT,\n" +
        "    clean_pseudo TEXT,\n" +
        "    mnemonics_spp TEXT,\n" +
        "    switches TEXT,\n" +
        "    function_hash TEXT,\n" +
        "    bytes_sum INTEGER,\n" +
        "    md_index TEXT,\n" +
        "    constants TEXT,\n" +
        "    constants_count INTEGER,\n" +
        "    segment_rva TEXT,\n" +
        "    assembly_addrs TEXT,\n" +
        "    kgh_hash TEXT,\n" +
        "    source_file TEXT,\n" +
        "    userdata TEXT,\n" +
        "    microcode TEXT,\n" +
        "    clean_microcode TEXT,\n" +
        "    microcode_spp TEXT,\n" +
        "    export_time REAL\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS program (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    callgraph_primes TEXT,\n" +
        "    callgraph_all_primes TEXT,\n" +
        "    processor TEXT,\n" +
        "    md5sum TEXT\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS program_data (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    name VARCHAR(255),\n" +
        "    type VARCHAR(255),\n" +
        "    value TEXT\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS version (value TEXT)",

        "CREATE TABLE IF NOT EXISTS instructions (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    func_id INTEGER NOT NULL,\n" +
        "    address TEXT,\n" +
        "    disasm TEXT,\n" +
        "    mnemonic TEXT,\n" +
        "    comment1 TEXT,\n" +
        "    comment2 TEXT,\n" +
        "    operand_names TEXT,\n" +
        "    name TEXT,\n" +
        "    type TEXT,\n" +
        "    pseudocomment TEXT,\n" +
        "    pseudoitp INTEGER,\n" +
        "    asm_type TEXT\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS basic_blocks (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    num INTEGER,\n" +
        "    address TEXT,\n" +
        "    asm_type TEXT\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS bb_relations (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    parent_id INTEGER NOT NULL REFERENCES basic_blocks(id) ON DELETE CASCADE,\n" +
        "    child_id INTEGER NOT NULL REFERENCES basic_blocks(id) ON DELETE CASCADE\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS bb_instructions (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    basic_block_id INTEGER REFERENCES basic_blocks(id) ON DELETE CASCADE,\n" +
        "    instruction_id INTEGER REFERENCES instructions(id) ON DELETE CASCADE\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS function_bblocks (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    function_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,\n" +
        "    basic_block_id INTEGER NOT NULL REFERENCES basic_blocks(id) ON DELETE CASCADE,\n" +
        "    asm_type TEXT\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS callgraph (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    func_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,\n" +
        "    address TEXT NOT NULL,\n" +
        "    type TEXT NOT NULL\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS constants (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    func_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE,\n" +
        "    constant TEXT NOT NULL\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS compilation_units (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    name TEXT,\n" +
        "    functions INT,\n" +
        "    primes_value TEXT,\n" +
        "    pseudocode_primes TEXT,\n" +
        "    start_ea TEXT UNIQUE,\n" +
        "    end_ea TEXT\n" +
        ")",

        "CREATE TABLE IF NOT EXISTS compilation_unit_functions (\n" +
        "    id INTEGER PRIMARY KEY,\n" +
        "    cu_id INTEGER NOT NULL REFERENCES compilation_units(id) ON DELETE CASCADE,\n" +
        "    func_id INTEGER NOT NULL REFERENCES functions(id) ON DELETE CASCADE\n" +
        ")"
    };

    public static final String[][] INDICES = {
        {"functions", "bytes_hash"},
        {"functions", "pseudocode"},
        {"functions", "name"},
        {"functions", "mangled_function"},
        {"functions", "assembly, pseudocode"},
        {"functions", "nodes, edges, mnemonics, names, cyclomatic_complexity, prototype2, indegree, outdegree"},
        {"functions", "instructions, mnemonics, names"},
        {"functions", "nodes, edges, cyclomatic_complexity"},
        {"functions", "cyclomatic_complexity"},
        {"functions", "pseudocode_lines, pseudocode_primes"},
        {"functions", "names, mnemonics"},
        {"functions", "pseudocode_hash2"},
        {"functions", "pseudocode_hash3"},
        {"functions", "pseudocode_hash1, pseudocode_hash2, pseudocode_hash3"},
        {"functions", "strongly_connected"},
        {"functions", "strongly_connected_spp"},
        {"functions", "loops"},
        {"functions", "rva"},
        {"functions", "tarjan_topological_sort"},
        {"functions", "mnemonics_spp"},
        {"functions", "clean_assembly"},
        {"functions", "clean_pseudo"},
        {"functions", "switches"},
        {"functions", "function_hash"},
        {"functions", "md_index"},
        {"functions", "kgh_hash"},
        {"functions", "constants_count, constants"},
        {"functions", "md_index, constants_count, constants"},
        {"functions", "address"},
        {"functions", "microcode_spp"},
        {"functions", "microcode"},
        {"instructions", "address"},
        {"bb_relations", "parent_id, child_id"},
        {"bb_instructions", "basic_block_id, instruction_id"},
        {"function_bblocks", "function_id, basic_block_id"},
        {"constants", "constant, func_id"},
        {"callgraph", "func_id"},
        {"compilation_units", "pseudocode_primes"},
        {"compilation_units", "name"},
        {"compilation_unit_functions", "func_id"},
        {"compilation_unit_functions", "cu_id"}
    };

    private DiaphoraSchema() {}

    public static void initDatabase(Connection conn) throws SQLException {
        boolean auto = conn.getAutoCommit();
        try (Statement stmt = conn.createStatement()) {
            // PRAGMAs (like journal_mode) must be executed in autocommit mode outside transactions
            if (!auto) {
                conn.setAutoCommit(true);
            }
            try {
                stmt.execute("PRAGMA journal_mode = WAL;");
                stmt.execute("PRAGMA synchronous = NORMAL;");
                stmt.execute("PRAGMA temp_store = MEMORY;");
            } catch (SQLException ignored) {
                // Ignore if pragma fails on certain SQLite setups
            }
            if (!auto) {
                conn.setAutoCommit(false);
            }

            for (String sql : TABLES) {
                stmt.execute(sql);
            }

            stmt.execute("DELETE FROM version;");
            stmt.execute("INSERT INTO version (value) VALUES ('" + VERSION_VALUE + "');");
        }
    }

    public static void createIndices(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            int idx = 0;
            for (String[] entry : INDICES) {
                String table = entry[0];
                String cols = entry[1];
                String cleanCols = cols.replaceAll("[^a-zA-Z0-9_]", "_");
                String indexName = "idx_" + table + "_" + cleanCols + "_" + (idx++);
                String sql = "CREATE INDEX IF NOT EXISTS " + indexName + " ON " + table + " (" + cols + ");";
                try {
                    stmt.execute(sql);
                } catch (SQLException ignored) {
                    // Ignore index creation errors if any
                }
            }
        }
    }
}
