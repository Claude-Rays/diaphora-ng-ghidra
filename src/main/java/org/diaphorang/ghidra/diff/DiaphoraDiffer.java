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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import org.diaphorang.ghidra.model.*;
import org.diaphorang.ghidra.util.PrimeFactors;
import org.diaphorang.ghidra.util.SequenceMatcher;
import org.diaphorang.ghidra.util.SideBySideDiff;

import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.sql.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core Diaphora Diffing Engine.
 *
 * Direct port of CBinDiff.diff() and everything it calls in diaphora.py. The
 * logic, the order of the phases and the quirks of the original are kept on
 * purpose. The only deviation of Diaphora-ng is "Related compilation unit"
 * (findRelatedCompilationUnit).
 * Not ported: project specific Python scripts (hooks) and the ML classifier.
 */
public class DiaphoraDiffer {

    /** Diffing options of the original export dialog (CBinDiffExporterSetup). */
    public static class Options {
        public boolean unreliable = false;          // DIFFING_ENABLE_UNRELIABLE
        public boolean slowHeuristics = true;       // DIFFING_ENABLE_SLOW_HEURISTICS
        public boolean relaxedRatio = false;        // DIFFING_ENABLE_RELAXED_RATIO
        public boolean experimental = true;         // DIFFING_ENABLE_EXPERIMENTAL ("Use speed ups")
        public boolean ignoreSubNames = true;       // DIFFING_IGNORE_SUB_FUNCTION_NAMES
        public boolean ignoreAllNames = false;      // DIFFING_IGNORE_ALL_FUNCTION_NAMES
        public boolean ignoreSmallFunctions = false; // DIFFING_IGNORE_SMALL_FUNCTIONS
    }

    // diaphora_config.py
    private static final int SQL_MAX_PROCESSED_ROWS = 1000000;
    private static final int SQL_TIMEOUT_LIMIT = 60 * 5;
    private static final double MATCHES_BONUS_RATIO = 0.01;
    private static final int DECIMAL_VALUES = 7;
    private static final int MAX_FUNCTIONS_PER_GAP = 100;
    private static final String SQL_DEFAULT_POSTFIX = " and f.instructions > 5 and df.instructions > 5 ";
    private static final double MINIMUM_RARE_MD_INDEX = 10.0;
    private static final double DEFAULT_PARTIAL_RATIO = 0.5;
    private static final double DEFAULT_TRUSTED_PARTIAL_RATIO = 0.3;
    private static final double INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU = 0.006;
    private static final double INCREASE_RATIO_PER_CONSTANT_MATCH = 0.008;
    private static final double SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT = 99.0;
    private static final double SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT = 90.0;
    private static final double SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO = 0.6;
    private static final int DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT = 25;
    private static final int DIFFING_MATCHES_MIN_BBLOCKS = 3;
    private static final double RELATED_MATCHES_MIN_RATIO = 0.8;

    private static final Pattern CPP_NAMES_RE = Pattern.compile(
        "([a-zA-Z_][a-zA-Z0-9_]{3,}((::){0,1}[a-zA-Z0-9_]+)*)", Pattern.CASE_INSENSITIVE);

    private static final String BEST = "best";
    private static final String PARTIAL = "partial";
    private static final String UNRELIABLE = "unreliable";
    private static final List<String> CHOOSERS = List.of(BEST, PARTIAL, UNRELIABLE);

    /** diaphora_heuristics.get_query_fields() */
    private static String getQueryFields(String heur, boolean quote) {
        String desc = quote ? "'" + heur.replace("'", "''") + "'" : heur;
        return " f.address ea, f.name name1, df.address ea2, df.name name2,\n" +
               " " + desc + " description,\n" +
               " f.pseudocode pseudo1, df.pseudocode pseudo2,\n" +
               " f.assembly asm1, df.assembly asm2,\n" +
               " f.pseudocode_primes pseudo_primes1, df.pseudocode_primes pseudo_primes2,\n" +
               " f.nodes nodes1, df.nodes nodes2,\n" +
               " cast(f.md_index as real) md1, cast(df.md_index as real) md2,\n" +
               " f.clean_assembly clean_assembly1, df.clean_assembly clean_assembly2,\n" +
               " f.clean_pseudo clean_pseudo1, df.clean_pseudo clean_pseudo2,\n" +
               " f.mangled_function mangled1, df.mangled_function mangled2,\n" +
               " f.clean_microcode clean_micro1, df.clean_microcode clean_micro2,\n" +
               " f.bytes_hash bytes_hash1, df.bytes_hash bytes_hash2,\n" +
               " f.edges edges1, df.edges edges2,\n" +
               " f.indegree indegree1, df.indegree indegree2,\n" +
               " f.outdegree outdegree1, df.outdegree outdegree2,\n" +
               " f.instructions instructions1, df.instructions instructions2,\n" +
               " f.cyclomatic_complexity cc1, df.cyclomatic_complexity cc2,\n" +
               " f.strongly_connected strongly_connected1,\n" +
               " df.strongly_connected strongly_connected2,\n" +
               " f.loops loops1, df.loops loops2,\n" +
               " f.constants_count constants_count1,\n" +
               " df.constants_count constants_count2,\n" +
               " f.size size1, df.size size2,\n" +
               " f.kgh_hash kgh_hash1, df.kgh_hash kgh_hash2\n";
    }

    private static String getQueryFields(String heur) {
        return getQueryFields(heur, true);
    }

    private final File primaryDbFile;
    private final File secondaryDbFile;
    private final Options opts;

    private final Map<MatchCategory, List<MatchItem>> results = new EnumMap<>(MatchCategory.class);

    private Map<String, Matched> matchedPrimary = new HashMap<>();
    private Map<String, Matched> matchedSecondary = new HashMap<>();
    private Map<String, List<Item>> allMatches = new LinkedHashMap<>();
    private final Map<String, Double> ratiosCache = new HashMap<>();

    private int totalFunctions1;
    private int totalFunctions2;
    private boolean isSameProcessor;
    private boolean isPatchDiff;
    private Connection conn;
    private TaskMonitor monitor;

    private static final class Matched {
        final String name;
        final double ratio;

        Matched(String name, double ratio) {
            this.name = name;
            this.ratio = ratio;
        }
    }

    /** A chooser item: [ea, name1, ea2, name2, desc, ratio, nodes1, nodes2] */
    private static final class Item {
        final String ea, name1, ea2, name2, desc;
        final double ratio;
        final int nodes1, nodes2;

        Item(String ea, String name1, String ea2, String name2, String desc, double ratio, int nodes1, int nodes2) {
            this.ea = ea;
            this.name1 = name1;
            this.ea2 = ea2;
            this.name2 = name2;
            this.desc = desc;
            this.ratio = ratio;
            this.nodes1 = nodes1;
            this.nodes2 = nodes2;
        }

        boolean sameAs(Item o) {
            return Objects.equals(ea, o.ea) && Objects.equals(name1, o.name1) && Objects.equals(ea2, o.ea2)
                && Objects.equals(name2, o.name2) && Objects.equals(desc, o.desc) && ratio == o.ratio
                && nodes1 == o.nodes1 && nodes2 == o.nodes2;
        }
    }

    /** main_d / diff_d dictionaries of check_match() and compare_function_rows(). */
    private static final class Row {
        String ea1, name1, ea2, name2, desc, mangled1;
        String pseudo1, pseudo2;
        String primes1, primes2;
        int nodes1, nodes2;
        Double md1, md2;
        String cleanAsm1, cleanAsm2, cleanPseudo1, cleanPseudo2, cleanMicro1, cleanMicro2;
        String bytesHash1, bytesHash2;
    }

    public DiaphoraDiffer(File primaryDbFile, File secondaryDbFile, Options opts) {
        this.primaryDbFile = primaryDbFile;
        this.secondaryDbFile = secondaryDbFile;
        this.opts = opts != null ? opts : new Options();
        for (MatchCategory cat : MatchCategory.values()) {
            results.put(cat, new ArrayList<>());
        }
        for (String c : CHOOSERS) {
            allMatches.put(c, new ArrayList<>());
        }
    }

    public DiaphoraDiffer(File primaryDbFile, File secondaryDbFile,
                          boolean relaxedRatio, boolean enableUnreliable, boolean ignoreSubNames) {
        this(primaryDbFile, secondaryDbFile, options(relaxedRatio, enableUnreliable, ignoreSubNames));
    }

    private static Options options(boolean relaxedRatio, boolean unreliable, boolean ignoreSubNames) {
        Options o = new Options();
        o.relaxedRatio = relaxedRatio;
        o.unreliable = unreliable;
        o.ignoreSubNames = ignoreSubNames;
        return o;
    }

    private void log(String msg) {
        Msg.info(this, "Diaphora-ng: " + msg);
    }

    private void logRefresh(String msg) {
        monitor.setMessage(msg);
        log(msg);
    }

    // ------------------------------------------------------------------------
    // diff()
    // ------------------------------------------------------------------------

    public Map<MatchCategory, List<MatchItem>> diff(TaskMonitor monitor) throws Exception {
        this.monitor = monitor;
        ratiosCache.clear();
        String url = "jdbc:sqlite:" + primaryDbFile.getAbsolutePath();
        try (Connection c = DriverManager.getConnection(url)) {
            this.conn = c;
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("ATTACH DATABASE '" + secondaryDbFile.getAbsolutePath().replace("'", "''") + "' AS diff");
            }
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("select value from diff.version")) {
                if (!rs.next()) {
                    throw new SQLException("Invalid database!");
                }
                if (!DiaphoraSchema.VERSION_VALUE.equals(rs.getString(1))) {
                    log("WARNING: The database is from a different version (current " +
                        DiaphoraSchema.VERSION_VALUE + ", database " + rs.getString(1) + ")!");
                }
            }

            long t0 = System.currentTimeMillis();
            logRefresh("Diffing...");

            // Find the unmodified functions
            logRefresh("Finding equal matches...");
            findEqualMatches();

            boolean skipOthers = false;
            isSameProcessor = sameProcessorBothDatabases();
            if (opts.experimental) {
                // Dirty magic. Might or might not work...
                logRefresh("Checking 'dirty' heuristics...");
                skipOthers = applyDirtyHeuristics();
            }

            if (!opts.ignoreAllNames) {
                findSameName(PARTIAL);
            }

            if (skipOthers) {
                findRemainingFunctions();
            } else {
                logRefresh("Finding best matches...");
                runHeuristicsForCategory("Best");

                // Find the modified functions
                logRefresh("Finding partial matches");
                findPartialMatches();

                if (opts.unreliable) {
                    // Find using likely unreliable methods modified functions
                    logRefresh("Finding probably unreliable matches");
                    findUnreliableMatches();

                    logRefresh("Finding experimental matches");
                    runHeuristicsForCategory("Experimental");
                }

                int iteration = 0;
                while (!monitor.isCancelled()) {
                    cleanupMatches();
                    int oldTotal = getTotalMatchedFunctions();

                    // Find new matches by diffing assembly and pseudo-code of
                    // previously found matches
                    findMatchesDiffing(iteration);

                    if (opts.slowHeuristics) {
                        // Find new matches by digging from previous very good matches
                        findRelatedMatches(iteration);
                    }

                    findRelatedCompilationUnit(iteration);

                    // Find new matches in the functions between matches
                    findLocallyAffineFunctions(iteration);

                    cleanupMatches();
                    int newTotal = getTotalMatchedFunctions();
                    if (newTotal <= oldTotal) {
                        break;
                    }
                    iteration++;
                }
            }

            finalPass();

            // Show the list of unmatched functions in both databases
            logRefresh("Finding unmatched functions");
            findUnmatched();

            int best = results.get(MatchCategory.BEST).size();
            int partial = results.get(MatchCategory.PARTIAL).size();
            int unreliable = results.get(MatchCategory.UNRELIABLE).size();
            int multi = results.get(MatchCategory.PROBLEMATIC).size();
            log("Final results: Best " + best + ", Partial " + partial + ", Unreliable " + unreliable +
                ", Multimatches " + multi);
            log("Done, time taken: " + (System.currentTimeMillis() - t0) / 1000.0 + " seconds.");
        } finally {
            this.conn = null;
        }
        return results;
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    private boolean sameProcessorBothDatabases() {
        String sql = "select 1 from main.program mp, diff.program dp where mp.processor = dp.processor";
        try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    private boolean allFunctionsMatched() {
        return matchedPrimary.size() == totalFunctions1 || matchedSecondary.size() == totalFunctions2;
    }

    private int getTotalMatchedFunctions() {
        return allMatches.get(BEST).size() + allMatches.get(PARTIAL).size();
    }

    private List<Item> getSortedResults(String category) {
        List<Item> l = new ArrayList<>(allMatches.get(category));
        l.sort((a, b) -> Double.compare(b.ratio, a.ratio));
        return l;
    }

    private static Double getDoubleOrNull(ResultSet rs, String col) throws SQLException {
        double v = rs.getDouble(col);
        return rs.wasNull() ? null : v;
    }

    /** Row of a query using get_query_fields(). */
    private static Row readRow(ResultSet rs) throws SQLException {
        Row r = new Row();
        r.ea1 = rs.getString("ea");
        r.name1 = rs.getString("name1");
        r.ea2 = rs.getString("ea2");
        r.name2 = rs.getString("name2");
        r.desc = rs.getString("description");
        r.mangled1 = rs.getString("mangled1");
        r.pseudo1 = rs.getString("pseudo1");
        r.pseudo2 = rs.getString("pseudo2");
        r.primes1 = rs.getString("pseudo_primes1");
        r.primes2 = rs.getString("pseudo_primes2");
        r.nodes1 = rs.getInt("nodes1");
        r.nodes2 = rs.getInt("nodes2");
        r.md1 = getDoubleOrNull(rs, "md1");
        r.md2 = getDoubleOrNull(rs, "md2");
        r.cleanAsm1 = rs.getString("clean_assembly1");
        r.cleanAsm2 = rs.getString("clean_assembly2");
        r.cleanPseudo1 = rs.getString("clean_pseudo1");
        r.cleanPseudo2 = rs.getString("clean_pseudo2");
        r.cleanMicro1 = rs.getString("clean_micro1");
        r.cleanMicro2 = rs.getString("clean_micro2");
        r.bytesHash1 = rs.getString("bytes_hash1");
        r.bytesHash2 = rs.getString("bytes_hash2");
        return r;
    }

    /** A "select *" row of the functions table. */
    private static Map<String, Object> readFunctionRow(ResultSet rs) throws SQLException {
        Map<String, Object> m = new HashMap<>();
        ResultSetMetaData md = rs.getMetaData();
        for (int i = 1; i <= md.getColumnCount(); i++) {
            m.put(md.getColumnLabel(i), rs.getObject(i));
        }
        return m;
    }

    private static String str(Map<String, Object> row, String key) {
        Object o = row.get(key);
        return o != null ? o.toString() : null;
    }

    private static int intOf(Map<String, Object> row, String key) {
        Object o = row.get(key);
        if (o instanceof Number) return ((Number) o).intValue();
        if (o == null) return 0;
        try {
            return Integer.parseInt(o.toString().trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static Double floatOf(Object o) {
        if (o == null) return null;
        if (o instanceof Number) return ((Number) o).doubleValue();
        try {
            return Double.parseDouble(o.toString().trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Map<String, Object> getFunctionRow(String name, String db) {
        String sql = "select * from " + db + ".functions where name = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? readFunctionRow(rs) : null;
            }
        } catch (SQLException e) {
            log("ERROR at get_function_row: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object>[] getRowForItems(Item item) {
        @SuppressWarnings("unchecked")
        Map<String, Object>[] rows = new Map[]{getFunctionRow(item.name1, "main"), getFunctionRow(item.name2, "diff")};
        return rows;
    }

    // ------------------------------------------------------------------------
    // add_match, has_best_match, has_better_match
    // ------------------------------------------------------------------------

    private void addMatch(String name1, String name2, double ratio, Item item, String chooser) {
        // If the function names are the same, it's a best match, regardless of the
        // ratio we got for the match, so fake the ratio as if it was 1.0.
        if (name1.equals(name2)) {
            ratio = 1.0;
        }
        if (ratio != 1.0) {
            if (hasBetterMatch(name1, name2, ratio)) {
                return;
            }
        }
        if (chooser != null) {
            List<Item> list = allMatches.get(chooser);
            boolean exists = false;
            for (Item it : list) {
                if (it.sameAs(item)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) list.add(item);
        }
        matchedPrimary.put(name1, new Matched(name2, ratio));
        matchedSecondary.put(name2, new Matched(name1, ratio));
    }

    private boolean hasBestMatch(String name1, String name2) {
        Matched m1 = matchedPrimary.get(name1);
        if (m1 != null && m1.ratio == 1.0) return true;
        Matched m2 = matchedSecondary.get(name2);
        return m2 != null && m2.ratio == 1.0;
    }

    private boolean hasBetterMatch(String name1, String name2, double ratio) {
        // If we have a match by name, that's the best match
        if (!name1.startsWith("sub_") && !name2.startsWith("sub_")) {
            Matched m = matchedPrimary.get(name1);
            if (m != null) {
                return m.name.equals(name1);
            }
        }
        Matched m1 = matchedPrimary.get(name1);
        if (m1 != null && m1.ratio > ratio) return true;
        Matched m2 = matchedSecondary.get(name2);
        return m2 != null && m2.ratio > ratio;
    }

    // ------------------------------------------------------------------------
    // check_ratio, deep_ratio, check_match
    // ------------------------------------------------------------------------

    private double quickRatio(String a, String b) {
        return SequenceMatcher.quickRatioLines(a, b);
    }

    private double fratio(String a, String b) {
        return opts.relaxedRatio ? SequenceMatcher.realQuickRatioLines(a, b) : SequenceMatcher.quickRatioLines(a, b);
    }

    /** float(decimal_values.format(v)) */
    private double fmt(double v) {
        int scale = opts.relaxedRatio ? 1 : DECIMAL_VALUES;
        return new BigDecimal(v).setScale(scale, RoundingMode.HALF_EVEN).doubleValue();
    }

    private double astRatio(String ast1, String ast2) {
        if (!opts.relaxedRatio) return 0;
        if (ast1 == null || ast2 == null) return 0;
        if (ast1.equals(ast2)) return 1.0;
        try {
            return PrimeFactors.differenceRatio(new BigInteger(ast1.trim()), new BigInteger(ast2.trim()));
        } catch (Exception e) {
            return 0;
        }
    }

    private double checkRatio(Row row) {
        String key = row.ea1 + "-" + row.ea2;
        Double cached = ratiosCache.get(key);
        if (cached != null) return cached;

        double md1 = row.md1 != null ? row.md1 : 0.0;
        double md2 = row.md2 != null ? row.md2 : 0.0;

        if (Objects.equals(row.bytesHash1, row.bytesHash2)) {
            ratiosCache.put(key, 1.0);
            return 1.0;
        }

        double v3 = 0;
        boolean astDone = false;
        if (opts.relaxedRatio && row.primes1 != null && row.primes2 != null
                && Math.max(row.primes1.length(), row.primes2.length()) < 16) {
            astDone = true;
            v3 = astRatio(row.primes1, row.primes2);
            if (v3 == 1.0) {
                ratiosCache.put(key, 1.0);
                return v3;
            }
        }

        double v1 = 0;
        if (row.pseudo1 != null && row.pseudo2 != null && !row.pseudo1.isEmpty() && !row.pseudo2.isEmpty()) {
            if ("".equals(row.cleanPseudo1) || "".equals(row.cleanPseudo2)) {
                log("Error cleaning pseudo-code!");
            } else {
                v1 = fmt(fratio(row.cleanPseudo1, row.cleanPseudo2));
                if (v1 == 1.0 && opts.relaxedRatio) {
                    // If real_quick_ratio returns 1 try again with quick_ratio
                    v1 = quickRatio(row.cleanPseudo1, row.cleanPseudo2);
                    if (v1 == 1.0) {
                        ratiosCache.put(key, 1.0);
                        return 1.0;
                    }
                }
            }
        }

        double v2 = fmt(fratio(row.cleanAsm1, row.cleanAsm2));
        if (v2 == 1.0 && opts.relaxedRatio) {
            v2 = quickRatio(row.cleanAsm1, row.cleanAsm2);
            if (v2 == 1.0) {
                ratiosCache.put(key, 1.0);
                return 1.0;
            }
        }

        if (opts.relaxedRatio && !astDone) {
            v3 = fmt(fratio(row.primes1, row.primes2));
            if (v3 == 1.0) {
                ratiosCache.put(key, 1.0);
                return 1.0;
            }
        }

        double v4 = 0.0;
        if (md1 == md2 && md1 > 0.0) {
            // A MD-Index >= 10.0 is somehow rare
            if (opts.relaxedRatio && md1 > MINIMUM_RARE_MD_INDEX) {
                ratiosCache.put(key, 1.0);
                return 1.0;
            }
            v4 = Math.min((v1 + v2 + v3 + 3.0) / 5, 1.0);
        }

        double v5 = 0.0;
        if (row.cleanMicro1 != null && row.cleanMicro2 != null) {
            v5 = fmt(fratio(row.cleanMicro1, row.cleanMicro2));
            if (v5 == 1.0) {
                ratiosCache.put(key, 1.0);
                return 1.0;
            }
        }

        double[] values = {v1, v2, v3, v4, v5};
        double r = 0;
        for (double v : values) r = Math.max(r, v);
        if (r == 1.0 && md1 != md2) {
            // We cannot assign a 1.0 ratio if both MD indices are different
            r = 0;
            for (double v : values) {
                if (v != 1.0 && v > r) r = v;
            }
        }

        if (r < 1.0) {
            double score = deepRatio(row);
            if (r + score < 1.0) {
                r += score;
            } else {
                r = 0.99;
            }
        }

        ratiosCache.put(key, r);
        return r;
    }

    private Map<String, Object> getFunctionRowByAddress(String ea, String db) {
        String sql = "select * from " + db + ".functions where address = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ea);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? readFunctionRow(rs) : null;
            }
        } catch (SQLException e) {
            return null;
        }
    }

    /** Python's str() of a JSON value: ints as integers, strings as they are. */
    private static String pyStr(JsonElement e) {
        if (e.isJsonPrimitive()) {
            JsonPrimitive p = e.getAsJsonPrimitive();
            if (p.isString()) return p.getAsString();
            if (p.isNumber()) {
                try {
                    return new BigDecimal(p.getAsString()).toBigIntegerExact().toString();
                } catch (ArithmeticException ex) {
                    return p.getAsString();
                }
            }
        }
        return e.toString();
    }

    private static Set<String> jsonSet(String json) {
        Set<String> set = new LinkedHashSet<>();
        if (json == null || json.isEmpty()) return set;
        try {
            JsonElement el = JsonParser.parseString(json);
            if (el.isJsonArray()) {
                JsonArray arr = el.getAsJsonArray();
                for (JsonElement e : arr) set.add(pyStr(e));
            }
        } catch (Exception ignored) {
            // Malformed JSON
        }
        return set;
    }

    private double deepRatio(Row row) {
        double score = 0;
        Map<String, Object> mainRow = getFunctionRowByAddress(row.ea1, "main");
        Map<String, Object> diffRow = getFunctionRowByAddress(row.ea2, "diff");
        if (mainRow == null || diffRow == null) return 0;

        String source1 = str(mainRow, "source_file");
        String source2 = str(diffRow, "source_file");
        if (source1 != null && source2 != null && source1.equals(source2) && !source1.isEmpty()) {
            score += 0.001;
        }

        String pp1 = str(mainRow, "pseudocode_primes");
        String pp2 = str(diffRow, "pseudocode_primes");
        if (pp1 != null && pp2 != null && pp1.equals(pp2) && !pp1.isEmpty()) {
            score += 0.001;
        }

        if (Objects.equals(mainRow.get("indegree"), diffRow.get("indegree")) && intOf(mainRow, "indegree") != 0) {
            score += 0.001;
        }
        if (Objects.equals(mainRow.get("outdegree"), diffRow.get("outdegree")) && intOf(mainRow, "outdegree") != 0) {
            score += 0.001;
        }

        String sw1 = str(mainRow, "switches");
        String sw2 = str(diffRow, "switches");
        if (Objects.equals(sw1, sw2) && !"[]".equals(sw1)) {
            score += 0.003;
        }

        if (Objects.equals(mainRow.get("cyclomatic_complexity"), diffRow.get("cyclomatic_complexity"))
                && intOf(mainRow, "cyclomatic_complexity") != 0) {
            score += 0.001;
        }

        if (!"[]".equals(str(mainRow, "constants"))) {
            Set<String> set1 = jsonSet(str(mainRow, "constants"));
            Set<String> set2 = jsonSet(str(diffRow, "constants"));
            set1.retainAll(set2);
            if (!set1.isEmpty()) {
                double tmp = isSameProcessor ? INCREASE_RATIO_PER_CONSTANT_MATCH_SAME_CPU
                                             : INCREASE_RATIO_PER_CONSTANT_MATCH;
                score += set1.size() * tmp;
            }
        }
        return score;
    }

    /** check_match(): null means "should not be added". */
    private Double checkMatch(Row row) {
        if (row.name1.startsWith("nullsub_") || row.name2.startsWith("nullsub_")) {
            return null;
        }
        // Do we already have a 1.0 match for any of these functions?
        if (hasBestMatch(row.name1, row.name2)) {
            return null;
        }
        double r = checkRatio(row);
        // Do we have a previous match with a better comparison ratio than this?
        if (hasBetterMatch(row.name1, row.name2, r)) {
            return null;
        }
        return r;
    }

    private Row rowFromFunctionRows(Map<String, Object> mainRow, Map<String, Object> diffRow) {
        Row r = new Row();
        r.ea1 = str(mainRow, "address");
        r.name1 = str(mainRow, "name");
        r.ea2 = str(diffRow, "address");
        r.name2 = str(diffRow, "name");
        r.pseudo1 = str(mainRow, "pseudocode");
        r.pseudo2 = str(diffRow, "pseudocode");
        r.primes1 = str(mainRow, "pseudocode_primes");
        r.primes2 = str(diffRow, "pseudocode_primes");
        r.nodes1 = intOf(mainRow, "nodes");
        r.nodes2 = intOf(diffRow, "nodes");
        r.md1 = floatOf(mainRow.get("md_index"));
        r.md2 = floatOf(diffRow.get("md_index"));
        r.cleanAsm1 = str(mainRow, "clean_assembly");
        r.cleanAsm2 = str(diffRow, "clean_assembly");
        r.cleanPseudo1 = str(mainRow, "clean_pseudo");
        r.cleanPseudo2 = str(diffRow, "clean_pseudo");
        r.cleanMicro1 = str(mainRow, "clean_microcode");
        r.cleanMicro2 = str(diffRow, "clean_microcode");
        r.bytesHash1 = str(mainRow, "bytes_hash");
        r.bytesHash2 = str(diffRow, "bytes_hash");
        return r;
    }

    /** compare_function_rows() */
    private double compareFunctionRows(Map<String, Object> mainRow, Map<String, Object> diffRow) {
        return checkRatio(rowFromFunctionRows(mainRow, diffRow));
    }

    /**
     * add_manual_match(): compare_function_rows() of the functions at the given
     * decimal addresses. Returns null if either function does not exist.
     */
    public Double compareFunctionsByAddress(String ea1, String ea2) throws SQLException {
        try (Connection c = GraphDiff.openDiff(primaryDbFile, secondaryDbFile)) {
            this.conn = c;
            Map<String, Object> mainRow = getFunctionRowByAddress(ea1, "main");
            Map<String, Object> diffRow = getFunctionRowByAddress(ea2, "diff");
            if (mainRow == null || diffRow == null) return null;
            return compareFunctionRows(mainRow, diffRow);
        } finally {
            this.conn = null;
        }
    }

    // ------------------------------------------------------------------------
    // SQL heuristics machinery
    // ------------------------------------------------------------------------

    /** add_matches_internal() over an already executed query. */
    private void addMatchesInternal(ResultSet rs, String best, String partial, Double val) throws SQLException {
        addMatchesInternal(rs, best, partial, val, System.currentTimeMillis());
    }

    /**
     * The same with the start time of the timeout ('t'); returns false on a
     * timeout. Diaphora-ng: "Related compilation unit" passes the start of the
     * whole heuristic.
     */
    private boolean addMatchesInternal(ResultSet rs, String best, String partial, Double val, long t)
        throws SQLException {
        int i = 0;
        while (i < SQL_MAX_PROCESSED_ROWS) {
            if (monitor.isCancelled()) return true;
            if ((System.currentTimeMillis() - t) / 1000 > SQL_TIMEOUT_LIMIT) {
                log("Timeout with heuristic");
                return false;
            }
            i++;
            if (!rs.next()) break;

            Row row = readRow(rs);
            Double r = checkMatch(row);
            if (r == null) continue;

            double v = val != null ? val : DEFAULT_PARTIAL_RATIO;
            Item item = new Item(row.ea1, row.name1, row.ea2, row.name2, row.desc, r, row.nodes1, row.nodes2);
            if (r == 1.0) {
                addMatch(row.name1, row.name2, r, item, best);
            } else if (r >= v && partial != null) {
                addMatch(row.name1, row.name2, r, item, partial);
            }
        }
        return true;
    }

    private void addMatchesFromQueryRatio(String sql, String best, String partial, Double val) {
        if (allFunctionsMatched()) return;
        try (Statement stmt = conn.createStatement()) {
            stmt.setQueryTimeout(SQL_TIMEOUT_LIMIT);
            try (ResultSet rs = stmt.executeQuery(sql)) {
                addMatchesInternal(rs, best, partial, val);
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    /** add_matches_from_query(): only for heuristics known to give 1.0 ratios. */
    private void addMatchesFromQuery(String sql, String category) {
        if (allFunctionsMatched()) return;
        try (Statement stmt = conn.createStatement()) {
            stmt.setQueryTimeout(SQL_TIMEOUT_LIMIT);
            try (ResultSet rs = stmt.executeQuery(sql)) {
                while (!monitor.isCancelled() && rs.next()) {
                    Row row = readRow(rs);
                    Double r = checkMatch(row);
                    if (r == null) continue;
                    Item item = new Item(row.ea1, row.name1, row.ea2, row.name2, row.desc, 1, row.nodes1, row.nodes2);
                    addMatch(row.name1, row.name2, 1.0, item, category);
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    private void runHeuristicsForCategory(String argCategory) {
        String postfix = "";
        if (opts.ignoreSmallFunctions) {
            postfix = SQL_DEFAULT_POSTFIX;
        }

        for (Heuristic heur : HeuristicsLoader.getHeuristics()) {
            if (monitor.isCancelled()) break;
            if (allFunctionsMatched()) {
                log("All functions matched in at least one database, finishing.");
                break;
            }
            if (!heur.getCategory().equals(argCategory)) continue;

            String name = heur.getName();
            int ratio = heur.getRatio();
            double minValue = 0.0;
            if (ratio == Heuristic.HEUR_TYPE_RATIO_MAX || ratio == Heuristic.HEUR_TYPE_RATIO_MAX_TRUSTED) {
                minValue = heur.getMin();
            }

            if (heur.hasFlag(Heuristic.HEUR_FLAG_UNRELIABLE) && !opts.unreliable) {
                log("Skipping unreliable heuristic '" + name + "'");
                continue;
            }
            if (heur.hasFlag(Heuristic.HEUR_FLAG_SLOW) && !opts.slowHeuristics) {
                log("Skipping slow heuristic '" + name + "'");
                continue;
            }
            if (heur.hasFlag(Heuristic.HEUR_FLAG_SAME_CPU) && !isSameProcessor) {
                log("Skipping processor specific heuristic '" + name + "'");
                continue;
            }

            String best = BEST;
            String partial = PARTIAL;
            if (argCategory.equalsIgnoreCase("unreliable")) {
                best = PARTIAL;
                partial = UNRELIABLE;
            }

            logRefresh("Finding with heuristic '" + name + "'");
            String sql = heur.getSql().replace("%POSTFIX%", postfix);

            switch (ratio) {
                case Heuristic.HEUR_TYPE_NO_FPS:
                    addMatchesFromQuery(sql, best);
                    break;
                case Heuristic.HEUR_TYPE_RATIO:
                    addMatchesFromQueryRatio(sql, best, partial, null);
                    break;
                case Heuristic.HEUR_TYPE_RATIO_MAX:
                    addMatchesFromQueryRatio(sql, best, partial, minValue);
                    break;
                case Heuristic.HEUR_TYPE_RATIO_MAX_TRUSTED:
                    addMatchesFromQueryRatio(sql, BEST, PARTIAL, minValue);
                    break;
                default:
                    throw new IllegalStateException("Invalid heuristic ratio calculation value!");
            }
        }

        cleanupMatches();
    }

    // ------------------------------------------------------------------------
    // Phases
    // ------------------------------------------------------------------------

    private void findEqualMatches() throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("select count(*) total from functions union all " +
                                              "select count(*) total from diff.functions")) {
            List<Integer> totals = new ArrayList<>();
            while (rs.next()) totals.add(rs.getInt(1));
            if (totals.size() != 2) {
                throw new SQLException("Malformed database!");
            }
            totalFunctions1 = totals.get(0);
            totalFunctions2 = totals.get(1);
        }

        String fields = "id, address, mangled_function, nodes, edges, size, bytes_hash";
        String sql = "select address ea, mangled_function, nodes, bytes_hash " +
                     "  from (select " + fields + " from functions " +
                     "        intersect " +
                     "        select " + fields + " from diff.functions) x";
        try (Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                String name = rs.getString("mangled_function");
                String ea = rs.getString("ea");
                int nodes = rs.getInt("nodes");
                Item item = new Item(ea, name, ea, name, "100% equal", 1, nodes, nodes);
                addMatch(name, name, 1.0, item, BEST);
            }
        }
    }

    private void findSameName(String choose) {
        String desc = "Perfect match, same name";
        String sql = "select distinct " + getQueryFields(desc) +
                     "  from functions f, diff.functions df" +
                     " where (df.mangled_function = f.mangled_function or df.name = f.name)" +
                     "   and f.name not like 'nullsub_%'";

        logRefresh("Finding with heuristic '" + desc + "'");
        List<Row> rows = new ArrayList<>();
        try (Statement stmt = conn.createStatement()) {
            stmt.setQueryTimeout(SQL_TIMEOUT_LIMIT);
            try (ResultSet rs = stmt.executeQuery(sql)) {
                while (rs.next()) rows.add(readRow(rs));
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
            return;
        }

        if (rows.isEmpty() || allFunctionsMatched()) return;
        for (Row row : rows) {
            if (monitor.isCancelled()) break;
            String name = row.mangled1;
            if (opts.ignoreSubNames && name != null && name.startsWith("sub_")) continue;

            Double r = checkMatch(row);
            if (r == null) continue;
            double ratio = r;

            Item item;
            String theChooser;
            if (ratio == 1.0 || (opts.relaxedRatio && row.md1 != null && row.md1 != 0 && row.md1.equals(row.md2))) {
                theChooser = BEST;
                item = new Item(row.ea1, row.name1, row.ea2, row.name2, row.desc, 1, row.nodes1, row.nodes2);
            } else {
                theChooser = choose;
                if (ratio + MATCHES_BONUS_RATIO < 1.0) {
                    ratio += MATCHES_BONUS_RATIO;
                }
                item = new Item(row.ea1, row.name1, row.ea2, row.name2, row.desc, ratio, row.nodes1, row.nodes2);
            }
            addMatch(row.name1, row.name2, ratio, item, theChooser);
        }
    }

    private void findPartialMatches() {
        runHeuristicsForCategory("Partial");
        if (opts.slowHeuristics) {
            // Search using some of the previous criterias but calculating the edit distance
            logRefresh("Finding with heuristic 'Small names difference'");
            searchSmallDifferences(PARTIAL);
        }
    }

    private void findUnreliableMatches() {
        runHeuristicsForCategory("Unreliable");
        if (opts.slowHeuristics && opts.unreliable) {
            // Find using brute-force
            logRefresh("Brute-forcing...");
            findBruteForce();
        }
    }

    private void searchSmallDifferences(String choose) {
        String name = "Nodes, edges, complexity and mnemonics with small differences";
        String sql = " select " + getQueryFields(name) + " ,\n" +
                     "        f.names  f_names,\n" +
                     "        df.names df_names\n" +
                     "   from functions f,\n" +
                     "        diff.functions df\n" +
                     "  where f.nodes = df.nodes\n" +
                     "    and f.edges = df.edges\n" +
                     "    and f.mnemonics = df.mnemonics\n" +
                     "    and f.cyclomatic_complexity = df.cyclomatic_complexity\n" +
                     "    and f.names != '[]' ";
        try (Statement stmt = conn.createStatement()) {
            stmt.setQueryTimeout(SQL_TIMEOUT_LIMIT);
            try (ResultSet rs = stmt.executeQuery(sql)) {
                while (!monitor.isCancelled() && rs.next()) {
                    Row row = readRow(rs);
                    Set<String> s1 = jsonSet(rs.getString("f_names"));
                    Set<String> s2 = jsonSet(rs.getString("df_names"));
                    int total = Math.max(s1.size(), s2.size());
                    Set<String> inter = new HashSet<>(s1);
                    inter.retainAll(s2);
                    double ratio = (inter.size() * 1.0) / total;
                    if (hasBetterMatch(row.name1, row.name2, ratio)) continue;

                    if (ratio >= DEFAULT_PARTIAL_RATIO) {
                        Double ratio2 = checkMatch(row);
                        if (ratio2 == null) continue;
                        ratio = ratio2;
                        Item item = new Item(row.ea1, row.name1, row.ea2, row.name2, row.desc, ratio,
                                             row.nodes1, row.nodes2);
                        String theChooser = ratio == 1.0 ? BEST : choose;
                        addMatch(row.name1, row.name2, ratio, item, theChooser);
                    }
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    private void findBruteForce() {
        try (Statement st = conn.createStatement()) {
            st.execute("create temporary table if not exists unmatched(id integer null primary key, address, main)");
            st.execute("delete from unmatched");

            try (PreparedStatement ins = conn.prepareStatement("insert into unmatched(address,main) values(?,?)")) {
                try (ResultSet rs = st.executeQuery("select name, address from functions")) {
                    while (rs.next()) {
                        if (!matchedPrimary.containsKey(rs.getString(1))) {
                            ins.setString(1, rs.getString(2));
                            ins.setInt(2, 1);
                            ins.addBatch();
                        }
                    }
                }
                try (ResultSet rs = st.executeQuery("select name, address from diff.functions")) {
                    while (rs.next()) {
                        if (!matchedSecondary.containsKey(rs.getString(1))) {
                            ins.setString(1, rs.getString(2));
                            ins.setInt(2, 0);
                            ins.addBatch();
                        }
                    }
                }
                ins.executeBatch();
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
            return;
        }

        if (opts.slowHeuristics) {
            String heur = "Brute forcing (MD-Index and KOKA hash)";
            String sql = "select " + getQueryFields(heur) +
                         "  from functions f, diff.functions df, unmatched um" +
                         " where ((f.address = um.address and um.main = 1)" +
                         "    or (df.address = um.address and um.main = 0))" +
                         "   and ((f.md_index = df.md_index" +
                         "   and f.md_index > 1 and df.md_index > 1)" +
                         "    or (f.kgh_hash = df.kgh_hash" +
                         "   and f.kgh_hash > 7 and df.kgh_hash > 7))";
            logRefresh("Finding via brute-forcing (MD-Index and KOKA hash)...");
            addMatchesFromCursorRatioMax(sql, UNRELIABLE, UNRELIABLE, DEFAULT_PARTIAL_RATIO);
        }

        String heur = "Brute forcing (Compilation Unit)";
        String sql = "select " + getQueryFields(heur) +
                     "  from functions f, diff.functions df, unmatched um" +
                     " where ((f.address = um.address and um.main = 1)" +
                     "    or (df.address = um.address and um.main = 0))" +
                     "   and f.source_file = df.source_file" +
                     "   and f.source_file != ''" +
                     "   and df.source_file is not null" +
                     "   and f.kgh_hash > 7 and df.kgh_hash > 7 ";
        logRefresh("Finding via brute-forcing (Compilation Unit)...");
        addMatchesFromCursorRatioMax(sql, UNRELIABLE, UNRELIABLE, DEFAULT_PARTIAL_RATIO);
    }

    private void addMatchesFromCursorRatioMax(String sql, String best, String partial, double val) {
        if (allFunctionsMatched()) return;
        try (Statement stmt = conn.createStatement()) {
            stmt.setQueryTimeout(SQL_TIMEOUT_LIMIT);
            try (ResultSet rs = stmt.executeQuery(sql)) {
                addMatchesInternal(rs, best, partial, val);
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    // --- Speed ups ("dirty" heuristics) ---

    private boolean applyDirtyHeuristics() {
        if (searchJustStrippedBinaries()) return true;
        return searchPatchdiffWithSymbols();
    }

    private int countQuery(String sql) {
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
            return 0;
        }
    }

    private boolean searchJustStrippedBinaries() {
        int total = totalFunctions1;
        int matches = countQuery("select count(0) from main.functions f, diff.functions df " +
                                 "where f.address = df.address");
        // If more than 99% of the best matches share the same exact address it is
        // clear it's the same binary with very little changes like, probably, just
        // symbols stripped.
        double percent = (matches * 100.0) / total;
        if (percent >= SPEEDUP_STRIPPED_BINARIES_MIN_PERCENT) {
            log("Symbols stripped detected: A total of " + matches + " matches out of " + total + ", " +
                percent + "% percent have the same address");
            String heur = "Same binary with symbols stripped";
            String sql = "select distinct " + getQueryFields(heur) +
                         "  from functions f, diff.functions df where f.address = df.address";
            logRefresh("Finding via '" + heur + "'");
            addMatchesFromQueryRatio(sql, BEST, PARTIAL, null);
            return true;
        }
        return false;
    }

    private boolean searchPatchdiffWithSymbols() {
        int total = totalFunctions1;
        int matches = countQuery("select count(0) from main.functions f, diff.functions df " +
                                 "where f.mangled_function = df.mangled_function");
        // If more than 90% of the best matches share the same exact mangled name
        // it is clear where patch diffing 2 different versions of the same binary.
        double percent = (matches * 100.0) / total;
        if (percent > SPEEDUP_PATCH_DIFF_SYMBOLS_MIN_PERCENT) {
            isPatchDiff = true;
            log("Patch diffing detected: A total of " + matches + " matches out of " + total + ", " +
                percent + "% percent have the same name");
            return true;
        }
        return false;
    }

    private void findRemainingFunctions() {
        List<String[]> mainUnmatched = new ArrayList<>();
        List<String[]> diffUnmatched = new ArrayList<>();
        String sql = "select 'main' db_name, name, address from main.functions " +
                     " union " +
                     " select 'diff' db_name, name, address from diff.functions";
        try (Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            Set<String> dones1 = new HashSet<>();
            Set<String> dones2 = new HashSet<>();
            while (rs.next()) {
                String name = rs.getString("name");
                String ea = rs.getString("address");
                boolean isDiff = "diff".equals(rs.getString("db_name"));
                Map<String, Matched> d = isDiff ? matchedSecondary : matchedPrimary;
                if (!d.containsKey(name)) {
                    String key = ea + "\u0000" + name;
                    if ((isDiff ? dones2 : dones1).add(key)) {
                        (isDiff ? diffUnmatched : mainUnmatched).add(new String[]{ea, name});
                    }
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
            return;
        }

        if (isPatchDiff) {
            String heur = "Renamed or anonymous function match in patch diffing session";
            searchRemainingFunctions(mainUnmatched, diffUnmatched, heur, true, false,
                                     SPEEDUP_PATCH_DIFF_RENAMED_FUNCTION_MIN_RATIO);
        }
    }

    private void searchRemainingFunctions(List<String[]> mainUnmatched, List<String[]> diffUnmatched,
                                          String heur, boolean onlySub, boolean small, double val) {
        String sql = "select " + getQueryFields("?", false) +
                     "  from main.functions f, diff.functions df" +
                     " where f.address = ?" +
                     "   and df.address = ?";
        if (!small) {
            sql += " and f.nodes >= 3 and df.nodes >= 3 ";
        }
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (String[] m : mainUnmatched) {
                if (monitor.isCancelled()) return;
                if (onlySub && !m[1].startsWith("sub_")) continue;
                for (String[] d : diffUnmatched) {
                    ps.setString(1, heur);
                    ps.setString(2, m[0]);
                    ps.setString(3, d[0]);
                    try (ResultSet rs = ps.executeQuery()) {
                        addMatchesInternal(rs, BEST, PARTIAL, val);
                    }
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    // --- Iterations ---

    private void findMatchesDiffing(int iteration) {
        cleanupMatches();
        // Only if the processor is the same for both databases we diff assembly
        if (isSameProcessor) {
            findMatchesDiffingInternal("Callee found diffing matches assembly", "assembly");
        }
        findMatchesDiffingInternal("Callee found diffing matches pseudo-code", "pseudocode");
    }

    private void findMatchesDiffingInternal(String heur, String fieldName) {
        logRefresh("Finding with heuristic '" + heur + "'");
        int iteration = 1;
        Set<String> dones = new HashSet<>();
        while (iteration <= 3 && !monitor.isCancelled()) {
            int oldTotal = getTotalMatchedFunctions();

            for (String key : List.of(BEST, PARTIAL)) {
                for (Item match : getSortedResults(key)) {
                    if (monitor.isCancelled()) return;
                    String matchKey = match.name1 + "-" + match.name2;
                    if (!dones.add(matchKey)) continue;

                    Map<String, Object>[] rows = getRowForItems(match);
                    if (rows[0] != null && rows[1] != null) {
                        if (rows[0].get(fieldName) == null) continue;
                        if (rows[1].get(fieldName) == null) continue;
                        findOneMatchDiffing(rows[0], rows[1], fieldName, heur, iteration, dones);
                    }
                }
            }

            cleanupMatches();
            int newTotal = getTotalMatchedFunctions();
            if (newTotal == oldTotal) break;
            log("New iteration with heuristic '" + heur + "'...");
            iteration++;
        }
    }

    /** str.splitlines(keepends=False) */
    private static List<String> splitlines(String s) {
        List<String> out = new ArrayList<>();
        if (s == null || s.isEmpty()) return out;
        int start = 0;
        int n = s.length();
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\u000b' || c == '\u000c' || c == '\u001c' || c == '\u001d'
                    || c == '\u001e' || c == '\u0085' || c == ' ' || c == ' ') {
                out.add(s.substring(start, i));
                if (c == '\r' && i + 1 < n && s.charAt(i + 1) == '\n') i++;
                start = i + 1;
            }
        }
        if (start < n) out.add(s.substring(start));
        return out;
    }

    private static List<String> findAllNames(List<String> lines) {
        List<String> names = new ArrayList<>();
        Matcher m = CPP_NAMES_RE.matcher(String.join("\n", lines));
        while (m.find()) names.add(m.group(1));
        return names;
    }

    private List<Map<String, Object>> functionsExists(String name1, String name2) {
        String sql = "select * from ( " +
                     "  select 'main' db_name, * from main.functions where name = ? " +
                     " union " +
                     "  select 'diff' db_name, * from diff.functions where name = ? " +
                     ") order by db_name desc";
        List<Map<String, Object>> l = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, name1);
            ps.setString(2, name2);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) l.add(readFunctionRow(rs));
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
        return l;
    }

    private void findOneMatchDiffing(Map<String, Object> inputMainRow, Map<String, Object> inputDiffRow,
                                     String fieldName, String heur, int iteration, Set<String> dones) {
        List<String> mainLines = splitlines(str(inputMainRow, fieldName));
        List<String> diffLines = splitlines(str(inputDiffRow, fieldName));
        List<String> df = SideBySideDiff.unifiedDiff(mainLines, diffLines);

        List<String> minus = new ArrayList<>();
        List<String> plus = new ArrayList<>();
        for (String row : df) {
            if (row.isEmpty()) continue;
            char c = row.charAt(0);
            if (c == '-') {
                minus.add(row);
            } else if (c == '+') {
                plus.add(row);
            } else if (c == ' ') {
                if (!minus.isEmpty() && !plus.isEmpty()) {
                    List<String> matches1 = findAllNames(minus);
                    List<String> matches2 = findAllNames(plus);
                    minus = new ArrayList<>();
                    plus = new ArrayList<>();

                    int size = Math.min(matches1.size(), matches2.size());
                    for (int i = 0; i < size; i++) {
                        String name1 = matches1.get(i);
                        String name2 = matches2.get(i);
                        String key = name1 + "-" + name2;
                        if (!dones.add(key)) continue;

                        if (name1.startsWith("nullsub") || name2.startsWith("nullsub")) continue;

                        List<Map<String, Object>> l = functionsExists(name1, name2);
                        if (l.size() == 2) {
                            Map<String, Object> mainRow = l.get(0);
                            Map<String, Object> diffRow = l.get(1);
                            int n1 = intOf(mainRow, "nodes");
                            int n2 = intOf(diffRow, "nodes");
                            int minNodes = Math.min(n1, n2);
                            int maxNodes = Math.max(n1, n2);

                            // If the number of basic blocks differ in more than 75% ignore...
                            if (maxNodes == 0 || (minNodes * 100.0) / maxNodes < DIFFING_MATCHES_MAX_DIFFERENT_BBLOCKS_PERCENT) {
                                continue;
                            }
                            // High risk of false positives with small functions
                            if (n1 < DIFFING_MATCHES_MIN_BBLOCKS) continue;
                            if (n2 < DIFFING_MATCHES_MIN_BBLOCKS) continue;

                            double r = compareFunctionRows(mainRow, diffRow);
                            String chooser;
                            if (r == 1.0) {
                                chooser = BEST;
                            } else if (r > DEFAULT_TRUSTED_PARTIAL_RATIO) {
                                chooser = PARTIAL;
                            } else {
                                continue;
                            }

                            if (r + MATCHES_BONUS_RATIO < 1.0) {
                                r += MATCHES_BONUS_RATIO;
                            }

                            String heurText = heur + " (iteration #" + iteration + ")";
                            Item newItem = new Item(str(mainRow, "address"), name1, str(diffRow, "address"), name2,
                                                    heurText, r, n1, n2);
                            addMatch(name1, name2, r, newItem, chooser);
                        }
                    }
                }
            }
        }
    }

    private void findRelatedMatches(int iteration) {
        String heur = "Same constants related matches";
        cleanupMatches();
        logRefresh("Finding with heuristic '" + heur + "'");
        Set<String> dones = new HashSet<>();

        for (String key : List.of(BEST, PARTIAL)) {
            for (Item match : getSortedResults(key)) {
                if (monitor.isCancelled()) return;
                String matchKey = match.name1 + "-" + match.name2;
                if (!dones.add(matchKey)) continue;

                if (match.ratio < RELATED_MATCHES_MIN_RATIO) break;

                Map<String, Object>[] rows = getRowForItems(match);
                if (rows[0] == null || rows[1] == null) continue;

                if (intOf(rows[0], "constants_count") > 0 && intOf(rows[1], "constants_count") > 0) {
                    findRelatedConstants(rows[0], rows[1]);
                }
            }
        }
    }

    private void findRelatedConstants(Map<String, Object> mainRow, Map<String, Object> diffRow) {
        String heur = "Same constants related matches";
        Set<String> mainConsts = jsonSet(str(mainRow, "constants"));
        Set<String> diffConsts = jsonSet(str(diffRow, "constants"));
        mainConsts.retainAll(diffConsts);
        if (mainConsts.isEmpty()) return;

        String sql = " select " + getQueryFields(heur) +
                     "   from main.functions f, diff.functions df, main.constants mc, diff.constants dc" +
                     "  where f.id = mc.func_id" +
                     "    and df.id = dc.func_id" +
                     "    and dc.constant = mc.constant" +
                     "    and mc.constant = ?" +
                     "    and abs(mc.constant) == 0 ";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (String constant : mainConsts) {
                ps.setString(1, constant);
                try (ResultSet rs = ps.executeQuery()) {
                    addMatchesInternal(rs, BEST, PARTIAL, null);
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    private void findRelatedCompilationUnit(int iteration) {
        String heur = "Related compilation unit";
        cleanupMatches();
        logRefresh("Finding with heuristic '" + heur + "'");

        List<Item> l = getSortedResults(BEST);
        l.addAll(getSortedResults(PARTIAL));

        String sqlCu = "SELECT distinct cus.id cu_id, cus.name cu_name, cus.start_ea start_ea, cus.end_ea end_ea" +
                       "  FROM {db}.compilation_unit_functions cuf, {db}.compilation_units cus, {db}.functions f" +
                       " WHERE f.id = cuf.func_id AND cus.id = cuf.cu_id AND f.name = ?";
        String sqlMain = sqlCu.replace("{db}", "main");
        String sqlDiff = sqlCu.replace("{db}", "diff");
        // Diaphora-ng: the compilation units' member functions instead of their
        // address range. Without symbols, LFA-detected units interleave and each
        // range spans most of the binary, turning every query into a near full
        // cross product of both binaries (hours on urlmon.dll).
        String sql = "select " + getQueryFields(heur) +
                     "  from functions f, diff.functions df" +
                     " where f.id  in (select func_id from main.compilation_unit_functions where cu_id = ?)" +
                     "   and df.id in (select func_id from diff.compilation_unit_functions where cu_id = ?) ";

        // Many matches share the same pair of compilation units and the query of
        // a pair always returns the same rows: run it once per pair. The timeout
        // covers the whole heuristic, including the time inside each query.
        Set<String> dones = new HashSet<>();
        long t = System.currentTimeMillis();
        try (PreparedStatement psMain = conn.prepareStatement(sqlMain);
             PreparedStatement psDiff = conn.prepareStatement(sqlDiff);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            for (Item match : l) {
                if (monitor.isCancelled()) return;
                if (match.ratio < RELATED_MATCHES_MIN_RATIO) break;
                long left = SQL_TIMEOUT_LIMIT - (System.currentTimeMillis() - t) / 1000;
                if (left <= 0) {
                    log("Timeout with heuristic '" + heur + "'");
                    return;
                }

                Long cu1 = null;
                psMain.setString(1, match.name1);
                try (ResultSet rs = psMain.executeQuery()) {
                    if (rs.next()) cu1 = rs.getLong("cu_id");
                }
                Long cu2 = null;
                psDiff.setString(1, match.name2);
                try (ResultSet rs = psDiff.executeQuery()) {
                    if (rs.next()) cu2 = rs.getLong("cu_id");
                }
                if (cu1 == null || cu2 == null || !dones.add(cu1 + ":" + cu2)) {
                    continue;
                }
                ps.setLong(1, cu1);
                ps.setLong(2, cu2);
                ps.setQueryTimeout((int) left);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!addMatchesInternal(rs, BEST, PARTIAL, null, t)) {
                        return;
                    }
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (Exception e) {
            return 0;
        }
    }

    private void findLocallyAffineFunctions(int iteration) {
        cleanupMatches();
        logRefresh("Finding locally affine functions");

        List<Item> tmp = new ArrayList<>(allMatches.get(BEST));
        tmp.addAll(allMatches.get(PARTIAL));
        tmp.sort((a, b) -> {
            int c = Long.compare(parseLong(a.ea), parseLong(b.ea));
            return c != 0 ? c : Long.compare(parseLong(a.ea2), parseLong(b.ea2));
        });

        int size = tmp.size();
        for (int i = 0; i < size; i++) {
            if (monitor.isCancelled()) return;
            if (i == 0) continue;
            Item prev = tmp.get(i - 1);
            Item match = tmp.get(i);
            findFunctionsBetween(new String[]{prev.ea, match.ea}, new String[]{prev.ea2, match.ea2});
        }
    }

    private List<Map<String, Object>> functionsInRange(String db, String[] range) throws SQLException {
        String sql = "select * from " + db + ".functions where address > ? and address < ? order by address desc";
        List<Map<String, Object>> rows = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, range[0]);
            ps.setString(2, range[1]);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) rows.add(readFunctionRow(rs));
            }
        }
        return rows;
    }

    private void findFunctionsBetween(String[] range1, String[] range2) {
        String heurText = "Local affinity";
        try {
            List<Map<String, Object>> mainRows = functionsInRange("main", range1);
            int size = mainRows.size();
            if (size <= 0 || size > MAX_FUNCTIONS_PER_GAP) return;
            List<Map<String, Object>> diffRows = functionsInRange("diff", range2);
            size = diffRows.size();
            if (size <= 0 || size > MAX_FUNCTIONS_PER_GAP) return;

            Set<String> localMainMatched = new HashSet<>();
            Map<String, Double> mainScore = new HashMap<>();
            Set<String> localDiffMatched = new HashSet<>();
            Map<String, Double> diffScore = new HashMap<>();

            for (Map<String, Object> mainRow : mainRows) {
                for (Map<String, Object> diffRow : diffRows) {
                    String name1 = str(mainRow, "name");
                    String name2 = str(diffRow, "name");
                    if (name1.startsWith("nullsub_") || name2.startsWith("nullsub_")) continue;
                    if (!name1.startsWith("sub_") && !name2.startsWith("sub_")) continue;

                    int pl1 = intOf(mainRow, "pseudocode_lines");
                    int pl2 = intOf(diffRow, "pseudocode_lines");
                    if (pl1 + pl2 != 0) {
                        if (pl1 == 3 || pl2 == 3) continue;
                    }

                    double r = compareFunctionRows(mainRow, diffRow);
                    String chooser;
                    if (r == 1.0) {
                        chooser = BEST;
                    } else if (r >= DEFAULT_PARTIAL_RATIO) {
                        chooser = PARTIAL;
                    } else {
                        continue;
                    }

                    if (localMainMatched.contains(name1) && mainScore.get(name1) >= r) continue;
                    if (localDiffMatched.contains(name2) && diffScore.get(name2) >= r) continue;

                    Item newItem = new Item(str(mainRow, "address"), name1, str(diffRow, "address"), name2,
                                            heurText, r, intOf(mainRow, "nodes"), intOf(diffRow, "nodes"));
                    addMatch(name1, name2, r, newItem, chooser);

                    localMainMatched.add(name1);
                    mainScore.put(name1, r);
                    localDiffMatched.add(name2);
                    diffScore.put(name2, r);
                }
            }
        } catch (SQLException e) {
            log("Error: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------------
    // cleanup_matches, final_pass, find_unmatched
    // ------------------------------------------------------------------------

    private void cleanupMatches() {
        Map<String, Double> dones = new HashMap<>();
        Map<String, Double> eaRatios = new HashMap<>();
        Map<String, List<Item>> d = new LinkedHashMap<>();

        for (Map.Entry<String, List<Item>> e : allMatches.entrySet()) {
            List<Item> kept = new ArrayList<>();
            List<Item> items = new ArrayList<>(e.getValue());
            items.sort((a, b) -> Double.compare(b.ratio, a.ratio));
            for (Item item : items) {
                // Ignore duplicated matches (might happen due to parallelism)
                String match = item.name1 + "-" + item.name2;
                if (dones.containsKey(match)) continue;

                double ratio = item.ratio;
                if (item.name1.equals(item.name2)) {
                    ratio = 1.0;
                }
                dones.put(match, ratio);

                // If the previous ratio for a match with function @ea is worst, ignore
                // this match
                Double prev = eaRatios.get(item.ea);
                if (prev != null && prev > ratio) continue;
                eaRatios.put(item.ea, ratio);
                kept.add(item);
            }
            d.put(e.getKey(), kept);
        }

        // Update now the dict of matched functions for both databases
        matchedPrimary = new HashMap<>();
        matchedSecondary = new HashMap<>();
        for (List<Item> items : d.values()) {
            for (Item item : items) {
                matchedPrimary.put(item.name1, new Matched(item.name2, item.ratio));
                matchedSecondary.put(item.name2, new Matched(item.name1, item.ratio));
            }
        }
        allMatches = d;
    }

    private void finalPass() throws SQLException {
        cleanupMatches();

        Map<String, Double> maxMain = new HashMap<>();
        Map<String, Double> maxDiff = new HashMap<>();
        Map<String, List<Item>> multiMain = new LinkedHashMap<>();
        Map<String, List<Item>> multiDiff = new LinkedHashMap<>();

        // find_unresolved_multimatches()
        Set<String> dones = new HashSet<>();
        for (List<Item> items : allMatches.values()) {
            List<Item> l = new ArrayList<>(items);
            l.sort((a, b) -> Double.compare(b.ratio, a.ratio));
            for (Item match : l) {
                String key = match.ea + "-" + match.ea2;
                if (!dones.add(key)) continue;
                double ratio = match.ratio;

                maxMain.putIfAbsent(match.ea, ratio);
                if (maxMain.get(match.ea) > ratio) continue;
                maxMain.put(match.ea, ratio);
                multiMain.computeIfAbsent(match.ea, x -> new ArrayList<>()).add(match);

                maxDiff.putIfAbsent(match.ea2, ratio);
                if (maxDiff.get(match.ea2) > ratio) continue;
                maxDiff.put(match.ea2, ratio);
                multiDiff.computeIfAbsent(match.ea2, x -> new ArrayList<>()).add(match);
            }
        }

        Set<String> ignoreMain = new HashSet<>();
        Set<String> ignoreDiff = new HashSet<>();
        Set<String> multiDones = new HashSet<>();
        addMultimatchesToChooser(multiMain, ignoreMain, multiDones);
        addMultimatchesToChooser(multiDiff, ignoreDiff, multiDones);

        // add_final_chooser_items()
        Map<String, MatchCategory> choosers = Map.of(
            BEST, MatchCategory.BEST, PARTIAL, MatchCategory.PARTIAL, UNRELIABLE, MatchCategory.UNRELIABLE);
        for (Map.Entry<String, List<Item>> e : allMatches.entrySet()) {
            List<Item> l = new ArrayList<>(e.getValue());
            l.sort((a, b) -> Double.compare(b.ratio, a.ratio));
            for (Item match : l) {
                if (ignoreMain.contains(match.ea) || ignoreDiff.contains(match.ea2)) continue;
                if (match.ratio < maxMain.get(match.ea)) continue;
                if (match.ratio < maxDiff.get(match.ea2)) continue;
                results.get(choosers.get(e.getKey())).add(toMatchItem(match));
            }
        }
    }

    private void addMultimatchesToChooser(Map<String, List<Item>> multi, Set<String> ignoreList, Set<String> dones)
            throws SQLException {
        for (Map.Entry<String, List<Item>> e : multi.entrySet()) {
            if (e.getValue().size() > 1) {
                for (Item match : e.getValue()) {
                    String key = match.ea + "-" + match.ea2;
                    if (dones.add(key)) {
                        results.get(MatchCategory.PROBLEMATIC).add(toMatchItem(match));
                        ignoreList.add(e.getKey());
                    }
                }
            }
        }
    }

    private MatchItem toMatchItem(Item it) throws SQLException {
        MatchItem item = new MatchItem(hexAddress(it.ea), it.name1, hexAddress(it.ea2), it.name2,
                                       it.desc, it.ratio, it.nodes1, it.nodes2);
        return item;
    }

    /**
     * Diaphora stores addresses as decimal integers; the UI and the importer use
     * hexadecimal strings.
     */
    private static String hexAddress(String ea) {
        if (ea == null || ea.isEmpty()) return "";
        if (ea.startsWith("0x") || ea.startsWith("0X")) return ea;
        try {
            return "0x" + Long.toHexString(Long.parseLong(ea.trim()));
        } catch (NumberFormatException e) {
            return ea;
        }
    }

    private void findUnmatched() throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("select name, address, nodes from functions")) {
            while (rs.next()) {
                String name = rs.getString("name");
                if (!matchedPrimary.containsKey(name)) {
                    MatchItem item = new MatchItem(hexAddress(rs.getString("address")), name, "", "", "Unmatched",
                                                   0.0, rs.getInt("nodes"), 0);
                    results.get(MatchCategory.UNMATCHED_PRIMARY).add(item);
                }
            }
        }
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("select name, address, nodes from diff.functions")) {
            while (rs.next()) {
                String name = rs.getString("name");
                if (!matchedSecondary.containsKey(name)) {
                    MatchItem item = new MatchItem("", "", hexAddress(rs.getString("address")), name, "Unmatched",
                                                   0.0, 0, rs.getInt("nodes"));
                    results.get(MatchCategory.UNMATCHED_SECONDARY).add(item);
                }
            }
        }
    }

    public Map<MatchCategory, List<MatchItem>> getResults() {
        return results;
    }
}
