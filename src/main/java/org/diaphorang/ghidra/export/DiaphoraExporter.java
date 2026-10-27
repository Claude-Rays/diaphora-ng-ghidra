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

import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import org.diaphorang.ghidra.model.DiaphoraSchema;
import org.diaphorang.ghidra.util.*;

import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Exports a Ghidra Program to a Diaphora SQLite database.
 *
 * The values stored follow the conventions of diaphora_ida.py as closely as Ghidra
 * allows, because the SQL heuristics and the ratio calculations depend on them:
 *  - addresses, RVAs and callgraph addresses are stored as decimal integers;
 *  - unnamed functions are called sub_XXXX (heuristics check for 'sub_');
 *  - assembly lines do not contain absolute addresses;
 *  - bytes_hash ignores the bytes of address/immediate operands;
 *  - the topological sort uses basic block numbers, not addresses.
 */
public class DiaphoraExporter {

    private final Program program;
    private final File outputFile;
    private final boolean useDecompiler;
    /** Level 1 (util/DiffSettings); refreshFunctions() takes it from the database. */
    private boolean canonicalNames;
    private final Gson gson = new Gson();

    private Memory memory;
    private SymbolTable symbolTable;
    private FunctionManager funcManager;
    private AddressSpace defaultSpace;
    private Map<Address, String> exportNames;

    /** Hexadecimal numbers (optionally a suffix of an identifier) that may be addresses. */
    private static final Pattern HEX_ADDR_PATTERN = Pattern.compile("(0x|_)([0-9a-fA-F]{6,16})\\b");

    public DiaphoraExporter(Program program, File outputFile, boolean useDecompiler) {
        this(program, outputFile, useDecompiler, true);
    }

    public DiaphoraExporter(Program program, File outputFile, boolean useDecompiler, boolean canonicalNames) {
        this.program = program;
        this.outputFile = outputFile;
        this.useDecompiler = useDecompiler;
        this.canonicalNames = canonicalNames;
    }

    public boolean doExport(TaskMonitor monitor) throws Exception {
        if (outputFile.exists()) {
            outputFile.delete();
        }
        // Stale WAL files from a previous export would corrupt the new database
        new File(outputFile.getAbsolutePath() + "-wal").delete();
        new File(outputFile.getAbsolutePath() + "-shm").delete();

        memory = program.getMemory();
        symbolTable = program.getSymbolTable();
        funcManager = program.getFunctionManager();
        defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

        String jdbcUrl = "jdbc:sqlite:" + outputFile.getAbsolutePath();
        try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
            DiaphoraSchema.initDatabase(conn);
            conn.setAutoCommit(false);

            DecompInterface decompiler = null;
            if (useDecompiler) {
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }

            try {
                monitor.setMessage("Computing function names...");
                exportNames = computeExportNames(monitor);
                exportFunctions(conn, decompiler, monitor);
                exportProgramInfo(conn);
                monitor.setMessage("Exporting structures, unions and enumerations...");
                exportStructures(conn, monitor);
                conn.commit();

                monitor.setMessage("Generating database indices...");
                DiaphoraSchema.createIndices(conn);
                conn.commit();
            } finally {
                if (decompiler != null) {
                    decompiler.dispose();
                }
            }
        }
        return true;
    }

    // ------------------------------------------------------------------------
    // Names
    // ------------------------------------------------------------------------

    /**
     * Function names are the key used everywhere by Diaphora to track matches, so
     * they must be unique and stable between versions of the same binary.
     *
     * Function.getName() returns the name WITHOUT its namespace, so all the
     * QueryInterface/AddRef/Release/destructors of different classes would collide.
     * Use the fully qualified name and, if still duplicated (overloads), append the
     * parameter types.
     */
    private Map<Address, String> computeExportNames(TaskMonitor monitor) {
        Map<Address, String> result = new HashMap<>();
        Map<String, List<Function>> byName = new HashMap<>();

        for (Function func : funcManager.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            String name = baseExportName(func);
            result.put(func.getEntryPoint(), name);
            byName.computeIfAbsent(name, k -> new ArrayList<>()).add(func);
        }

        for (Map.Entry<String, List<Function>> e : byName.entrySet()) {
            List<Function> funcs = e.getValue();
            if (funcs.size() < 2) continue;

            Map<String, Integer> counts = new HashMap<>();
            Map<Function, String> withParams = new HashMap<>();
            for (Function f : funcs) {
                String n = e.getKey() + "(" + parameterTypes(f) + ")";
                withParams.put(f, n);
                counts.merge(n, 1, Integer::sum);
            }
            // Still duplicated (i.e. compiler generated helpers with the very same name):
            // number them in address order, which is usually preserved between builds,
            // instead of using the address itself, which is not.
            Map<String, Integer> ordinals = new HashMap<>();
            for (Function f : funcs) {
                String n = withParams.get(f);
                if (counts.get(n) > 1) {
                    int ordinal = ordinals.merge(n, 1, Integer::sum) - 1;
                    n = n + "_" + ordinal;
                }
                result.put(f.getEntryPoint(), n);
            }
        }
        return result;
    }

    private String baseExportName(Function func) {
        if (func.isThunk()) {
            Function thunked = func.getThunkedFunction(true);
            if (thunked != null && thunked != func) {
                return "j_" + baseExportName(thunked);
            }
        }
        if (isDefaultName(func)) {
            return "sub_" + Long.toHexString(func.getEntryPoint().getOffset()).toUpperCase();
        }
        return func.getName(true);
    }

    private static boolean isDefaultName(Function func) {
        Symbol sym = func.getSymbol();
        return sym == null || sym.getSource() == SourceType.DEFAULT || func.getName().startsWith("FUN_");
    }

    private static String parameterTypes(Function func) {
        StringBuilder sb = new StringBuilder();
        for (Parameter p : func.getParameters()) {
            if (sb.length() > 0) sb.append(",");
            DataType dt = p.getDataType();
            sb.append(dt != null ? dt.getDisplayName() : "?");
        }
        return sb.toString();
    }

    private String exportNameOf(Function func) {
        String n = exportNames.get(func.getEntryPoint());
        return n != null ? n : baseExportName(func);
    }

    /** The mangled name of the function, if Ghidra kept it as a secondary symbol. */
    private String mangledName(Function func, String fallback) {
        for (Symbol s : symbolTable.getSymbols(func.getEntryPoint())) {
            String n = s.getName();
            if (n.startsWith("?") || n.startsWith("_Z") || n.startsWith("__Z")) {
                return n;
            }
        }
        return fallback;
    }

    /**
     * Name of a referenced address, as Diaphora's "names" field: only user/imported
     * names, never auto-generated ones (sub_, FUN_, DAT_, LAB_...).
     */
    private String referencedName(Reference ref) {
        if (ref.isExternalReference() && ref instanceof ExternalReference) {
            ExternalLocation loc = ((ExternalReference) ref).getExternalLocation();
            return loc != null ? loc.getLabel() : null;
        }
        Address to = ref.getToAddress();
        if (to == null || !to.isMemoryAddress()) return null;

        Function f = funcManager.getFunctionAt(to);
        if (f != null) {
            if (isDefaultName(f)) return null;
            String n = exportNameOf(f);
            int pos = n.indexOf('(');
            return pos > 0 ? n.substring(0, pos) : n;
        }

        Symbol sym = symbolTable.getPrimarySymbol(to);
        if (sym != null && sym.getSource() != SourceType.DEFAULT && !sym.isDynamic()) {
            return sym.getName(true);
        }

        // Import thunks / IAT slots: pointer data with an external reference
        Data data = program.getListing().getDataAt(to);
        if (data != null) {
            Reference ext = data.getExternalReference(0);
            if (ext instanceof ExternalReference) {
                ExternalLocation loc = ((ExternalReference) ext).getExternalLocation();
                if (loc != null) return loc.getLabel();
            }
        }
        return null;
    }

    /**
     * idc.get_type() of a referenced named item: the prototype of a function or
     * the data type of a defined variable (null when it has no type).
     */
    private String referencedType(Reference ref) {
        Address to = ref.getToAddress();
        if (to == null) return null;
        Function f = funcManager.getFunctionAt(to);
        if (f == null && ref.isExternalReference() && ref instanceof ExternalReference) {
            ExternalLocation loc = ((ExternalReference) ref).getExternalLocation();
            f = loc != null ? loc.getFunction() : null;
        }
        if (f != null) {
            return f.getPrototypeString(false, false);
        }
        if (!to.isMemoryAddress()) return null;
        Data data = program.getListing().getDataAt(to);
        if (data == null || !data.isDefined()) return null;
        DataType dt = data.getDataType();
        if (dt == null || dt instanceof ghidra.program.model.data.Undefined) return null;
        return dt.getDisplayName();
    }

    // ------------------------------------------------------------------------
    // Text normalization helpers
    // ------------------------------------------------------------------------

    /**
     * Replace numbers that are addresses of the program (0x180012345, LAB_180012345,
     * s_Error_180012345...) by XXXX. Addresses change between versions of a binary,
     * so they must not take part in the comparisons.
     */
    private String maskAddresses(String text) {
        if (text == null || text.isEmpty()) return text;
        Matcher m = HEX_ADDR_PATTERN.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String repl = m.group(0);
            try {
                long val = Long.parseUnsignedLong(m.group(2), 16);
                Address a = defaultSpace.getAddress(val);
                if (memory.contains(a)) {
                    repl = m.group(1) + "XXXX";
                }
            } catch (Exception ignored) {
                // Not a valid address
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(repl));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private boolean isMemoryAddress(long value) {
        try {
            return memory.contains(defaultSpace.getAddress(value));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extract the body of Ghidra's decompiler output as Diaphora does with Hex-Rays:
     * without the prototype (first line in IDA), comments and empty lines.
     */
    /**
     * The C text of a decompilation; with 'canonical', Hex-Rays' v1, v2... instead of
     * uVar3, local_28 (LocalNames, level 1, optional: util/DiffSettings).
     */
    private static String pseudocodeText(Function func, DecompileResults results, boolean canonical) {
        if (canonical && results.getCCodeMarkup() != null) return LocalNames.canonicalC(func, results.getCCodeMarkup());
        return results.getDecompiledFunction().getC();
    }

    private static List<String> extractPseudoLines(String c) {
        String[] raw = c.split("\r?\n");
        int start = 0;
        for (int i = 0; i < raw.length; i++) {
            if (raw[i].trim().equals("{")) {
                start = i;
                break;
            }
        }
        List<String> lines = new ArrayList<>();
        for (int i = start; i < raw.length; i++) {
            String line = raw[i].stripTrailing();
            String t = line.trim();
            if (t.isEmpty()) continue;
            if (t.startsWith("/*") && t.endsWith("*/")) continue;
            if (t.startsWith("//")) continue;
            lines.add(line);
        }
        return lines;
    }

    /** Same filter as diaphora_ida.py constant_filter() (taken from REgoogle). */
    private static boolean constantFilter(long value) {
        if (Long.compareUnsigned(value, 0x1000) < 0) return false;
        if ((value & 0xFFFFFF00L) == 0xFFFFFF00L
                || (value & 0xFFFF00L) == 0xFFFF00L
                || (value & 0xFFFFFFFFFFFFFF00L) == 0xFFFFFFFFFFFFFF00L
                || (value & 0xFFFFFFFFFFFF00L) == 0xFFFFFFFFFFFF00L) {
            return false;
        }
        return Long.bitCount(value) != 1;
    }

    private static Object constantValue(long value) {
        if (value >= 0) return value;
        return new BigInteger(Long.toUnsignedString(value));
    }

    // ------------------------------------------------------------------------
    // Export
    // ------------------------------------------------------------------------

    /** Prepared statements and id counters shared by the functions of an export. */
    private final class Ctx implements AutoCloseable {
        final Connection conn;
        final DecompInterface decompiler;
        final TaskMonitor monitor;
        final Listing listing = program.getListing();
        final BasicBlockModel blockModel = new BasicBlockModel(program);
        final ReferenceManager refManager = program.getReferenceManager();
        final long imageBase = program.getImageBase().getOffset();
        final CodeUnitFormat cuFormat = CodeUnitFormat.DEFAULT;
        final PreparedStatement stmtFunc, stmtCall, stmtConst, stmtInst, stmtBB, stmtBBInst, stmtFuncBB, stmtBBRel;
        long funcId;
        long instId;
        long bbId;

        Ctx(Connection conn, DecompInterface decompiler, TaskMonitor monitor) throws java.sql.SQLException {
            this.conn = conn;
            this.decompiler = decompiler;
            this.monitor = monitor;
            stmtFunc = conn.prepareStatement(INSERT_FUNC_SQL);
            stmtCall = conn.prepareStatement("INSERT INTO callgraph (func_id, address, type) VALUES (?, ?, ?)");
            stmtConst = conn.prepareStatement("INSERT INTO constants (func_id, constant) VALUES (?, ?)");
            stmtInst = conn.prepareStatement("INSERT INTO instructions (id, func_id, address, disasm, mnemonic, " +
                "comment1, comment2, operand_names, name, type, pseudocomment, pseudoitp, asm_type) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'native')");
            stmtBB = conn.prepareStatement("INSERT INTO basic_blocks (id, num, address, asm_type) VALUES (?, ?, ?, 'native')");
            stmtBBInst = conn.prepareStatement("INSERT INTO bb_instructions (basic_block_id, instruction_id) VALUES (?, ?)");
            stmtFuncBB = conn.prepareStatement("INSERT INTO function_bblocks (function_id, basic_block_id, asm_type) VALUES (?, ?, 'native')");
            stmtBBRel = conn.prepareStatement("INSERT INTO bb_relations (parent_id, child_id) VALUES (?, ?)");
        }

        @Override
        public void close() throws java.sql.SQLException {
            for (PreparedStatement ps : new PreparedStatement[]{stmtFunc, stmtCall, stmtConst, stmtInst, stmtBB,
                                                                stmtBBInst, stmtFuncBB, stmtBBRel}) {
                ps.close();
            }
        }
    }

    private static final String INSERT_FUNC_SQL = "INSERT INTO functions (" +
            "id, name, address, nodes, edges, indegree, outdegree, size, instructions, " +
            "mnemonics, names, prototype, cyclomatic_complexity, primes_value, comment, " +
            "mangled_function, bytes_hash, pseudocode, pseudocode_lines, pseudocode_hash1, " +
            "pseudocode_primes, function_flags, assembly, prototype2, pseudocode_hash2, " +
            "pseudocode_hash3, strongly_connected, loops, rva, tarjan_topological_sort, " +
            "strongly_connected_spp, clean_assembly, clean_pseudo, mnemonics_spp, switches, " +
            "function_hash, bytes_sum, md_index, constants, constants_count, segment_rva, " +
            "assembly_addrs, kgh_hash, source_file, userdata, microcode, clean_microcode, " +
            "microcode_spp, export_time" +
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    private void exportFunctions(Connection conn, DecompInterface decompiler, TaskMonitor monitor) throws Exception {
        long totalFuncs = funcManager.getFunctionCount();
        monitor.initialize(totalFuncs);
        monitor.setMessage("Exporting functions to Diaphora SQLite...");

        try (Ctx ctx = new Ctx(conn, decompiler, monitor)) {
            FunctionIterator iter = funcManager.getFunctions(true);
            long count = 0;
            int batchCount = 0;
            while (iter.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function func = iter.next();
                count++;
                monitor.setProgress(count);
                monitor.setMessage("Exporting function (" + count + "/" + totalFuncs + "): " + func.getName());
                exportFunction(ctx, func);

                batchCount++;
                if (batchCount >= 250) {
                    conn.commit();
                    batchCount = 0;
                }
            }
            conn.commit();
        }
    }

    /**
     * refresh_function_row(): after importing names, comments and types, read the
     * functions again and replace their rows in an existing database. As
     * delete_function() in diaphora.py only the functions row is deleted; the new
     * rows get new ids.
     */
    public void refreshFunctions(Collection<Address> addresses, TaskMonitor monitor) throws Exception {
        memory = program.getMemory();
        symbolTable = program.getSymbolTable();
        funcManager = program.getFunctionManager();
        defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + outputFile.getAbsolutePath())) {
            // the rows must be named as the rest of the database
            canonicalNames = DiffSettings.exportedCanonical(conn, "main");
            conn.setAutoCommit(false);
            DecompInterface decompiler = null;
            if (useDecompiler) {
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }
            try (Ctx ctx = new Ctx(conn, decompiler, monitor)) {
                exportNames = computeExportNames(monitor);
                ctx.funcId = maxId(conn, "functions");
                ctx.instId = maxId(conn, "instructions");
                ctx.bbId = maxId(conn, "basic_blocks");
                monitor.initialize(addresses.size());
                long total = 0;
                for (Address addr : addresses) {
                    if (monitor.isCancelled()) break;
                    monitor.setMessage("Updating primary database... " + total + "/" + addresses.size());
                    monitor.setProgress(total++);
                    Function func = funcManager.getFunctionAt(addr);
                    try (PreparedStatement del = conn.prepareStatement("delete from functions where address = ?")) {
                        del.setString(1, String.valueOf(addr.getOffset()));
                        del.executeUpdate();
                    }
                    if (func != null) {
                        exportFunction(ctx, func);
                    } else {
                        Msg.warn(this, "Diaphora-ng: WARNING: Trying to save a non resolved function? " + addr);
                    }
                }
                conn.commit();
            } finally {
                if (decompiler != null) {
                    decompiler.dispose();
                }
            }
            conn.setAutoCommit(true);
            try (java.sql.Statement st = conn.createStatement()) {
                st.execute("analyze");
            }
        }
    }

    private static long maxId(Connection conn, String table) throws java.sql.SQLException {
        try (java.sql.Statement st = conn.createStatement();
             java.sql.ResultSet rs = st.executeQuery("select max(id) from " + table)) {
            return rs.next() ? rs.getLong(1) : 0;
        }
    }

    private void exportFunction(Ctx ctx, Function func) throws Exception {
        Listing listing = ctx.listing;
        BasicBlockModel blockModel = ctx.blockModel;
        ReferenceManager refManager = ctx.refManager;
        long imageBase = ctx.imageBase;
        TaskMonitor monitor = ctx.monitor;
        DecompInterface decompiler = ctx.decompiler;
        CodeUnitFormat cuFormat = ctx.cuFormat;
        PreparedStatement stmtFunc = ctx.stmtFunc;
        PreparedStatement stmtCall = ctx.stmtCall;
        PreparedStatement stmtConst = ctx.stmtConst;
        PreparedStatement stmtInst = ctx.stmtInst;
        PreparedStatement stmtBB = ctx.stmtBB;
        PreparedStatement stmtBBInst = ctx.stmtBBInst;
        PreparedStatement stmtFuncBB = ctx.stmtFuncBB;
        PreparedStatement stmtBBRel = ctx.stmtBBRel;
        {
            {


                Address entry = func.getEntryPoint();
                long entryOffset = entry.getOffset();
                MemoryBlock memBlock = memory.getBlock(entry);
                long segStart = memBlock != null ? memBlock.getStart().getOffset() : imageBase;
                String funcName = exportNameOf(func);
                int funcSize = (int) func.getBody().getNumAddresses();

                // 1. Basic blocks, sorted by address with the entry point block first
                List<CodeBlock> blocks = new ArrayList<>();
                CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), monitor);
                while (blockIter.hasNext()) {
                    blocks.add(blockIter.next());
                }
                blocks.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));
                for (int i = 0; i < blocks.size(); i++) {
                    if (blocks.get(i).contains(entry)) {
                        if (i != 0) blocks.add(0, blocks.remove(i));
                        break;
                    }
                }
                Map<Address, Integer> blockNum = new HashMap<>();
                for (int i = 0; i < blocks.size(); i++) {
                    blockNum.put(blocks.get(i).getFirstStartAddress(), i);
                }

                // 2. Instructions, block by block
                List<String> mnemonics = new ArrayList<>();
                List<String> asmLines = new ArrayList<>();
                List<String> cleanAsmLines = new ArrayList<>();
                List<Long> asmAddrs = new ArrayList<>();
                Set<String> names = new LinkedHashSet<>();
                List<Object> constants = new ArrayList<>();
                Set<Long> callees = new LinkedHashSet<>();
                List<long[]> instRows = new ArrayList<>(); // {instId, blockNum}
                List<String[]> instData = new ArrayList<>(); // {address, disasm, mnemonic, name}
                MessageDigest bytesMd5 = MessageDigest.getInstance("MD5");
                MessageDigest funcMd5 = MessageDigest.getInstance("MD5");
                long bytesSum = 0;
                int instructionCount = 0;
                int outdegree = 0;
                Set<Address> seenInst = new HashSet<>();

                for (int bnum = 0; bnum < blocks.size(); bnum++) {
                    InstructionIterator instIter = listing.getInstructions(blocks.get(bnum), true);
                    while (instIter.hasNext()) {
                        Instruction inst = instIter.next();
                        if (!seenInst.add(inst.getAddress())) continue;
                        instructionCount++;

                        String mnem = inst.getMnemonicString().toLowerCase();
                        String disasm = cuFormat.getRepresentationString(inst);
                        mnemonics.add(mnem);
                        asmLines.add(disasm);
                        cleanAsmLines.add(TextCleaner.getCmpAsm(maskAddresses(disasm)));
                        long instRva = inst.getAddress().getOffset() - imageBase;
                        asmAddrs.add(instRva);

                        byte[] bytes = inst.getBytes();
                        if (bytes != null) {
                            funcMd5.update(bytes);
                            for (byte b : bytes) {
                                bytesSum += (b & 0xFF);
                            }
                            bytesMd5.update(maskOperandBytes(inst, bytes));
                        }

                        // References: callees, names and string constants
                        String instName = null;
                        String instType = null;
                        for (Reference ref : inst.getReferencesFrom()) {
                            RefType rt = ref.getReferenceType();
                            if (rt.isCall()) {
                                outdegree++;
                                Function target = funcManager.getFunctionAt(ref.getToAddress());
                                if (target != null && target != func) {
                                    callees.add(target.getEntryPoint().getOffset());
                                }
                            }
                            if (rt.isFlow() && !rt.isCall()) continue; // jumps inside the function
                            String n = referencedName(ref);
                            if (n != null && !n.startsWith("sub_") && !n.startsWith("nullsub_")) {
                                names.add(n);
                                instName = n;
                                instType = referencedType(ref);
                            }
                            if (rt.isData()) {
                                Data d = listing.getDataAt(ref.getToAddress());
                                if (d != null && d.hasStringValue()) {
                                    Object v = d.getValue();
                                    if (v != null) {
                                        String s = v.toString();
                                        if (!constants.contains(s)) constants.add(s);
                                    }
                                }
                            }
                        }

                        // Numeric constants
                        for (int opIdx = 0; opIdx < inst.getNumOperands(); opIdx++) {
                            for (Object obj : inst.getOpObjects(opIdx)) {
                                if (!(obj instanceof Scalar)) continue;
                                long v = ((Scalar) obj).getUnsignedValue();
                                if (inst.getOperandReferences(opIdx).length > 0 || isMemoryAddress(v)) continue;
                                if (constantFilter(v)) {
                                    constants.add(constantValue(v));
                                }
                            }
                        }

                        ctx.instId++;
                        instRows.add(new long[]{ctx.instId, bnum});
                        // Instructions are stored by RVA, as diaphora_ida.py does (assembly_addrs)
                        instData.add(new String[]{
                            String.valueOf(instRva), disasm, mnem, instName, instType,
                            listing.getComment(CommentType.EOL, inst.getAddress()),
                            listing.getComment(CommentType.REPEATABLE, inst.getAddress()),
                            listing.getComment(CommentType.PRE, inst.getAddress())});
                    }
                }

                String bytesHash = toHex(bytesMd5.digest());
                String functionHash = toHex(funcMd5.digest());
                String asmText = String.join("\n", asmLines);
                String cleanAsm = String.join("\n", cleanAsmLines);
                String mnemonicsSpp = PrimeUtils.calculateMnemonicSPP(mnemonics).toString();

                // 3. CFG analysis, using basic block numbers as node identifiers
                TarjanGraph tarjan = new TarjanGraph();
                List<long[]> edgesList = new ArrayList<>();
                Map<Long, int[]> degrees = new HashMap<>();
                int nodeCount = blocks.size();
                int edgeCount = 0;

                for (int bnum = 0; bnum < blocks.size(); bnum++) {
                    tarjan.addNode(bnum);
                    degrees.putIfAbsent((long) bnum, new int[]{0, 0});
                }
                for (int bnum = 0; bnum < blocks.size(); bnum++) {
                    Set<Integer> succs = new LinkedHashSet<>();
                    CodeBlockReferenceIterator dests = blocks.get(bnum).getDestinations(monitor);
                    while (dests.hasNext()) {
                        CodeBlockReference destRef = dests.next();
                        if (destRef.getFlowType().isCall()) continue;
                        Integer dnum = blockNum.get(destRef.getDestinationAddress());
                        if (dnum != null) succs.add(dnum);
                    }
                    for (int dnum : succs) {
                        edgeCount++;
                        edgesList.add(new long[]{bnum, dnum});
                        tarjan.addEdge(bnum, dnum);
                        degrees.get((long) bnum)[1]++;
                        degrees.get((long) dnum)[0]++;
                    }
                }

                int indegree = 0;
                Set<Long> callers = new LinkedHashSet<>();
                ReferenceIterator refToIter = refManager.getReferencesTo(entry);
                while (refToIter.hasNext()) {
                    Reference r = refToIter.next();
                    indegree++;
                    Function caller = funcManager.getFunctionContaining(r.getFromAddress());
                    if (caller != null) {
                        callers.add(caller.getEntryPoint().getOffset());
                    }
                }

                int cyclomaticComplexity = Math.max(1, edgeCount - nodeCount + 2);
                int loops = tarjan.countLoops();
                List<List<Long>> scc = tarjan.getStronglyConnectedComponents();
                BigInteger sccSpp = BigInteger.ONE;
                for (List<Long> comp : scc) {
                    if (comp.size() > 1) {
                        sccSpp = sccSpp.multiply(BigInteger.valueOf(PrimeUtils.getPrime(comp.size())));
                    }
                }
                int sccCount = scc.size();
                List<List<Long>> topoSort = tarjan.getRobustTopologicalSort();
                for (List<Long> comp : topoSort) {
                    Collections.sort(comp);
                }

                Map<Long, Integer> topoOrder = new HashMap<>();
                for (int i = 0; i < topoSort.size(); i++) {
                    for (Long node : topoSort.get(i)) {
                        topoOrder.put(node, i);
                    }
                }

                double mdIndexVal = MDIndex.calculate(edgesList, topoOrder, degrees);
                String mdIndexStr = String.valueOf(mdIndexVal);

                // 4. Decompilation
                String pseudocode = null;
                int pseudoLines = 0;
                String pseudoHash1 = null;
                String pseudoHash2 = null;
                String pseudoHash3 = null;
                String pseudoPrimes = null;
                String cleanPseudo = null;

                if (decompiler != null) {
                    try {
                        DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
                        if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                            String c = pseudocodeText(func, results, canonicalNames);
                            if (c != null) {
                                List<String> lines = extractPseudoLines(c);
                                if (!lines.isEmpty()) {
                                    pseudocode = String.join("\n", lines);
                                    pseudoLines = lines.size();
                                    cleanPseudo = TextCleaner.getCmpPseudoLines(maskAddresses(pseudocode));
                                    pseudoPrimes = PrimeUtils.calculatePseudocodeSPP(pseudocode).toString();

                                    String[] fHashes = KoretFuzzy.hashString(pseudocode, 512).split(";", -1);
                                    if (fHashes.length >= 1 && !fHashes[0].isEmpty()) pseudoHash1 = fHashes[0];
                                    if (fHashes.length >= 2 && !fHashes[1].isEmpty()) pseudoHash2 = fHashes[1];
                                    if (fHashes.length >= 3 && !fHashes[2].isEmpty()) pseudoHash3 = fHashes[2];
                                }
                            }
                        }
                    } catch (Exception e) {
                        // Decompilation failure is gracefully caught
                    }
                }

                // 5. Insert the function
                ctx.funcId++;
                int p = 1;
                stmtFunc.setLong(p++, ctx.funcId);
                stmtFunc.setString(p++, funcName);
                stmtFunc.setString(p++, String.valueOf(entryOffset));
                stmtFunc.setInt(p++, nodeCount);
                stmtFunc.setInt(p++, edgeCount);
                stmtFunc.setInt(p++, indegree);
                stmtFunc.setInt(p++, outdegree);
                stmtFunc.setInt(p++, funcSize);
                stmtFunc.setInt(p++, instructionCount);
                stmtFunc.setString(p++, gson.toJson(mnemonics));
                stmtFunc.setString(p++, gson.toJson(names));
                stmtFunc.setString(p++, func.getPrototypeString(true, false));
                stmtFunc.setInt(p++, cyclomaticComplexity);
                stmtFunc.setString(p++, String.valueOf(PrimeUtils.getPrime(cyclomaticComplexity)));
                setNullableString(stmtFunc, p++, func.getComment());
                stmtFunc.setString(p++, mangledName(func, funcName));
                stmtFunc.setString(p++, bytesHash);
                setNullableString(stmtFunc, p++, pseudocode);
                stmtFunc.setInt(p++, pseudoLines);
                setNullableString(stmtFunc, p++, pseudoHash1);
                setNullableString(stmtFunc, p++, pseudoPrimes);
                stmtFunc.setInt(p++, 0); // function_flags
                stmtFunc.setString(p++, asmText);
                stmtFunc.setString(p++, prototype2(func));
                setNullableString(stmtFunc, p++, pseudoHash2);
                setNullableString(stmtFunc, p++, pseudoHash3);
                stmtFunc.setInt(p++, sccCount);
                stmtFunc.setInt(p++, loops);
                stmtFunc.setLong(p++, entryOffset - imageBase);
                stmtFunc.setString(p++, gson.toJson(topoSort));
                stmtFunc.setString(p++, sccSpp.toString());
                stmtFunc.setString(p++, cleanAsm);
                setNullableString(stmtFunc, p++, cleanPseudo);
                stmtFunc.setString(p++, mnemonicsSpp);
                stmtFunc.setString(p++, "[]"); // switches
                stmtFunc.setString(p++, functionHash);
                stmtFunc.setLong(p++, bytesSum);
                stmtFunc.setString(p++, mdIndexStr);
                stmtFunc.setString(p++, gson.toJson(constants));
                stmtFunc.setInt(p++, constants.size());
                stmtFunc.setLong(p++, entryOffset - segStart);
                stmtFunc.setString(p++, gson.toJson(asmAddrs));
                stmtFunc.setNull(p++, java.sql.Types.VARCHAR);   // kgh_hash — IDA/KOKA exclusive
                stmtFunc.setString(p++, ""); // source_file
                stmtFunc.setString(p++, ""); // userdata
                stmtFunc.setNull(p++, java.sql.Types.VARCHAR);   // microcode — IDA Hex-Rays exclusive
                stmtFunc.setNull(p++, java.sql.Types.VARCHAR);   // clean_microcode — IDA Hex-Rays exclusive
                stmtFunc.setNull(p++, java.sql.Types.VARCHAR);   // microcode_spp — IDA Hex-Rays exclusive
                stmtFunc.setDouble(p++, System.currentTimeMillis() / 1000.0);
                stmtFunc.executeUpdate();

                // 6. Callgraph
                for (Long caller : callers) {
                    stmtCall.setLong(1, ctx.funcId);
                    stmtCall.setString(2, String.valueOf(caller));
                    stmtCall.setString(3, "caller");
                    stmtCall.addBatch();
                }
                for (Long callee : callees) {
                    stmtCall.setLong(1, ctx.funcId);
                    stmtCall.setString(2, String.valueOf(callee));
                    stmtCall.setString(3, "callee");
                    stmtCall.addBatch();
                }
                stmtCall.executeBatch();

                // 7. Constants (strings only when longer than 4 chars, as Diaphora does)
                for (Object constant : constants) {
                    if (constant instanceof String && ((String) constant).length() <= 4) continue;
                    stmtConst.setLong(1, ctx.funcId);
                    stmtConst.setString(2, constant.toString());
                    stmtConst.addBatch();
                }
                stmtConst.executeBatch();

                // 8. Instructions and basic blocks
                long firstBB = ctx.bbId + 1;
                for (int bnum = 0; bnum < blocks.size(); bnum++) {
                    ctx.bbId++;
                    stmtBB.setLong(1, ctx.bbId);
                    stmtBB.setInt(2, bnum);
                    stmtBB.setString(3, String.valueOf(blocks.get(bnum).getFirstStartAddress().getOffset() - imageBase));
                    stmtBB.addBatch();
                    stmtFuncBB.setLong(1, ctx.funcId);
                    stmtFuncBB.setLong(2, ctx.bbId);
                    stmtFuncBB.addBatch();
                }
                stmtBB.executeBatch();
                stmtFuncBB.executeBatch();

                for (long[] edge : edgesList) {
                    stmtBBRel.setLong(1, firstBB + edge[0]);
                    stmtBBRel.setLong(2, firstBB + edge[1]);
                    stmtBBRel.addBatch();
                }
                stmtBBRel.executeBatch();

                for (int i = 0; i < instRows.size(); i++) {
                    long[] row = instRows.get(i);
                    String[] data = instData.get(i);
                    stmtInst.setLong(1, row[0]);
                    stmtInst.setLong(2, ctx.funcId);
                    stmtInst.setString(3, data[0]);
                    stmtInst.setString(4, data[1]);
                    stmtInst.setString(5, data[2]);
                    setNullableString(stmtInst, 6, data[5]);   // comment1: regular (EOL) comment
                    setNullableString(stmtInst, 7, data[6]);   // comment2: repeatable comment
                    stmtInst.setString(8, "[]");               // operand_names: no forced operands in Ghidra
                    setNullableString(stmtInst, 9, data[3]);   // name
                    setNullableString(stmtInst, 10, data[4]);  // type
                    setNullableString(stmtInst, 11, data[7]);  // pseudocomment: PRE comments, shown by the decompiler
                    stmtInst.addBatch();
                    stmtBBInst.setLong(1, firstBB + row[1]);
                    stmtBBInst.setLong(2, row[0]);
                    stmtBBInst.addBatch();
                }
                stmtInst.executeBatch();
                stmtBBInst.executeBatch();
            }
        }
    }

    /**
     * Zero the bits of the operands that encode addresses, immediates or
     * displacements, like Diaphora does when calculating bytes_hash (it only
     * hashes the bytes before the first memory/immediate operand). This way the
     * hash survives relocations and changes of call/jump targets.
     */
    private static byte[] maskOperandBytes(Instruction inst, byte[] bytes) {
        byte[] masked = bytes.clone();
        try {
            InstructionPrototype proto = inst.getPrototype();
            for (int op = 0; op < inst.getNumOperands(); op++) {
                int type = inst.getOperandType(op);
                boolean volatileOp = (type & (OperandType.ADDRESS | OperandType.SCALAR
                        | OperandType.RELATIVE | OperandType.IMMEDIATE)) != 0
                        || inst.getOperandReferences(op).length > 0;
                if (!volatileOp) continue;
                Mask mask = proto.getOperandValueMask(op);
                if (mask == null) continue;
                byte[] mb = mask.getBytes();
                for (int i = 0; i < masked.length && i < mb.length; i++) {
                    masked[i] &= (byte) ~mb[i];
                }
            }
        } catch (Exception e) {
            // Fall back to the raw bytes
        }
        return masked;
    }

    /** Prototype without the function name, comparable between versions. */
    private static String prototype2(Function func) {
        DataType ret = func.getReturnType();
        return (ret != null ? ret.getDisplayName() : "undefined") + "(" + parameterTypes(func) + ")";
    }

    private static void setNullableString(PreparedStatement stmt, int idx, String value) throws java.sql.SQLException {
        if (value != null) {
            stmt.setString(idx, value);
        } else {
            stmt.setNull(idx, java.sql.Types.VARCHAR);
        }
    }

    private static String toHex(byte[] hash) {
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * export_structures(): the local types (structures, unions and enumerations)
     * of the program as C definitions in program_data. Ghidra has no type
     * libraries (TILs), so no 'til' rows are exported.
     */
    private void exportStructures(Connection conn, TaskMonitor monitor) throws Exception {
        String sql = "insert into main.program_data (name, type, value) values (?, ?, ?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
            while (it.hasNext()) {
                if (monitor.isCancelled()) break;
                DataType dt = it.next();
                String typeName;
                if (dt instanceof ghidra.program.model.data.Union) {
                    typeName = "union";
                } else if (dt instanceof ghidra.program.model.data.Structure) {
                    typeName = "struct";
                } else if (dt instanceof ghidra.program.model.data.Enum) {
                    typeName = "enum";
                } else {
                    continue;
                }
                String definition = typeDefinition(dt);
                if (definition == null) continue;
                ps.setString(1, dt.getName());
                ps.setString(2, typeName);
                ps.setString(3, definition);
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }

    /**
     * decompile_and_get(): the current prototype and pseudo-code of a function,
     * as "prototype\npseudocode" (null if it cannot be decompiled). 'canonical':
     * level 1, as the database it is compared with was exported.
     */
    public static String decompileWithPrototype(Program program, Function func, TaskMonitor monitor,
                                                boolean canonical) {
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(program)) return null;
            DecompileResults res = decompiler.decompileFunction(func, 60, monitor);
            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) return null;
            String c = pseudocodeText(func, res, canonical);
            if (c == null) return null;
            List<String> lines = extractPseudoLines(c);
            return func.getPrototypeString(true, false) + "\n" + String.join("\n", lines);
        } finally {
            decompiler.dispose();
        }
    }

    /** C definition of a data type (and the types it depends on), as Ghidra's "Export C". */
    public static String typeDefinition(DataType dt) {
        try {
            java.io.StringWriter sw = new java.io.StringWriter();
            ghidra.program.model.data.DataTypeWriter writer =
                new ghidra.program.model.data.DataTypeWriter(null, sw, false);
            writer.write(List.of(dt), TaskMonitor.DUMMY, false);
            String s = sw.toString().trim();
            return s.isEmpty() ? null : s;
        } catch (Exception e) {
            return null;
        }
    }

    private void exportProgramInfo(Connection conn) throws Exception {
        String sql = "INSERT INTO program (callgraph_primes, callgraph_all_primes, processor, md5sum) " +
                     "VALUES ('1', '{}', ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, program.getLanguage().getProcessor().toString());
            stmt.setString(2, program.getExecutableMD5());
            stmt.executeUpdate();
        }
        // how the pseudo-code was named, for the diff views (util/DiffSettings)
        if (useDecompiler) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "insert into main.program_data (name, type, value) values (?, ?, ?)")) {
                ps.setString(1, DiffSettings.CANONICAL_ROW);
                ps.setString(2, DiffSettings.EXPORT_OPTION);
                ps.setString(3, canonicalNames ? "1" : "0");
                ps.executeUpdate();
            }
        }
    }
}
