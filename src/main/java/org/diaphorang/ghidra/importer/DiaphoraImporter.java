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
package org.diaphorang.ghidra.importer;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.TaskMonitor;
import org.diaphorang.ghidra.diff.DiffDatabases;
import org.diaphorang.ghidra.model.MatchItem;
import org.diaphorang.ghidra.util.SideBySideDiff;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;

/**
 * Import names, comments, prototypes and types from the diffed (secondary)
 * database into the current program. Port of the import related parts of
 * diaphora_ida.CIDABinDiff / diaphora-idafree importer.cpp.
 *
 * Ghidra adaptations: there are no type libraries (TILs), function flags or
 * forced operands; pseudo-code comments are PRE comments, which the decompiler
 * shows; mangled names are demangled to recreate their namespaces.
 */
public class DiaphoraImporter {

    /** config.CLEANING_CMP_REPS: prefixes of IDA's auto-generated names. */
    private static final String[] CLEANING_CMP_REPS = {
        "loc_", "j_nullsub_", "nullsub_", "j_sub_", "sub_",
        "qword_", "dword_", "byte_", "word_", "off_", "def_", "unk_", "asc_",
        "stru_", "dbl_", "locret_", "flt_", "jpt_",
    };

    private final Program program;
    private final DiffDatabases dbs;
    private final DataTypeManagerService dtmService;
    private final TaskMonitor monitor;
    private Connection conn;

    public DiaphoraImporter(Program program, DiffDatabases dbs, DataTypeManagerService dtmService,
                            TaskMonitor monitor) {
        this.program = program;
        this.dbs = dbs;
        this.dtmService = dtmService;
        this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
    }

    private void log(String msg) {
        Msg.info(this, "Diaphora-ng: " + msg);
    }

    private Connection conn() throws SQLException {
        if (conn == null || conn.isClosed()) {
            conn = dbs.open();
        }
        return conn;
    }

    public void close() {
        try {
            if (conn != null) conn.close();
        } catch (SQLException ignored) {
        }
        conn = null;
    }

    private List<Map<String, String>> query(String sql, Object... args) throws SQLException {
        return DiffDatabases.query(conn(), sql, args);
    }

    /** Run @body inside a program transaction. */
    private <T> T inTransaction(String name, java.util.concurrent.Callable<T> body) throws Exception {
        int tx = program.startTransaction(name);
        boolean ok = false;
        try {
            T r = body.call();
            ok = true;
            return r;
        } finally {
            program.endTransaction(tx, ok);
        }
    }

    // ------------------------------------------------------------------------
    // Type libraries and definitions
    // ------------------------------------------------------------------------

    /** import_til(): IDA type libraries cannot be loaded in Ghidra, they are only logged. */
    public void importTil() throws SQLException {
        log("Importing type libraries...");
        for (Map<String, String> row : query("select name from diff.program_data where type = 'til'")) {
            log("Error loading TIL " + row.get("name") + ": type libraries are not supported by Ghidra");
        }
    }

    /** get_struc_id(): a defined structure or union with that name. */
    private boolean strucExists(String name) {
        List<DataType> found = new ArrayList<>();
        program.getDataTypeManager().findDataTypes(name, found);
        for (DataType dt : found) {
            if (dt instanceof Composite && !dt.isNotYetDefined()) {
                return true;
            }
        }
        return false;
    }

    /** get_valid_definition() */
    public static String getValidDefinition(String defs) {
        if (defs == null) return "";
        return defs.replace("?", "_").replace("@", "_").replace("$", "_");
    }

    private void parseDecls(String text) {
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CParser parser = new CParser(dtm, true, new DataTypeManager[]{dtm});
            parser.parse(text);
        } catch (Throwable t) {
            // idc.parse_decls() errors are ignored by Diaphora
        }
    }

    /** import_definitions(): structures, unions and enumerations. */
    public void importDefinitions() throws Exception {
        List<Map<String, String>> rows = query(
            "select type, name, value from diff.program_data where type in ('structure', 'struct', 'enum', 'union')");
        inTransaction("Diaphora-ng: import definitions", () -> {
            List<Map<String, String>> newRows = new ArrayList<>();
            for (Map<String, String> row : rows) {
                if (row.get("name") == null) continue;
                String theName = row.get("name").split(" ")[0];
                if (!strucExists(theName)) {
                    String typeName = "struct";
                    if ("enum".equals(row.get("type"))) {
                        typeName = "enum";
                    } else if ("union".equals(row.get("type"))) {
                        typeName = "union";
                    }
                    newRows.add(row);
                    parseDecls(typeName + " " + row.get("name") + ";");
                }
            }

            for (int i = 0; i < 10; i++) {
                for (Map<String, String> row : newRows) {
                    String theName = row.get("name").split(" ")[0];
                    if (!strucExists(theName) && !strucExists(row.get("name"))) {
                        parseDecls(getValidDefinition(row.get("value")));
                    }
                }
            }
            return null;
        });
    }

    // ------------------------------------------------------------------------
    // Instruction level
    // ------------------------------------------------------------------------

    /** [ea, cmt1, cmt2, operand_names, name, type, dis, cmt, itp] */
    private static final class InsSym {
        String ea, cmt1, cmt2, name, type, dis, cmt, itp;
        final List<Map.Entry<Integer, String>> operandNames = new ArrayList<>();
    }

    private static Map<String, InsSym> loadSyms(List<Map<String, String>> rows) {
        Map<String, InsSym> out = new HashMap<>();
        for (Map<String, String> row : rows) {
            InsSym s = new InsSym();
            s.ea = row.get("ea");
            s.cmt1 = row.get("cmt1");
            s.cmt2 = row.get("cmt2");
            String ops = row.get("operand_names");
            if (ops != null) {
                try {
                    JsonElement j = JsonParser.parseString(ops);
                    if (j.isJsonArray()) {
                        for (JsonElement op : j.getAsJsonArray()) {
                            if (op.isJsonArray() && op.getAsJsonArray().size() == 2) {
                                JsonArray a = op.getAsJsonArray();
                                s.operandNames.add(Map.entry(a.get(0).getAsInt(), a.get(1).getAsString()));
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
            s.name = row.get("name");
            s.type = row.get("type");
            s.dis = row.get("dis");
            s.cmt = row.get("cmt");
            s.itp = row.get("itp");
            out.put(s.ea, s);
        }
        return out;
    }

    /**
     * row_is_importable(): note that the python version checks the 7th field
     * (the disassembly, never None) as the pseudo-code comment, so any row with
     * some importable data in the secondary database is importable.
     */
    private static boolean rowIsImportable(String ea2, Map<String, InsSym> importSyms) {
        InsSym s = importSyms.get(ea2);
        if (s == null) return false;
        if (s.cmt1 != null || s.cmt2 != null) return true;
        for (Map.Entry<Integer, String> op : s.operandNames) {
            if (!op.getValue().isEmpty()) return true;
        }
        if (s.name != null) return true;
        return s.dis != null || s.cmt != null;
    }

    static boolean isAutoGenerated(String name) {
        for (String rep : CLEANING_CMP_REPS) {
            if (name.startsWith(rep)) return true;
        }
        return false;
    }

    /** get_ea_name() */
    private String currentName(Address ea) {
        Symbol sym = program.getSymbolTable().getPrimarySymbol(ea);
        return sym != null ? sym.getName(true) : "";
    }

    /** Auto-generated names: IDA's ones and Ghidra's default (FUN_, DAT_, LAB_...) symbols. */
    private boolean currentNameIsAuto(Address ea) {
        Symbol sym = program.getSymbolTable().getPrimarySymbol(ea);
        if (sym == null) return false;
        return sym.getSource() == SourceType.DEFAULT || isAutoGenerated(sym.getName());
    }

    /** ea in self.names: the address has a user given or imported name. */
    private boolean hasName(Address ea) {
        Symbol sym = program.getSymbolTable().getPrimarySymbol(ea);
        return sym != null && sym.getSource() != SourceType.DEFAULT && !sym.isDynamic();
    }

    /** set_name(ea, name, SN_CHECK) */
    private boolean setName(Address ea, String name) {
        Function f = program.getFunctionManager().getFunctionAt(ea);
        if (f != null) {
            return renameFunction(f, name);
        }
        try {
            SymbolTable st = program.getSymbolTable();
            Symbol sym = st.getPrimarySymbol(ea);
            if (sym != null && sym.getSource() != SourceType.DEFAULT && !sym.isDynamic()) {
                sym.setName(name, SourceType.IMPORTED);
            } else {
                Symbol label = st.createLabel(ea, name, SourceType.IMPORTED);
                label.setPrimary();
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Address rvaToAddress(String rva) {
        long v = Long.parseLong(rva.trim());
        return program.getImageBase().add(v);
    }

    private void importInstruction(InsSym insData1, InsSym insData2) {
        Address ea1 = rvaToAddress(insData1.ea);
        Listing listing = program.getListing();

        // Set instruction level comments
        if (insData2.cmt1 != null && listing.getComment(CommentType.EOL, ea1) == null) {
            listing.setComment(ea1, CommentType.EOL, insData2.cmt1);
        }
        if (insData2.cmt2 != null && listing.getComment(CommentType.REPEATABLE, ea1) == null) {
            listing.setComment(ea1, CommentType.REPEATABLE, insData2.cmt2);
        }

        // Ghidra has no forced operands (set_forced_operand): operand names are not imported.

        // Pseudo-code comments: the decompiler shows the PRE comments
        if (insData2.cmt != null) {
            listing.setComment(ea1, CommentType.PRE, insData2.cmt);
        }

        String name = insData2.name;
        boolean hasNewName = name != null && !name.isEmpty();
        Address tmpEa = null;
        boolean theType = false;

        Instruction inst = listing.getInstructionAt(ea1);
        List<Address> dataRefs = new ArrayList<>();
        List<Address> farCodeRefs = new ArrayList<>();
        List<Address> codeRefs = new ArrayList<>();
        if (inst != null) {
            for (Reference ref : inst.getReferencesFrom()) {
                RefType rt = ref.getReferenceType();
                if (!ref.getToAddress().isMemoryAddress()) continue;
                if (rt.isData()) {
                    dataRefs.add(ref.getToAddress());
                } else if (rt.isFlow()) {
                    farCodeRefs.add(ref.getToAddress());
                    codeRefs.add(ref.getToAddress());
                }
            }
            // get_first_cref_from() also returns the ordinary flow
            Address fall = inst.getFallThrough();
            if (fall != null) codeRefs.add(0, fall);
        }

        if (!dataRefs.isEmpty()) {
            // Global variables
            tmpEa = dataRefs.get(0);
            if (hasName(tmpEa)) {
                String currName = currentName(tmpEa);
                if (hasNewName && !currName.equals(name) && currentNameIsAuto(tmpEa)) {
                    setName(tmpEa, name);
                }
                theType = false;
            } else {
                // If it's an object, we don't want to rename the offset, we want to
                // rename the true global variable.
                Data d = listing.getDataAt(tmpEa);
                if (d != null && d.isPointer()) {
                    Reference[] next = d.getReferencesFrom();
                    if (next.length > 0 && next[0].getToAddress().isMemoryAddress()) {
                        tmpEa = next[0].getToAddress();
                    }
                }
                if (hasNewName) {
                    setName(tmpEa, name);
                }
                theType = true;
            }
        } else {
            // Functions
            List<Address> refs = !farCodeRefs.isEmpty() ? farCodeRefs : codeRefs;
            if (!refs.isEmpty()) {
                String currName = currentName(refs.get(0));
                if (hasNewName && !currName.equals(name) && currentNameIsAuto(refs.get(0))) {
                    setName(refs.get(0), name);
                    tmpEa = refs.get(0);
                    theType = true;
                }
            }
        }

        if (tmpEa != null && theType && insData2.type != null) {
            String current = currentType(tmpEa);
            if (!insData2.type.equals(current)) {
                setType(tmpEa, insData2.type);
            }
        }
    }

    private String currentType(Address ea) {
        Function f = program.getFunctionManager().getFunctionAt(ea);
        if (f != null) return f.getPrototypeString(false, false);
        Data d = program.getListing().getDataAt(ea);
        if (d != null && d.isDefined()) return d.getDataType().getDisplayName();
        return null;
    }

    /** idc.SetType(): parse the declaration and apply it. */
    boolean setType(Address ea, String decl) {
        if (decl == null || decl.isEmpty()) return false;
        Function f = program.getFunctionManager().getFunctionAt(ea);
        if (f != null) {
            return applyPrototype(f, decl);
        }
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataTypeParser parser = new DataTypeParser(dtm, dtm, dtmService, DataTypeParser.AllowedDataTypes.FIXED_LENGTH);
            String text = decl.endsWith(";") ? decl.substring(0, decl.length() - 1) : decl;
            DataType dt = parser.parse(text.trim());
            if (dt == null) return false;
            DataUtilities.createData(program, ea, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
            return true;
        } catch (CodeUnitInsertionException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /** Apply a C prototype to a function without renaming it. */
    private boolean applyPrototype(Function f, String decl) {
        String text = decl.trim();
        if (text.endsWith(";")) text = text.substring(0, text.length() - 1);
        FunctionDefinitionDataType sig = parseSignature(text);
        if (sig == null) {
            // IDA prototypes may not have a name: "int __stdcall(HWND)"
            int pos = text.indexOf('(');
            if (pos > 0) {
                sig = parseSignature(text.substring(0, pos) + " diaphora_f" + text.substring(pos));
            }
        }
        if (sig == null) return false;
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), sig,
            SourceType.IMPORTED, true, false, DataTypeConflictHandler.DEFAULT_HANDLER, FunctionRenameOption.NO_CHANGE);
        return cmd.applyTo(program, monitor);
    }

    private FunctionDefinitionDataType parseSignature(String text) {
        try {
            return CParserUtils.parseSignature(dtmService, program, text, false);
        } catch (Throwable t) {
            return null;
        }
    }

    private void importInstructionLevel(String ea1, String ea2) throws SQLException {
        // Check first if we have any importable items
        List<Map<String, String>> importRows = query(
            " select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, " +
            "        ins.operand_names operand_names, ins.name name, ins.type type, " +
            "        ins.pseudocomment cmt, ins.pseudoitp itp " +
            "   from diff.function_bblocks bb, diff.functions f, diff.bb_instructions bbi, diff.instructions ins " +
            "  where f.id = bb.function_id " +
            "    and bbi.basic_block_id = bb.basic_block_id " +
            "    and ins.id = bbi.instruction_id " +
            "    and f.address = ? " +
            "    and (ins.comment1 is not null " +
            "     or ins.comment2 is not null " +
            "     or ins.operand_names is not null " +
            "     or ins.name is not null " +
            "     or pseudocomment is not null) ", ea2);
        if (importRows.isEmpty()) return;
        Map<String, InsSym> importSyms = loadSyms(importRows);

        // Check in the current database
        List<Map<String, String>> matchRows = query(
            " select distinct ins.address ea, ins.disasm dis, ins.comment1 cmt1, ins.comment2 cmt2, " +
            "        ins.operand_names operand_names, ins.name name, ins.type type, " +
            "        ins.pseudocomment cmt, ins.pseudoitp itp " +
            "   from function_bblocks bb, functions f, bb_instructions bbi, instructions ins " +
            "  where f.id = bb.function_id " +
            "    and bbi.basic_block_id = bb.basic_block_id " +
            "    and ins.id = bbi.instruction_id " +
            "    and f.address = ?", ea1);
        if (matchRows.isEmpty()) return;
        Map<String, InsSym> matchedSyms = loadSyms(matchRows);

        // We have 'something' to import, let's diff the assembly...
        List<Map<String, String>> diffRows = query(
            "select * from (" +
            "  select assembly, assembly_addrs, 1 side from functions " +
            "   where address = ? and assembly is not null " +
            "  union select assembly, assembly_addrs, 2 side from diff.functions " +
            "   where address = ? and assembly is not null) " +
            " order by side asc", ea1, ea2);
        if (diffRows.size() != 2) return;

        try {
            List<String[]> pairs = alignLines(diffRows.get(0).get("assembly"), diffRows.get(0).get("assembly_addrs"),
                                              diffRows.get(1).get("assembly"), diffRows.get(1).get("assembly_addrs"));
            for (String[] pair : pairs) {
                String sEa1 = pair[0];
                String sEa2 = pair[1];
                boolean changed = pair[2] != null;
                boolean importable = rowIsImportable(sEa2, importSyms);
                if (changed || importable) {
                    InsSym m1 = matchedSyms.get(sEa1);
                    InsSym i2 = importSyms.get(sEa2);
                    if (m1 != null && i2 != null) importInstruction(m1, i2);
                    InsSym m2 = matchedSyms.get(sEa2);
                    InsSym i1 = importSyms.get(sEa1);
                    if (m2 != null && i1 != null) importInstruction(m2, i1);
                }
            }
        } catch (Exception e) {
            log("Error importing item: " + e);
        }
    }

    /**
     * do_import_instruction_level_item(): which instruction (assembly_addrs value)
     * of the primary function matches which one of the secondary function, by
     * diffing their assembly as difflib._mdiff does. Every result is
     * {ea1, ea2, changed}, changed being non null for whole line changes.
     */
    static List<String[]> alignLines(String asm1, String addrsJson1, String asm2, String addrsJson2) {
        JsonArray addrs1 = JsonParser.parseString(addrsJson1).getAsJsonArray();
        JsonArray addrs2 = JsonParser.parseString(addrsJson2).getAsJsonArray();
        List<String> lines1 = splitLines(asm1);
        List<String> lines2 = splitLines(asm2);
        List<String[]> out = new ArrayList<>();
        for (SideBySideDiff.Row x : SideBySideDiff.diff(lines1, lines2)) {
            if (x.lno == 0 || x.rno == 0) continue;
            if (x.lno > addrs1.size() || x.rno > addrs2.size()) continue;
            // At this point, we know which line number matches with which another
            // line number in both databases.
            out.add(new String[]{addrs1.get(x.lno - 1).toString(), addrs2.get(x.rno - 1).toString(),
                                 x.fullChange ? "changed" : null});
        }
        return out;
    }

    private static List<String> splitLines(String s) {
        return Arrays.asList(s.split("\r\n|\r|\n", -1));
    }

    // ------------------------------------------------------------------------
    // Function level
    // ------------------------------------------------------------------------

    private Address eaToAddress(String ea) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(ea));
    }

    /** do_import_one(): name, prototype, comment and instruction level data. */
    private void doImportOne(String ea1, String ea2, boolean force) throws SQLException {
        List<Map<String, String>> rows = query(
            "select prototype, comment, mangled_function, function_flags from diff.functions where address = ?", ea2);
        if (rows.isEmpty()) return;
        Map<String, String> row = rows.get(0);
        Address addr1 = eaToAddress(ea1);
        Function func = program.getFunctionManager().getFunctionAt(addr1);

        String name = row.get("mangled_function");
        if (name != null && (!name.startsWith("sub_") || force)) {
            if (!setFunctionName(addr1, func, name)) {
                for (int i = 0; i < 10; i++) {
                    if (setFunctionName(addr1, func, name + "_" + i)) break;
                }
            }
        }

        String proto = row.get("prototype");
        if (proto != null && !proto.equals("int()") && func != null) {
            applyPrototype(func, proto);
        }

        String comment = row.get("comment");
        if (comment != null && !comment.isEmpty() && func != null) {
            func.setComment(comment);
        }

        // function_flags are IDA flags (func_t::flags), they don't exist in Ghidra.

        importInstructionLevel(ea1, ea2);
    }

    /** set_name(ea1, mangled_function, SN_NOWARN | SN_NOCHECK) */
    private boolean setFunctionName(Address addr, Function func, String name) {
        if (name.startsWith("?") || name.startsWith("_Z") || name.startsWith("__Z")) {
            if (applyMangled(addr, name)) return true;
        }
        if (func != null) {
            return renameFunction(func, name);
        }
        return setName(addr, name);
    }

    /** Keep the mangled name as a label and apply the demangled one (namespace and signature). */
    private boolean applyMangled(Address addr, String mangled) {
        try {
            List<DemangledObject> objs = DemanglerUtil.demangle(program, mangled, addr);
            if (objs == null || objs.isEmpty()) return false;
            program.getSymbolTable().createLabel(addr, mangled, SourceType.IMPORTED);
            DemanglerOptions options = new DemanglerOptions();
            for (DemangledObject obj : objs) {
                if (obj.applyTo(program, addr, options, monitor)) return true;
            }
        } catch (Exception e) {
            // fall back to the raw name
        }
        return false;
    }

    /**
     * Names exported by Ghidra are fully qualified (Class::Method) and, for
     * overloads, carry the parameter types: "Class::Method(int,char *)".
     * Recreate the namespace and set just the simple name.
     */
    private boolean renameFunction(Function func, String fullName) {
        String name = stripParameters(fullName);
        try {
            SymbolPath path = new SymbolPath(name);
            Namespace ns = program.getGlobalNamespace();
            if (path.getParent() != null) {
                ns = NamespaceUtils.createNamespaceHierarchy(path.getParentPath(), ns, program,
                        SourceType.IMPORTED);
            }
            func.getSymbol().setNameAndNamespace(path.getName(), ns, SourceType.IMPORTED);
            return true;
        } catch (Exception e) {
            try {
                func.setName(name.replace(" ", "_"), SourceType.IMPORTED);
                return true;
            } catch (Exception ignored) {
                return false;
            }
        }
    }

    static String stripParameters(String name) {
        if (!name.endsWith(")")) return name;
        int depth = 0;
        for (int i = name.length() - 1; i >= 0; i--) {
            char c = name.charAt(i);
            if (c == ')') depth++;
            else if (c == '(') {
                depth--;
                if (depth == 0) {
                    return i > 0 ? name.substring(0, i) : name;
                }
            }
        }
        return name;
    }

    /**
     * import_one(): import just the selected item (forcing sub_ names). The
     * caller asks first whether to import the type libraries and definitions.
     * Returns the primary function to refresh in the database.
     */
    public List<Address> importOne(MatchItem item, boolean importTypes) throws Exception {
        if (importTypes) {
            // Import all the type libraries and the struct and enum definitions
            importTil();
            importDefinitions();
        }
        String ea1 = DiffDatabases.toDecimal(item.getAddress1());
        String ea2 = DiffDatabases.toDecimal(item.getAddress2());
        inTransaction("Diaphora-ng: import " + item.getName2(), () -> {
            doImportOne(ea1, ea2, true);
            return null;
        });
        return List.of(eaToAddress(ea1));
    }

    /** import_selected(): only_auto imports just the sub_* functions. */
    public List<Address> importSelected(List<MatchItem> selected, boolean onlyAuto) throws Exception {
        // Import all the type libraries and the struct and enum definitions
        importTil();
        importDefinitions();
        List<MatchItem> newItems = new ArrayList<>();
        for (MatchItem item : selected) {
            if (!onlyAuto || (item.getName1() != null && item.getName1().startsWith("sub_"))) {
                newItems.add(item);
            }
        }
        return importItems(newItems);
    }

    /** do_import_all(): import_all (only_subs false) and import_all_auto (only_subs true). */
    public List<Address> importAll(List<MatchItem> items, boolean onlySubs) throws Exception {
        importTil();
        importDefinitions();
        List<MatchItem> list = new ArrayList<>();
        for (MatchItem item : items) {
            if (!onlySubs || (item.getName1() != null && item.getName1().startsWith("sub_"))) {
                list.add(item);
            }
        }
        return importItems(list);
    }

    /** import_items(): import all the function names and comments. */
    public List<Address> importItems(List<MatchItem> items) throws Exception {
        List<Address> toImport = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        inTransaction("Diaphora-ng: import " + items.size() + " functions", () -> {
            monitor.initialize(items.size());
            int n = 0;
            for (MatchItem item : items) {
                if (monitor.isCancelled()) break;
                monitor.setProgress(n++);
                monitor.setMessage("Importing " + item.getName2());
                String ea1 = DiffDatabases.toDecimal(item.getAddress1());
                String ea2 = DiffDatabases.toDecimal(item.getAddress2());
                if (ea1 == null || ea1.isEmpty() || ea2 == null || ea2.isEmpty()) continue;
                doImportOne(ea1, ea2, false);
                if (seen.add(ea1)) {
                    toImport.add(eaToAddress(ea1));
                }
            }
            return null;
        });
        return toImport;
    }
}
