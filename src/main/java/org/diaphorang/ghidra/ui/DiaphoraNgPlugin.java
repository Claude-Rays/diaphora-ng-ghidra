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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import org.diaphorang.ghidra.diff.DiffDatabases;
import org.diaphorang.ghidra.export.DiaphoraExporter;
import org.diaphorang.ghidra.importer.DiaphoraImporter;
import org.diaphorang.ghidra.model.DiaphoraResults;
import org.diaphorang.ghidra.model.DiaphoraSchema;
import org.diaphorang.ghidra.model.MatchCategory;
import org.diaphorang.ghidra.util.DiffSettings;
import org.diaphorang.ghidra.model.MatchItem;
import resources.Icons;

import javax.swing.*;
import java.awt.GridLayout;
import java.awt.event.KeyEvent;
import java.io.File;
import java.util.*;

/**
 * Main Ghidra Plugin entry point for Diaphora-ng.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "Diaphora-ng",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Diaphora-ng program diffing plugin for Ghidra",
    description = "Diaphora-ng for Ghidra: Joxean Koret's Diaphora with Claude-Rays Decompiler for Ghidra diffs and other additions.",
    servicesRequired = {},
    servicesProvided = {}
)
public class DiaphoraNgPlugin extends ProgramPlugin {

    public static final String PLUGIN_VERSION = "0.1.0-beta";
    public static final String BASE_VERSION = "3.4.1";
    public static final String PORT_AUTHOR = "ClaudeMonkey";
    public static final String PORT_REPO = "Claude-Rays/diaphora-ng-ghidra";
    public static final String ORIGINAL_AUTHOR = "Joxean Koret";
    public static final String ORIGINAL_REPO = "joxeankoret/diaphora";

    private DiaphoraResultsProvider provider;

    public DiaphoraNgPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        super.init();
        printBanner();
        provider = new DiaphoraResultsProvider(this);
        // Register the provider with the tool: removeFromTool() on dispose expects the
        // "show provider" action created by addToTool() (NPE when closing otherwise).
        provider.addToTool();

        createActions();
    }

    private void printBanner() {
        Msg.info(this, String.format("Diaphora-ng for Ghidra %s by %s (%s)", PLUGIN_VERSION, PORT_AUTHOR, PORT_REPO));
        Msg.info(this, String.format("Java port of Diaphora %s by %s (%s), plus the Claude-Rays Decompiler for Ghidra "
            + "pseudo-code diffs.", BASE_VERSION, ORIGINAL_AUTHOR, ORIGINAL_REPO));
    }

    private void addMenuAction(String name, String description, Command body, KeyBindingData keys,
                               ToolBarData toolbar) {
        DockingAction action = new DockingAction(name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    body.run();
                } catch (Exception e) {
                    Msg.showError(DiaphoraNgPlugin.this, null, "Diaphora-ng", "Diaphora-ng error: " + e.getMessage(), e);
                }
            }
        };
        action.setMenuBarData(new MenuData(new String[]{"Diaphora-ng", name}, "Diaphora-ng"));
        if (keys != null) action.setKeyBindingData(keys);
        if (toolbar != null) action.setToolBarData(toolbar);
        action.setDescription(description);
        tool.addAction(action);
    }

    private interface Command {
        void run() throws Exception;
    }

    /** The main menu of diaphora-idafree (plugin.cpp MENU_ITEMS). */
    private void createActions() {
        addMenuAction("Diff or export", "Export program to SQLite and optionally diff with another database",
            () -> showDiffDialog(null, null), null, new ToolBarData(Icons.EXPAND_ALL_ICON, "Diaphora-ng"));
        addMenuAction("Show results", "Show Diaphora results panel",
            this::showResults, new KeyBindingData(KeyEvent.VK_F3, 0), null);
        addMenuAction("Load results", "Load diffing results from a .diaphora file", this::loadResults, null, null);
        addMenuAction("Save results", "Save current diffing results to a .diaphora file", this::saveResults, null, null);
        addMenuAction("Load and import results", "Load diffing results and import all the matched sub_* functions",
            this::loadAndImportResults, null, null);
        addMenuAction("Import definitions", "Import structures, unions and enumerations from a Diaphora database",
            this::importDefinitions, null, null);
        addMenuAction("Local diff", "Diff the current function against another function of this program",
            this::localDiff, null, null);
        addMenuAction("Pseudo-code diff settings", "Renaming of the locals after the other side in the pseudo-code diffs (level 2)",
            this::diffSettings, null, null);
    }

    /**
     * Diaphora-ng: level 2 of the pseudo-code diff, a view option (util/DiffSettings;
     * level 1 is an export option, in the export dialog).
     * Off: the diff views show each side as it was exported.
     */
    private void diffSettings() {
        JCheckBox rename = new JCheckBox("Rename the locals after the other side in the diff views (level 2)",
                                         DiffSettings.renameLocals());
        JPanel panel = new JPanel(new GridLayout(0, 1, 4, 4));
        panel.add(rename);
        panel.add(new JLabel("      Only what Diff pseudo-code, Show pseudo-code patch and Local diff show."));
        panel.add(new JLabel("Level 1 (locals named v1, v2...) is an option of the export dialog: it is saved in"));
        panel.add(new JLabel("each database, and Diff pseudo-code follows how the databases were exported."));
        if (JOptionPane.showConfirmDialog(tool.getToolFrame(), panel, "Diaphora-ng: pseudo-code diff settings",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) {
            return;
        }
        DiffSettings.setRenameLocals(rename.isSelected());
        Msg.info(this, "Diaphora-ng: locals renamed after the other side " + (rename.isSelected() ? "on" : "off"));
    }

    @Override
    public boolean goTo(Address addr) {
        return super.goTo(addr);
    }

    public DiaphoraResultsProvider getProvider() {
        return provider;
    }

    // ------------------------------------------------------------------------
    // Menu commands
    // ------------------------------------------------------------------------

    /** cmd_diff_or_export() / re_diff() */
    public void showDiffDialog(File lastPrimary, File lastSecondary) {
        if (currentProgram == null) {
            Msg.showWarn(this, null, "No Program", "Please open a program before launching Diaphora.");
            return;
        }
        tool.showDialog(new DiaphoraExportDialog(this, lastPrimary, lastSecondary));
    }

    private void showResults() {
        if (!provider.hasResults()) {
            Msg.showWarn(this, null, "Diaphora-ng", "No active diffing results to show.");
        }
        provider.setVisible(true);
    }

    private File askFile(boolean save, String extension, String title) {
        GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
        chooser.setTitle(title);
        chooser.setFileFilter(new ExtensionFileFilter(extension, "*." + extension));
        chooser.setApproveButtonText(save ? "Save" : "Open");
        File file = chooser.getSelectedFile();
        chooser.dispose();
        return file;
    }

    /** cmd_save_results() */
    public void saveResults() {
        if (!provider.hasResults()) {
            Msg.showWarn(this, null, "Diaphora-ng", "No active diffing results to save.");
            return;
        }
        File file = askFile(true, "diaphora", "Select the file to store diffing results");
        if (file == null) return;
        if (!file.getName().contains(".")) {
            file = new File(file.getAbsolutePath() + ".diaphora");
        }
        try {
            File main = provider.getPrimaryDb();
            File diff = provider.getSecondaryDb();
            DiaphoraResults.save(file, provider.getResults(),
                main != null ? main.getAbsolutePath() : "", diff != null ? diff.getAbsolutePath() : "");
            Msg.info(this, "Diaphora-ng: Diffing results saved in file '" + file + "'.");
            tool.setStatusInfo("Diaphora-ng: diffing results saved in " + file.getName());
        } catch (Exception e) {
            Msg.showError(this, null, "Diaphora-ng", "Error saving results: " + e.getMessage(), e);
        }
    }

    private DiaphoraResults.Config readConfig(File file) {
        DiaphoraResults.Config cfg = DiaphoraResults.readConfig(file);
        if (cfg == null) {
            Msg.showWarn(this, null, "Diaphora-ng", "Malformed results database!");
            return null;
        }
        if (!DiaphoraSchema.VERSION_VALUE.equals(cfg.version)) {
            Msg.showWarn(this, null, "Diaphora-ng", "The version of the diff results is " + cfg.version +
                " and current version is " + DiaphoraSchema.VERSION_VALUE + ", there can be some incompatibilities.");
        }
        return cfg;
    }

    /** cmd_load_results() */
    private void loadResults() {
        File file = askFile(false, "diaphora", "Select the file to load diffing results");
        if (file == null || !file.exists()) return;
        DiaphoraResults.Config cfg = readConfig(file);
        if (cfg == null) return;

        File mainDb = new File(cfg.mainDb != null ? cfg.mainDb : "");
        File diffDb = new File(cfg.diffDb != null ? cfg.diffDb : "");
        if (!mainDb.exists()) {
            Msg.info(this, "Diaphora-ng: Primary database " + cfg.mainDb + " not found.");
            mainDb = askFile(false, "sqlite", "Select the primary database path");
            if (mainDb == null) return;
        }
        if (!diffDb.exists()) {
            diffDb = askFile(false, "sqlite", "Select the secondary database path");
            if (diffDb == null) return;
        }
        try {
            Msg.info(this, "Diaphora-ng: Main database '" + mainDb + "'.");
            Msg.info(this, "Diaphora-ng: Diff database '" + diffDb + "'.");
            Map<MatchCategory, List<MatchItem>> results = DiaphoraResults.load(file, -1, true);
            provider.setResults(results, mainDb, diffDb, null, hasPseudocode(mainDb));
            Msg.info(this, "Diaphora-ng: Showing diff results.");
            provider.setVisible(true);
        } catch (Exception e) {
            Msg.showError(this, null, "Diaphora-ng", "Error loading results: " + e.getMessage(), e);
        }
    }

    /** Whether the database was exported with the decompiler. */
    private static boolean hasPseudocode(File db) {
        try {
            return !new DiffDatabases(db, db)
                .query("select 1 from main.functions where pseudocode is not null limit 1").isEmpty();
        } catch (Exception e) {
            return true;
        }
    }

    /** get_value_for(): DIAPHORA_<NAME> environment overrides. */
    private static double getValueFor(String name, double def) {
        String v = System.getenv("DIAPHORA_" + name);
        if (v == null) return def;
        try {
            return Double.parseDouble(v);
        } catch (NumberFormatException e) {
            return def;
        }
    }

    /** cmd_load_and_import_results(): import all the sub_* best and partial matches. */
    private void loadAndImportResults() {
        if (currentProgram == null) return;
        File file = askFile(false, "diaphora", "Select the diffing results to load and import");
        if (file == null || !file.exists()) return;
        DiaphoraResults.Config cfg = readConfig(file);
        if (cfg == null) return;

        Program program = currentProgram;
        File mainDb = new File(cfg.mainDb);
        File diffDb = new File(cfg.diffDb);
        DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
        Task task = new Task("Diaphora-ng: load and import results", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    double minRatio = getValueFor("MINIMUM_IMPORT_RATIO", 0.5);
                    Msg.info(DiaphoraNgPlugin.this, "Diaphora-ng: Minimum import threshold " + minRatio);
                    Map<MatchCategory, List<MatchItem>> results = DiaphoraResults.load(file, minRatio, false);
                    DiffDatabases dbs = new DiffDatabases(mainDb, diffDb);
                    DiaphoraImporter importer = new DiaphoraImporter(program, dbs, service, monitor);
                    Set<Address> toRefresh = new LinkedHashSet<>();
                    try {
                        toRefresh.addAll(importer.importAll(results.get(MatchCategory.BEST), true));
                        toRefresh.addAll(importer.importAll(results.get(MatchCategory.PARTIAL), true));
                    } finally {
                        importer.close();
                    }
                    boolean decompiler = hasPseudocode(mainDb);
                    if (!toRefresh.isEmpty()) {
                        new DiaphoraExporter(program, mainDb, decompiler).refreshFunctions(toRefresh, monitor);
                    }
                    SwingUtilities.invokeLater(() -> provider.setResults(results, mainDb, diffDb, null, decompiler));
                } catch (Exception e) {
                    Msg.showError(DiaphoraNgPlugin.this, null, "Diaphora-ng", "Error importing results: " + e.getMessage(), e);
                }
            }
        };
        new TaskLauncher(task, tool.getToolFrame());
    }

    /** cmd_import_definitions() */
    private void importDefinitions() {
        if (currentProgram == null) return;
        File file = askFile(false, "sqlite", "Select the file to import structures, unions and enumerations from");
        if (file == null || !file.exists()) return;
        if (OptionDialog.showYesNoDialog(null, "Diaphora-ng",
                "Do you really want to import all structures, unions and enumerations?") != OptionDialog.YES_OPTION) {
            return;
        }
        Program program = currentProgram;
        DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
        Task task = new Task("Diaphora-ng: import definitions", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                DiaphoraImporter importer = new DiaphoraImporter(program, new DiffDatabases(null, file), service, monitor);
                try {
                    importer.importTil();
                    importer.importDefinitions();
                } catch (Exception e) {
                    Msg.showError(DiaphoraNgPlugin.this, null, "Diaphora-ng", "Error importing definitions: " + e.getMessage(), e);
                } finally {
                    importer.close();
                }
            }
        };
        new TaskLauncher(task, tool.getToolFrame());
    }

    // ------------------------------------------------------------------------
    // Local diff (extras/diaphora_local.py)
    // ------------------------------------------------------------------------

    private static String localGetDisasm(Instruction inst, CodeUnitFormat fmt) {
        String mnem = inst.getMnemonicString();
        String op1 = inst.getNumOperands() > 0 ? fmt.getOperandRepresentationString(inst, 0) : "";
        String op2 = inst.getNumOperands() > 1 ? fmt.getOperandRepresentationString(inst, 1) : "";
        String line = String.format("%-8s %s", mnem, op1 != null ? op1 : "");
        if (op2 != null && !op2.isEmpty()) {
            line += ", " + op2;
        }
        return line;
    }

    private static String localGetAssembly(Program program, Function func) throws Exception {
        List<String> lines = new ArrayList<>();
        CodeUnitFormat fmt = CodeUnitFormat.DEFAULT;
        BasicBlockModel model = new BasicBlockModel(program);
        List<CodeBlock> blocks = new ArrayList<>();
        CodeBlockIterator it = model.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);
        while (it.hasNext()) blocks.add(it.next());
        blocks.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));
        for (CodeBlock block : blocks) {
            if (!block.getFirstStartAddress().equals(func.getEntryPoint())) {
                lines.add(String.format("loc_%08x:", block.getFirstStartAddress().getOffset()));
            }
            InstructionIterator ii = program.getListing().getInstructions(block, true);
            while (ii.hasNext()) {
                lines.add("     " + localGetDisasm(ii.next(), fmt));
            }
        }
        return String.join("\n", lines);
    }

    /** cmd_local_diff(): diff the function at the cursor against another function. */
    private void localDiff() throws Exception {
        Program program = currentProgram;
        ProgramLocation loc = currentLocation;
        Function func = (program != null && loc != null)
            ? program.getFunctionManager().getFunctionContaining(loc.getAddress()) : null;
        if (func == null) {
            Msg.showWarn(this, null, "Diaphora-ng", "Please place the cursor over a function before calling this plugin.");
            return;
        }
        List<String[]> rows = new ArrayList<>();
        List<Function> funcs = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            rows.add(new String[]{f.getName(true), f.getEntryPoint().toString()});
            funcs.add(f);
        }
        DiaphoraChooserDialog chooser = new DiaphoraChooserDialog(
            "Select the function to diff " + func.getName(true) + " against",
            new String[]{"Function name", "Address"}, rows);
        tool.showDialog(chooser);
        if (chooser.getSelected() < 0) return;
        Function func2 = funcs.get(chooser.getSelected());
        Msg.info(this, String.format("Diaphora-ng: Selected function address 0x%08x", func2.getEntryPoint().getOffset()));

        String name1 = func.getName(true);
        String name2 = func2.getName(true);

        // assembly
        String buf1 = name1 + " proc near\n" + localGetAssembly(program, func) + "\n" + name1 + " endp";
        String buf2 = name2 + " proc near\n" + localGetAssembly(program, func2) + "\n" + name2 + " endp";
        tool.showDialog(new DiaphoraDiffDialog("Diff assembly " + name1 + " - " + name2, buf1, buf2));

        // pseudo-code
        Task task = new Task("Diaphora-ng: decompiling", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                boolean canonical = DiffSettings.canonicalNames();
                String p1 = DiaphoraExporter.decompileWithPrototype(program, func, monitor, canonical);
                if (p1 == null) {
                    Msg.info(DiaphoraNgPlugin.this, "Diaphora-ng: [i] Cannot get the pseudo-code for the current function");
                    return;
                }
                String p2raw = DiaphoraExporter.decompileWithPrototype(program, func2, monitor, canonical);
                if (p2raw == null) {
                    Msg.info(DiaphoraNgPlugin.this, "Diaphora-ng: Cannot get the pseudo-code for the second function");
                    return;
                }
                // Diaphora-ng: the locals of the second function renamed after the first ("level 2")
                long base = program.getImageBase().getOffset();
                String p2 = DiaphoraResultsProvider.renameLocals(p1, p2raw, base, base);
                if (p1.equals(p2)) {
                    Msg.showWarn(DiaphoraNgPlugin.this, null, "Diaphora-ng", "Both pseudo-codes are equal.");
                }
                SwingUtilities.invokeLater(() -> tool.showDialog(
                    new DiaphoraDiffDialog("Diff pseudo-code " + name1 + " - " + name2, p1, p2)));
            }
        };
        new TaskLauncher(task, tool.getToolFrame());
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            if (provider.isInTool()) {
                provider.removeFromTool();
            }
            provider = null;
        }
        super.dispose();
    }
}
