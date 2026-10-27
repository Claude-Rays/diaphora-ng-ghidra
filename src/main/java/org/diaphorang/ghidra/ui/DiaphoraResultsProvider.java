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
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import org.diaphorang.ghidra.diff.DiaphoraDiffer;
import org.diaphorang.ghidra.diff.DiffDatabases;
import org.diaphorang.ghidra.diff.GraphDiff;
import org.diaphorang.ghidra.export.DiaphoraExporter;
import org.diaphorang.ghidra.importer.DiaphoraImporter;
import org.diaphorang.ghidra.model.MatchCategory;
import org.diaphorang.ghidra.model.MatchItem;
import org.diaphorang.ghidra.util.DiffSettings;
import org.diaphorang.ghidra.util.LocalRenamer;
import org.diaphorang.ghidra.util.TextCleaner;
import resources.Icons;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.util.*;
import java.util.List;

/**
 * Dockable component provider displaying Diaphora diffing results: the
 * equivalent of the CIDAChooser choosers of diaphora_ida.py and of their
 * commands (diaphora-idafree ui.cpp, run_command()).
 */
public class DiaphoraResultsProvider extends ComponentProvider {

    private final DiaphoraNgPlugin plugin;
    private final JPanel mainPanel;
    private final JTabbedPane tabbedPane;
    private final JTextField filterField;

    private Map<MatchCategory, List<MatchItem>> results = new EnumMap<>(MatchCategory.class);
    private final Map<MatchCategory, MatchTableModel> tableModels = new EnumMap<>(MatchCategory.class);
    private final Map<MatchCategory, GTable> tables = new EnumMap<>(MatchCategory.class);

    /** Databases of the diff (or of the loaded results). */
    private DiffDatabases dbs;
    /** Options of the last diff, used by "Add manual match". */
    private DiaphoraDiffer.Options diffOptions = new DiaphoraDiffer.Options();
    /** The primary database was exported with the decompiler (for refresh_function_row). */
    private boolean useDecompiler = true;

    /** matched_primary / matched_secondary: names of the matched functions. */
    private final Set<String> matchedPrimary = new HashSet<>();
    private final Set<String> matchedSecondary = new HashSet<>();

    /** Diaphora-ng: the Claude diff pseudo-code commands and their orientation. */
    private final ClaudeDiffCommands claude = new ClaudeDiffCommands();

    public DiaphoraResultsProvider(DiaphoraNgPlugin plugin) {
        super(plugin.getTool(), "Diaphora-ng Results", plugin.getName());
        this.plugin = plugin;

        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Filter bar
        JPanel filterPanel = new JPanel(new BorderLayout(5, 5));
        filterPanel.add(new JLabel("Filter: "), BorderLayout.WEST);
        filterField = new JTextField();
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); }
            public void removeUpdate(DocumentEvent e) { applyFilter(); }
            public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filterPanel.add(filterField, BorderLayout.CENTER);
        mainPanel.add(filterPanel, BorderLayout.NORTH);

        tabbedPane = new JTabbedPane();
        for (MatchCategory cat : MatchCategory.values()) {
            MatchTableModel model = new MatchTableModel();
            tableModels.put(cat, model);

            GTable table = createTable(model, cat);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            table.setDefaultRenderer(Double.class, new RatioRenderer());
            setupTableListeners(table, cat);
            tables.put(cat, table);

            JScrollPane scroll = new JScrollPane(table);
            tabbedPane.addTab(cat.getTitle() + " (0)", scroll);
        }
        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        createActions();
    }

    private void createActions() {
        DockingAction refreshAction = new DockingAction("Refresh", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                applyFilter();
            }
        };
        refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON));
        refreshAction.setDescription("Refresh results view");
        addLocalAction(refreshAction);
    }

    public void setResults(Map<MatchCategory, List<MatchItem>> newResults) {
        setResults(newResults, null, null, null, true);
    }

    public void setResults(Map<MatchCategory, List<MatchItem>> newResults, File primaryDb, File secondaryDb) {
        setResults(newResults, primaryDb, secondaryDb, null, true);
    }

    public void setResults(Map<MatchCategory, List<MatchItem>> newResults, File primaryDb, File secondaryDb,
                           DiaphoraDiffer.Options options, boolean useDecompiler) {
        this.results = new EnumMap<>(MatchCategory.class);
        for (MatchCategory cat : MatchCategory.values()) {
            List<MatchItem> items = newResults != null ? newResults.get(cat) : null;
            this.results.put(cat, items != null ? new ArrayList<>(items) : new ArrayList<>());
        }
        this.dbs = primaryDb != null && secondaryDb != null ? new DiffDatabases(primaryDb, secondaryDb) : null;
        this.diffOptions = options != null ? options : new DiaphoraDiffer.Options();
        this.useDecompiler = useDecompiler;
        claude.reset();

        matchedPrimary.clear();
        matchedSecondary.clear();
        for (MatchCategory cat : MatchCategory.values()) {
            if (!isMatchCategory(cat)) continue;
            for (MatchItem item : this.results.get(cat)) {
                matchedPrimary.add(item.getName1());
                matchedSecondary.add(item.getName2());
            }
        }
        updateTabs();
    }

    public Map<MatchCategory, List<MatchItem>> getResults() {
        return results;
    }

    public File getPrimaryDb() {
        return dbs != null ? dbs.getPrimary() : null;
    }

    public File getSecondaryDb() {
        return dbs != null ? dbs.getSecondary() : null;
    }

    public boolean hasResults() {
        for (List<MatchItem> l : results.values()) {
            if (!l.isEmpty()) return true;
        }
        return false;
    }

    private static boolean isMatchCategory(MatchCategory cat) {
        return cat != MatchCategory.UNMATCHED_PRIMARY && cat != MatchCategory.UNMATCHED_SECONDARY;
    }

    /**
     * Table whose rows are colored by ratio, as Diaphora's choosers.
     */
    private GTable createTable(MatchTableModel model, MatchCategory cat) {
        return new GTable(model) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (isMatchCategory(cat) && !isRowSelected(row)) {
                    MatchItem item = model.getItemAt(convertRowIndexToModel(row));
                    if (item != null) {
                        c.setBackground(DiaphoraColors.rowColor(item, getBackground()));
                        if (c instanceof JComponent) {
                            ((JComponent) c).setOpaque(true);
                        }
                    }
                }
                return c;
            }
        };
    }

    private void updateTabs() {
        int index = 0;
        String filter = filterField.getText().trim().toLowerCase();

        for (MatchCategory cat : MatchCategory.values()) {
            List<MatchItem> items = results.getOrDefault(cat, Collections.emptyList());
            List<MatchItem> filtered = new ArrayList<>();
            for (MatchItem item : items) {
                if (filter.isEmpty() || matchesFilter(item, filter)) {
                    filtered.add(item);
                }
            }

            tableModels.get(cat).setItems(filtered);
            tabbedPane.setTitleAt(index, cat.getTitle() + " (" + filtered.size() + ")");
            index++;
        }
    }

    private void applyFilter() {
        updateTabs();
    }

    private boolean matchesFilter(MatchItem item, String filter) {
        if (item.getName1() != null && item.getName1().toLowerCase().contains(filter)) return true;
        if (item.getName2() != null && item.getName2().toLowerCase().contains(filter)) return true;
        if (item.getAddress1() != null && item.getAddress1().toLowerCase().contains(filter)) return true;
        if (item.getAddress2() != null && item.getAddress2().toLowerCase().contains(filter)) return true;
        if (item.getDescription() != null && item.getDescription().toLowerCase().contains(filter)) return true;
        return false;
    }

    /** Selected items of a tab, in model order. */
    private List<MatchItem> selectedItems(MatchCategory cat) {
        GTable table = tables.get(cat);
        MatchTableModel model = tableModels.get(cat);
        List<MatchItem> selected = new ArrayList<>();
        for (int r : table.getSelectedRows()) {
            MatchItem item = model.getItemAt(table.convertRowIndexToModel(r));
            if (item != null) selected.add(item);
        }
        return selected;
    }

    private void setupTableListeners(GTable table, MatchCategory cat) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybePopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybePopup(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row < 0) return;
                    MatchItem item = tableModels.get(cat).getItemAt(table.convertRowIndexToModel(row));
                    jumpToPrimary(item);
                }
            }

            private void maybePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && !table.isRowSelected(row)) {
                    table.setRowSelectionInterval(row, row);
                }
                showContextMenu(table, cat, e.getX(), e.getY());
            }
        });
        table.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_DELETE) {
                    deleteSelected(cat);
                }
            }
        });
    }

    private void jumpToPrimary(MatchItem item) {
        if (item == null || item.getAddress1() == null || item.getAddress1().isEmpty()) return;
        Program program = plugin.getCurrentProgram();
        if (program == null) return;
        Address addr = parseAddress(program, item.getAddress1());
        if (addr != null) {
            plugin.goTo(addr);
        } else {
            Msg.showWarn(this, getComponent(), "Navigation Error", "Could not jump to address: " + item.getAddress1());
        }
    }

    // ------------------------------------------------------------------------
    // Context menu (match_cmds / unmatched_cmds)
    // ------------------------------------------------------------------------

    private JMenuItem menuItem(JPopupMenu menu, String label, boolean enabled, Command action) {
        JMenuItem mi = new JMenuItem(label);
        mi.setEnabled(enabled);
        mi.addActionListener(e -> {
            try {
                action.run();
            } catch (Exception ex) {
                Msg.showError(this, getComponent(), "Diaphora-ng", "Diaphora-ng error: " + ex.getMessage(), ex);
            }
        });
        menu.add(mi);
        return mi;
    }

    private interface Command {
        void run() throws Exception;
    }

    private void showContextMenu(GTable table, MatchCategory cat, int x, int y) {
        JPopupMenu menu = new JPopupMenu();
        List<MatchItem> selection = selectedItems(cat);
        MatchItem item = selection.isEmpty() ? null : selection.get(0);
        boolean haveItem = item != null;
        boolean haveDbs = dbs != null;

        if (!isMatchCategory(cat)) {
            boolean primary = cat == MatchCategory.UNMATCHED_PRIMARY;
            menuItem(menu, "Show assembly", haveItem && haveDbs, () -> showAsm(item, primary));
            menuItem(menu, "Show pseudo-code", haveItem && haveDbs, () -> showPseudo(item, primary));
            menu.show(table, x, y);
            return;
        }

        menuItem(menu, "Diff again", haveDbs, this::diffAgain);
        menuItem(menu, "Save results", hasResults(), plugin::saveResults);
        menuItem(menu, "Add manual match", haveDbs, this::addManualMatch);
        menu.addSeparator();
        menuItem(menu, "Diff assembly", haveItem && haveDbs, () -> showAsmDiff(item, true));
        // Hex-Rays microcode does not exist in Ghidra
        menuItem(menu, "Diff microcode", false, () -> {});
        menuItem(menu, "Diff pseudo-code", haveItem && haveDbs, () -> showPseudoDiff(item, true));
        menuItem(menu, "Diff assembly in a graph", haveItem && haveDbs, () -> graphDiff(item));
        menuItem(menu, "Diff microcode in a graph", false, () -> {});
        menuItem(menu, "Diff using an external tool", haveItem && haveDbs, () -> diffExternal(item));
        menuItem(menu, "Show assembly patch", haveItem && haveDbs, () -> showAsmDiff(item, false));
        menuItem(menu, "Show pseudo-code patch", haveItem && haveDbs, () -> showPseudoDiff(item, false));
        menuItem(menu, "Show callers and callees graph", haveItem && haveDbs, () -> showCallgraphContext(item));
        menu.addSeparator();
        // Diaphora-ng: Claude-Rays Decompiler
        menuItem(menu, "Claude diff pseudo-code", haveItem && haveDbs, () -> claudeDiff(item, true, false));
        menuItem(menu, "Claude pseudo-code patch", haveItem && haveDbs, () -> claudeDiff(item, false, false));
        menuItem(menu, "Regenerate Claude diff", haveItem && haveDbs, () -> claudeDiff(item, true, true));
        menuItem(menu, "Set the new version for Claude...", haveItem && haveDbs,
            () -> claude.orientation(getComponent(), item, dbs.getSecondary(), true));
        menu.addSeparator();
        menuItem(menu, "Import selected", haveItem && haveDbs, () -> importSelected(cat, selection, false));
        menuItem(menu, "Import selected sub_*", haveItem && haveDbs, () -> importSelected(cat, selection, true));
        menuItem(menu, "Import *all* functions", haveDbs, () -> importAll(cat, false));
        menuItem(menu, "Import *all* data for sub_* functions", haveDbs, () -> importAll(cat, true));
        menu.addSeparator();
        Color tabColor = DiaphoraColors.highlightColor(cat);
        menuItem(menu, "Highlight matches", tabColor != null, () -> highlightTab(cat, tabColor));
        menuItem(menu, "Unhighlight matches", tabColor != null, () -> highlightTab(cat, null));
        menu.addSeparator();
        menuItem(menu, "Delete match", haveItem, () -> deleteSelected(cat));
        menuItem(menu, "Go to primary address", haveItem, () -> jumpToPrimary(item));
        menuItem(menu, "Highlight basic block differences", haveItem && haveDbs, () -> highlightBasicBlocks(item));
        menuItem(menu, "Clear basic block colors", haveItem, () -> clearFunctionColors(item));

        menu.show(table, x, y);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    private void warning(String msg) {
        Msg.showWarn(this, getComponent(), "Diaphora-ng", msg);
    }

    private void log(String msg) {
        Msg.info(this, "Diaphora-ng: " + msg);
    }

    private interface MonitoredBody {
        void run(TaskMonitor monitor) throws Exception;
    }

    /** Run @body in a background task with a progress dialog, reporting errors. */
    private void runTask(String title, MonitoredBody body) {
        Task task = new Task(title, true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    body.run(monitor);
                } catch (Exception e) {
                    Msg.showError(DiaphoraResultsProvider.this, null, "Diaphora-ng", "Diaphora-ng error: " + e.getMessage(), e);
                }
            }
        };
        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void showDialog(docking.DialogComponentProvider dlg) {
        SwingUtilities.invokeLater(() -> plugin.getTool().showDialog(dlg));
    }

    private static String ea(String uiAddress) {
        return DiffDatabases.toDecimal(uiAddress);
    }

    // ------------------------------------------------------------------------
    // Show / diff commands
    // ------------------------------------------------------------------------

    /** show_asm(): unmatched functions of the primary or the secondary database. */
    private void showAsm(MatchItem item, boolean primary) throws Exception {
        String db = primary ? "main" : "diff";
        String address = primary ? item.getAddress1() : item.getAddress2();
        List<Map<String, String>> rows = dbs.query(
            "select prototype, assembly, name from " + db + ".functions where address = ?", ea(address));
        if (rows.isEmpty()) {
            warning("Sorry, there is no assembly available for the selected function.");
            return;
        }
        Map<String, String> row = rows.get(0);
        String name = row.get("name");
        String src = "; " + row.get("prototype") + "\n" + name + " proc near\n" +
                     TextCleaner.prettifyAsm(row.get("assembly")) + "\n" + name + " endp\n";
        showDialog(DiaphoraTextDialog.numberedSource("Assembly for " + name, src));
    }

    /** show_pseudo() */
    private void showPseudo(MatchItem item, boolean primary) throws Exception {
        String db = primary ? "main" : "diff";
        String address = primary ? item.getAddress1() : item.getAddress2();
        List<Map<String, String>> rows = dbs.query(
            "select prototype, pseudocode, name from " + db + ".functions where address = ?", ea(address));
        if (rows.isEmpty() || rows.get(0).get("prototype") == null || rows.get(0).get("pseudocode") == null) {
            warning("Sorry, there is no pseudo-code available for the selected function.");
            return;
        }
        Map<String, String> row = rows.get(0);
        String src = row.get("prototype") + "\n" + row.get("pseudocode");
        showDialog(DiaphoraTextDialog.numberedSource("Pseudo-code for " + row.get("name"), src));
    }

    /** generate_asm_diff(): side by side (html) or unified (patch). */
    private void showAsmDiff(MatchItem item, boolean html) throws Exception {
        List<Map<String, String>> rows = dbs.getSourcesDiffData(ea(item.getAddress1()), ea(item.getAddress2()),
                                                                "assembly");
        if (rows == null) {
            warning("Sorry, there is no assembly available for either the first or the second database.");
            return;
        }
        String name1 = rows.get(0).get("name");
        String name2 = rows.get(1).get("name");
        String buf1 = name1 + " proc near\n" + TextCleaner.prettifyAsm(rows.get(0).get("assembly")) + "\n" + name1 + " endp";
        String buf2 = name2 + " proc near\n" + TextCleaner.prettifyAsm(rows.get(1).get("assembly")) + "\n" + name2 + " endp";
        String title = "Diff assembly " + name1 + " - " + name2;
        if (html) {
            showDialog(new DiaphoraDiffDialog(title, buf1, buf2));
        } else {
            showDialog(DiaphoraTextDialog.unifiedDiff("Patch: " + title, buf1, buf2));
        }
    }

    /**
     * show_pseudo_diff(): the primary side is decompiled again, so the changes
     * done since the export (i.e. imported names) are visible.
     */
    private void showPseudoDiff(MatchItem item, boolean html) throws Exception {
        List<Map<String, String>> rows = dbs.getSourcesDiffData(ea(item.getAddress1()), ea(item.getAddress2()),
                                                                "pseudocode");
        if (rows == null) {
            warning("Sorry, there is no pseudo-code available for either the first or the second database.");
            return;
        }
        Map<String, String> row1 = rows.get(0);
        Map<String, String> row2 = rows.get(1);
        Program program = plugin.getCurrentProgram();
        // Diaphora-ng: the primary is decompiled with the locals named as the secondary was exported (level 1)
        boolean canonical = dbs.canonicalNames("diff");
        if (canonical != dbs.canonicalNames("main")) {
            log("warning: the databases were exported with different local names (v1, v2... in " +
                (canonical ? "the secondary" : "the primary") + " only); the saved primary pseudo-code will not match");
        }
        runTask("Diaphora-ng: decompiling", monitor -> {
            String buf1 = null;
            Address addr = program != null ? parseAddress(program, item.getAddress1()) : null;
            Function func = addr != null ? program.getFunctionManager().getFunctionAt(addr) : null;
            if (func != null) {
                buf1 = DiaphoraExporter.decompileWithPrototype(program, func, monitor, canonical);
            }
            if (buf1 == null) {
                log("warning: cannot retrieve the current pseudo-code for the function, using the previously saved one...");
                buf1 = row1.get("prototype") + "\n" + row1.get("pseudocode");
            }
            String buf2 = row2.get("prototype") + "\n" + row2.get("pseudocode");
            // Diaphora-ng: the locals of the secondary side renamed after the primary ("level 2")
            buf2 = renameLocals(buf1, buf2, dbs.imageBase("main", ea(item.getAddress1())),
                                dbs.imageBase("diff", ea(item.getAddress2())));
            if (buf1.equals(buf2)) {
                warning("Both pseudo-codes are equal.");
            }
            String title = "Diff pseudo-code " + row1.get("name") + " - " + row2.get("name");
            if (html) {
                showDialog(new DiaphoraDiffDialog(title, buf1, buf2));
            } else {
                showDialog(DiaphoraTextDialog.unifiedDiff("Patch: " + title, buf1, buf2));
            }
        });
    }

    /**
     * Diaphora-ng: 'text' with its locals renamed after those of 'ref' and its
     * declarations in their order (LocalRenamer, "level 2");
     * 'text' as it is if level 2 is off (util/DiffSettings).
     */
    static String renameLocals(String ref, String text, long refBase, long base) {
        if (!DiffSettings.renameLocals()) {
            return text;
        }
        LocalRenamer.Result r = LocalRenamer.rename(Arrays.asList(ref.split("\n", -1)),
                                                    Arrays.asList(text.split("\n", -1)), refBase, base);
        if (!r.renamed.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : r.renamed.entrySet()) {
                sb.append(sb.length() == 0 ? "" : ", ").append(e.getKey()).append(" -> ").append(e.getValue());
            }
            Msg.info(DiaphoraResultsProvider.class, "Diaphora-ng: locals renamed after the other side: " + sb);
        }
        return String.join("\n", r.lines);
    }

    /** Diaphora-ng: Claude diff pseudo-code (Claude-Rays Decompiler). */
    private void claudeDiff(MatchItem item, boolean html, boolean force) throws Exception {
        claude.show(plugin.getTool(), plugin.getCurrentProgram(), getComponent(), dbs, item, html, force);
    }

    /** graph_diff(): both basic block graphs, colored by compare_graphs(). */
    private void graphDiff(MatchItem item) throws Exception {
        log("Diff native graph for " + item.getAddress1() + " - " + item.getAddress2());
        GraphDiff.Graph g1;
        GraphDiff.Graph g2;
        try (Connection conn = dbs.open()) {
            g1 = GraphDiff.getGraph(conn, "main", ea(item.getAddress1()));
            g2 = GraphDiff.getGraph(conn, "diff", ea(item.getAddress2()));
        }
        if (g1.isEmpty() || g2.isEmpty()) {
            warning("Sorry, graph information is not available for one of the databases.");
            return;
        }
        GraphDiff.Result colours = GraphDiff.compare(g1, g2);
        String title1 = "Graph for " + item.getName1() + " (primary)";
        String title2 = "Graph for " + item.getName2() + " (secondary)";
        showDialog(new DiaphoraGraphDialog("Diff assembly in a graph: " + item.getName1() + " - " + item.getName2(),
            buildDiffGraph(title1, g1, colours.primary), buildDiffGraph(title2, g2, colours.secondary)));
    }

    /** build_diff_graph() */
    static DiaphoraGraphPanel.GraphData buildDiffGraph(String title, GraphDiff.Graph g,
                                                       Map<String, GraphDiff.BlockMatch> colours) {
        DiaphoraGraphPanel.GraphData data = new DiaphoraGraphPanel.GraphData(title);
        Map<String, Integer> nodes = new HashMap<>();
        java.util.function.BiFunction<String, String, Integer> addNode = (key, text) -> {
            Integer id = nodes.get(key);
            if (id != null) return id;
            GraphDiff.BlockMatch m = colours.get(key);
            Color c = null;
            if (m == GraphDiff.BlockMatch.PARTIAL) {
                c = DiaphoraColors.blockPartialColor();
            } else if (m == GraphDiff.BlockMatch.NONE) {
                c = DiaphoraColors.blockNoneColor();
            }
            int n = data.addNode(text, c, "");
            nodes.put(key, n);
            return n;
        };
        for (String key : g.getBlockOrder()) {
            addNode.apply(key, String.join("\n", g.getBlockText(key)));
        }
        for (String key : g.getRelationOrder()) {
            int parent = addNode.apply(key, "");
            for (String child : g.getChildren(key)) {
                data.edges.add(new int[]{parent, addNode.apply(child, "")});
            }
        }
        return data;
    }

    /** show_callgraph_context() */
    private void showCallgraphContext(MatchItem item) throws Exception {
        log("Showing call graph context for " + item.getAddress1() + " - " + item.getAddress2());
        List<Map<String, String>> mainCallers = dbs.getCallsGraph(item.getName1(), "caller", "main");
        List<Map<String, String>> mainCallees = dbs.getCallsGraph(item.getName1(), "callee", "main");
        List<Map<String, String>> diffCallers = dbs.getCallsGraph(item.getName2(), "caller", "diff");
        List<Map<String, String>> diffCallees = dbs.getCallsGraph(item.getName2(), "callee", "diff");
        String title1 = "Call graph context for " + item.getName1();
        String title2 = "Call graph context for " + item.getName2();
        if (title1.equals(title2)) {
            title2 += " (secondary)";
        }
        showDialog(new DiaphoraGraphDialog("Show callers and callees graph",
            buildCallsGraph(title1, mainCallers, mainCallees, item.getName1()),
            buildCallsGraph(title2, diffCallers, diffCallees, item.getName2())));
    }

    /** build_calls_graph() */
    static DiaphoraGraphPanel.GraphData buildCallsGraph(String title, List<Map<String, String>> callers,
                                                        List<Map<String, String>> callees, String target) {
        DiaphoraGraphPanel.GraphData data = new DiaphoraGraphPanel.GraphData(title);
        int root = data.addNode(target, DiaphoraColors.callgraphTargetColor(), "target");
        for (Map<String, String> caller : callers) {
            data.edges.add(new int[]{data.addNode(caller.get("name1"), null, "caller"), root});
        }
        for (Map<String, String> callee : callees) {
            data.edges.add(new int[]{root, data.addNode(callee.get("name1"), null, "callee")});
        }
        return data;
    }

    // ------------------------------------------------------------------------
    // External diffing tool
    // ------------------------------------------------------------------------

    private static final String EXTERNAL_COMMAND_PREF = "diaphora_ng_external_command";

    /** run_external_diff_tool() */
    private int runExternalDiffTool(String buf1, String buf2, MatchItem item, String ext, String cmdLine)
            throws Exception {
        File dir = new File(System.getProperty("java.io.tmpdir"));
        File file1 = new File(dir, String.format("main_%08x.%s",
            Long.parseUnsignedLong(ea(item.getAddress1())), ext));
        File file2 = new File(dir, String.format("diff_%08x.%s",
            Long.parseUnsignedLong(ea(item.getAddress2())), ext));
        Files.writeString(file1.toPath(), buf1, StandardCharsets.UTF_8);
        Files.writeString(file2.toPath(), buf2, StandardCharsets.UTF_8);
        String line = cmdLine.replace("$1", file1.getAbsolutePath()).replace("$2", file2.getAbsolutePath());
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        ProcessBuilder pb = windows ? new ProcessBuilder("cmd.exe", "/c", line) : new ProcessBuilder("sh", "-c", line);
        pb.inheritIO();
        return pb.start().waitFor();
    }

    /** diff_external(): ask the command line and diff the pseudo-code or the assembly. */
    private void diffExternal(MatchItem item) throws Exception {
        String cmd = Preferences.getProperty(EXTERNAL_COMMAND_PREF);
        if (cmd == null || cmd.isEmpty()) {
            cmd = "your_command $1 $2";
        }
        JTextField field = new JTextField(cmd, 60);
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.add(new JLabel("Enter command line (use $1 and $2 for the two files):"), BorderLayout.NORTH);
        panel.add(field, BorderLayout.CENTER);
        Object[] options = {"Diff Pseudo-code", "Diff Assembler", "Cancel"};
        int ok = JOptionPane.showOptionDialog(getComponent(), panel, "External Diffing Tool",
            JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        if (ok != 0 && ok != 1) return;
        // ask_form() returns 1 for "Diff Pseudo-code" and 0 for "Diff Assembler"
        boolean diffAsm = ok == 1;
        String cmdLine = field.getText();
        Preferences.setProperty(EXTERNAL_COMMAND_PREF, cmdLine);
        Preferences.store();

        List<Map<String, String>> rows;
        String buf1;
        String buf2;
        String ext;
        if (diffAsm) {
            rows = dbs.getSourcesDiffData(ea(item.getAddress1()), ea(item.getAddress2()), "assembly");
            if (rows == null) {
                warning("Sorry, there is no assembly available for either the first or the second database.");
                return;
            }
            String name1 = rows.get(0).get("name");
            String name2 = rows.get(1).get("name");
            buf1 = name1 + " proc near\n" + TextCleaner.prettifyAsm(rows.get(0).get("assembly")) + "\n" + name1 + " endp";
            buf2 = name2 + " proc near\n" + TextCleaner.prettifyAsm(rows.get(1).get("assembly")) + "\n" + name2 + " endp";
            ext = "asm";
        } else {
            rows = dbs.getSourcesDiffData(ea(item.getAddress1()), ea(item.getAddress2()), "pseudocode");
            if (rows == null) {
                warning("Sorry, there is no pseudo-code available for either the first or the second database.");
                return;
            }
            buf1 = rows.get(0).get("prototype") + "\n" + rows.get(0).get("pseudocode");
            buf2 = rows.get(1).get("prototype") + "\n" + rows.get(1).get("pseudocode");
            ext = "cpp";
        }
        String b1 = buf1;
        String b2 = buf2;
        String e = ext;
        runTask("Diaphora-ng: external diffing tool", monitor -> {
            int ret = runExternalDiffTool(b1, b2, item, e, cmdLine);
            log("External command returned " + ret);
        });
    }

    // ------------------------------------------------------------------------
    // Import
    // ------------------------------------------------------------------------

    private DiaphoraImporter newImporter(TaskMonitor monitor) {
        DataTypeManagerService service = plugin.getTool().getService(DataTypeManagerService.class);
        return new DiaphoraImporter(plugin.getCurrentProgram(), dbs, service, monitor);
    }

    private boolean askYesNo(String question) {
        return OptionDialog.showYesNoDialog(getComponent(), "Diaphora-ng", question) == OptionDialog.YES_OPTION;
    }

    /** CMD_IMPORT_SELECTED / CMD_IMPORT_SELECTED_AUTO */
    private void importSelected(MatchCategory cat, List<MatchItem> selection, boolean onlyAuto) {
        if (plugin.getCurrentProgram() == null) return;
        if (selection.size() <= 1) {
            if (selection.isEmpty()) return;
            MatchItem item = selection.get(0);
            int ret = OptionDialog.showYesNoCancelDialog(getComponent(), "Diaphora-ng",
                "Do you want to import all the type libraries, structs and enumerations?");
            if (ret == OptionDialog.CANCEL_OPTION) return;
            boolean types = ret == OptionDialog.YES_OPTION;
            runImport(importer -> importer.importOne(item, types));
        } else if (askYesNo("Do you really want to import all selected IDA named matched functions, " +
                            "comments, prototypes and definitions?")) {
            runImport(importer -> importer.importSelected(selection, onlyAuto));
        }
    }

    /** CMD_IMPORT_ALL / CMD_IMPORT_ALL_FUNCS */
    private void importAll(MatchCategory cat, boolean onlySubs) {
        if (plugin.getCurrentProgram() == null) return;
        String q = onlySubs
            ? "Do you really want to import all IDA named matched functions, comments, prototypes and definitions?"
            : "Do you want to import all functions, comments, prototypes and definitions?";
        if (!askYesNo(q)) return;
        List<MatchItem> items = new ArrayList<>(results.getOrDefault(cat, List.of()));
        runImport(importer -> importer.importAll(items, onlySubs));
    }

    private interface ImportBody {
        List<Address> run(DiaphoraImporter importer) throws Exception;
    }

    /** Import, then refresh_function_row() for the imported functions and update_choosers(). */
    private void runImport(ImportBody body) {
        Program program = plugin.getCurrentProgram();
        DiffDatabases importDbs = dbs;
        runTask("Diaphora-ng: importing", monitor -> {
            List<Address> toRefresh;
            DiaphoraImporter importer = newImporter(monitor);
            try {
                toRefresh = body.run(importer);
            } finally {
                importer.close();
            }
            if (!toRefresh.isEmpty()) {
                monitor.setMessage("Updating primary database...");
                DiaphoraExporter exporter = new DiaphoraExporter(program, importDbs.getPrimary(), useDecompiler);
                exporter.refreshFunctions(toRefresh, monitor);
            }
            SwingUtilities.invokeLater(this::updateChoosers);
        });
    }

    /** update_choosers(): the primary names of the matches, as stored now in the primary database. */
    private void updateChoosers() {
        if (dbs == null) return;
        Map<String, String> names = new HashMap<>();
        try {
            for (Map<String, String> row : dbs.query("select address, name from main.functions")) {
                names.put(row.get("address"), row.get("name"));
            }
        } catch (Exception e) {
            log("Error updating the choosers: " + e.getMessage());
            return;
        }
        for (MatchCategory cat : MatchCategory.values()) {
            if (!isMatchCategory(cat)) continue;
            for (MatchItem item : results.get(cat)) {
                String name = names.get(ea(item.getAddress1()));
                if (name != null && !name.isEmpty() && !name.equals(item.getName1())) {
                    matchedPrimary.remove(item.getName1());
                    item.setName1(name);
                    matchedPrimary.add(name);
                }
            }
        }
        updateTabs();
    }

    // ------------------------------------------------------------------------
    // Manual matches, deletion and diff again
    // ------------------------------------------------------------------------

    /** add_manual_match() */
    private void addManualMatch() throws Exception {
        Program program = plugin.getCurrentProgram();
        if (program == null) return;
        List<String[]> funcs = new ArrayList<>();
        List<Function> funcList = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            funcs.add(new String[]{f.getName(true), f.getEntryPoint().toString()});
            funcList.add(f);
        }
        DiaphoraChooserDialog ch1 = new DiaphoraChooserDialog("Select a function from the current database...",
            new String[]{"Function name", "Address"}, funcs);
        plugin.getTool().showDialog(ch1);
        if (ch1.getSelected() < 0) return;
        Function f1 = funcList.get(ch1.getSelected());

        List<Map<String, String>> diffFuncs = dbs.getDiffFunctions();
        List<String[]> rows = new ArrayList<>();
        for (Map<String, String> r : diffFuncs) {
            rows.add(new String[]{r.get("id"), r.get("name")});
        }
        DiaphoraChooserDialog ch2 = new DiaphoraChooserDialog("Select a function from the external database...",
            new String[]{"Id", "Name"}, rows);
        plugin.getTool().showDialog(ch2);
        if (ch2.getSelected() < 0) return;

        String ea1 = String.valueOf(f1.getEntryPoint().getOffset());
        String ea2 = diffFuncs.get(ch2.getSelected()).get("address");
        log(String.format("Adding manual match between 0x%08x and 0x%08x",
            Long.parseUnsignedLong(ea1), Long.parseUnsignedLong(ea2)));
        addManualMatchInternal(ea1, ea2);
    }

    private void addManualMatchInternal(String ea1, String ea2) throws Exception {
        Map<String, String> mainRow = dbs.getFunctionRowByEa(ea1, "main");
        if (mainRow == null) {
            warning("Can't find the local function!");
            return;
        }
        Map<String, String> diffRow = dbs.getFunctionRowByEa(ea2, "diff");
        if (diffRow == null) {
            warning("Can't find the foreign function!");
            return;
        }

        DiaphoraDiffer differ = new DiaphoraDiffer(dbs.getPrimary(), dbs.getSecondary(), diffOptions);
        Double ratio = differ.compareFunctionsByAddress(ea1, ea2);
        MatchItem item = new MatchItem(DiffDatabases.toHex(mainRow.get("address")), mainRow.get("name"),
            DiffDatabases.toHex(diffRow.get("address")), diffRow.get("name"), "Manual match",
            ratio != null ? ratio : 0.0, parseInt(mainRow.get("nodes")), parseInt(diffRow.get("nodes")));

        if (matchedPrimary.contains(item.getName1()) || matchedSecondary.contains(item.getName2())) {
            warning("Either the local function or the foreign function is already matched!\n" +
                    "Please remove the previously assigned match before adding a manual match.");
            return;
        }
        results.get(MatchCategory.PARTIAL).add(item);
        matchedPrimary.add(item.getName1());
        matchedSecondary.add(item.getName2());
        updateTabs();
        tabbedPane.setSelectedIndex(MatchCategory.PARTIAL.ordinal());
    }

    private static int parseInt(String s) {
        try {
            return s != null ? Integer.parseInt(s) : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** OnDeleteLine(): remove the items and forget their matched names. */
    private void deleteSelected(MatchCategory cat) {
        List<MatchItem> selection = selectedItems(cat);
        if (selection.isEmpty()) return;
        List<MatchItem> items = results.get(cat);
        for (MatchItem item : selection) {
            items.remove(item);
            matchedPrimary.remove(item.getName1());
            matchedSecondary.remove(item.getName2());
        }
        updateTabs();
    }

    /** CMD_REDIFF: the diff/export dialog again with the same databases. */
    private void diffAgain() {
        plugin.showDiffDialog(dbs.getPrimary(), dbs.getSecondary());
    }

    // ------------------------------------------------------------------------
    // Colors in the listing
    // ------------------------------------------------------------------------

    private ColorizingService getColorizer() {
        ColorizingService service = plugin.getTool().getService(ColorizingService.class);
        if (service == null) {
            Msg.showWarn(this, getComponent(), "Diaphora-ng", "The Colorizer service is not available in this tool.");
        }
        return service;
    }

    private Address parseAddress(Program program, String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) return null;
        try {
            return program.getAddressFactory().getDefaultAddressSpace()
                          .getAddress(Long.parseUnsignedLong(ea(addrStr)));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * "Highlight matches" / "Unhighlight matches": change the background color of
     * every matched function of the tab (color null clears it).
     */
    private void highlightTab(MatchCategory cat, Color color) {
        Program program = plugin.getCurrentProgram();
        ColorizingService colorizer = getColorizer();
        if (program == null || colorizer == null) return;

        if (color != null) {
            int answer = OptionDialog.showYesNoDialog(getComponent(), "Diaphora-ng",
                "Do you want to change the background color of each matched function?");
            if (answer != OptionDialog.YES_OPTION) return;
        }

        int count = 0;
        int tx = program.startTransaction(color != null ? "Diaphora-ng: highlight matches" : "Diaphora-ng: unhighlight matches");
        try {
            for (MatchItem item : results.getOrDefault(cat, Collections.emptyList())) {
                Address addr = parseAddress(program, item.getAddress1());
                if (addr == null) continue;
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    log("Error setting color for " + item.getAddress1());
                    continue;
                }
                if (color != null) {
                    colorizer.setBackgroundColor(func.getBody(), color);
                } else {
                    colorizer.clearBackgroundColor(func.getBody());
                }
                count++;
            }
        } finally {
            program.endTransaction(tx, true);
        }
        plugin.getTool().setStatusInfo("Diaphora-ng: " + (color != null ? "highlighted " : "unhighlighted ") +
            count + " functions");
    }

    private void clearFunctionColors(MatchItem item) {
        Program program = plugin.getCurrentProgram();
        ColorizingService colorizer = getColorizer();
        if (program == null || colorizer == null || item == null) return;
        Address addr = parseAddress(program, item.getAddress1());
        Function func = addr != null ? program.getFunctionManager().getFunctionAt(addr) : null;
        if (func == null) return;
        int tx = program.startTransaction("Diaphora-ng: clear basic block colors");
        try {
            colorizer.clearBackgroundColor(func.getBody());
        } finally {
            program.endTransaction(tx, true);
        }
    }

    /**
     * Graph diff in the listing: color the basic blocks of the primary function
     * that are new (GRAPH_BBLOCK_MATCH_NONE) or modified (GRAPH_BBLOCK_MATCH_PARTIAL)
     * with respect to the matched secondary function. Visible in the Listing and in
     * the Function Graph.
     */
    private void highlightBasicBlocks(MatchItem item) {
        Program program = plugin.getCurrentProgram();
        ColorizingService colorizer = getColorizer();
        if (program == null || colorizer == null || item == null) return;

        Address entry = parseAddress(program, item.getAddress1());
        Function func = entry != null ? program.getFunctionManager().getFunctionAt(entry) : null;
        if (func == null) {
            Msg.showWarn(this, getComponent(), "Diaphora-ng", "Function not found at " + item.getAddress1());
            return;
        }

        GraphDiff.Result diff;
        try {
            diff = GraphDiff.compare(dbs.getPrimary(), dbs.getSecondary(), ea(item.getAddress1()), ea(item.getAddress2()));
        } catch (Exception e) {
            Msg.showError(this, getComponent(), "Diaphora-ng", "Error comparing basic blocks: " + e.getMessage(), e);
            return;
        }

        Color partial = DiaphoraColors.blockPartialColor();
        Color none = DiaphoraColors.blockNoneColor();
        BasicBlockModel model = new BasicBlockModel(program);
        int modified = 0;
        int added = 0;

        int tx = program.startTransaction("Diaphora-ng: highlight basic block differences");
        try {
            colorizer.clearBackgroundColor(func.getBody());
            for (Map.Entry<String, GraphDiff.BlockMatch> e : diff.primary.entrySet()) {
                if (e.getValue() == GraphDiff.BlockMatch.PERFECT) continue;
                Address bbAddr;
                try {
                    // Basic blocks are stored by RVA, as diaphora_ida.py does
                    bbAddr = program.getImageBase().add(Long.parseLong(e.getKey()));
                } catch (Exception ex) {
                    continue;
                }
                CodeBlock block = model.getCodeBlockAt(bbAddr, TaskMonitor.DUMMY);
                if (block == null) {
                    block = model.getFirstCodeBlockContaining(bbAddr, TaskMonitor.DUMMY);
                }
                if (block == null) continue;
                AddressSet set = new AddressSet(block).intersect(func.getBody());
                if (e.getValue() == GraphDiff.BlockMatch.PARTIAL) {
                    colorizer.setBackgroundColor(set, partial);
                    modified++;
                } else {
                    colorizer.setBackgroundColor(set, none);
                    added++;
                }
            }
        } catch (Exception e) {
            Msg.showError(this, getComponent(), "Diaphora-ng", "Error coloring basic blocks: " + e.getMessage(), e);
        } finally {
            program.endTransaction(tx, true);
        }

        long removed = diff.secondary.values().stream().filter(v -> v == GraphDiff.BlockMatch.NONE).count();
        plugin.goTo(entry);
        plugin.getTool().setStatusInfo("Diaphora-ng: " + diff.primary.size() + " basic blocks, " + added +
            " new (red), " + modified + " modified (yellow), " + removed + " only in the secondary function");
    }

    // --- Table Model ---
    private static class MatchTableModel extends AbstractTableModel {
        private final String[] columns = {"Ratio", "Name 1", "Address 1", "Name 2", "Address 2", "Description", "Nodes 1", "Nodes 2"};
        private List<MatchItem> items = new ArrayList<>();

        public void setItems(List<MatchItem> items) {
            this.items = (items != null) ? items : new ArrayList<>();
            fireTableDataChanged();
        }

        public List<MatchItem> getItems() {
            return items;
        }

        public MatchItem getItemAt(int row) {
            if (row >= 0 && row < items.size()) {
                return items.get(row);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return items.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) return Double.class;
            if (columnIndex == 6 || columnIndex == 7) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            MatchItem item = items.get(rowIndex);
            switch (columnIndex) {
                case 0: return item.getRatio();
                case 1: return item.getName1();
                case 2: return item.getAddress1();
                case 3: return item.getName2();
                case 4: return item.getAddress2();
                case 5: return item.getDescription();
                case 6: return item.getNodes1();
                case 7: return item.getNodes2();
                default: return "";
            }
        }
    }

    // --- Renderer for Ratio with colors ---
    private static class RatioRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (value instanceof Double) {
                double r = (Double) value;
                setText(String.format("%.3f", r));
                setHorizontalAlignment(SwingConstants.RIGHT);
            }
            return c;
        }
    }
}
