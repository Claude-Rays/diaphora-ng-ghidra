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

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import org.diaphorang.ghidra.diff.DiaphoraDiffer;
import org.diaphorang.ghidra.export.DiaphoraExporter;
import org.diaphorang.ghidra.model.MatchCategory;
import org.diaphorang.ghidra.model.MatchItem;
import org.diaphorang.ghidra.util.DiffSettings;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * Setup dialog for exporting and diffing Ghidra programs.
 */
public class DiaphoraExportDialog extends DialogComponentProvider {

    private final DiaphoraNgPlugin plugin;
    private final JTextField primaryPathField;
    private final JTextField secondaryPathField;
    private final JCheckBox useDecompilerBox;
    private final JCheckBox relaxedRatioBox;
    private final JCheckBox enableUnreliableBox;
    private final JCheckBox ignoreSubNamesBox;
    private final JCheckBox slowHeuristicsBox;
    private final JCheckBox experimentalBox;
    private final JCheckBox ignoreAllNamesBox;
    private final JCheckBox ignoreSmallBox;
    private final JCheckBox canonicalNamesBox;

    public DiaphoraExportDialog(DiaphoraNgPlugin plugin) {
        this(plugin, null, null);
    }

    /** re_diff(): the dialog again, with the databases of the last diff. */
    public DiaphoraExportDialog(DiaphoraNgPlugin plugin, File lastPrimary, File lastSecondary) {
        super("Diaphora-ng: Diff or Export", true, true, true, false);
        this.plugin = plugin;

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel.setPreferredSize(new Dimension(700, 430));

        // Form panel
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Primary DB output
        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0.0;
        form.add(new JLabel("Primary Output Database:"), gbc);

        Program prog = plugin.getCurrentProgram();
        String defaultPrimary = new File(defaultDirectory(plugin),
                (prog != null ? prog.getName().replaceAll("[^a-zA-Z0-9_.-]", "_") : "program") + ".sqlite")
                .getAbsolutePath();

        primaryPathField = new JTextField(defaultPrimary);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        form.add(primaryPathField, gbc);

        JButton browsePrimary = new JButton("Browse...");
        browsePrimary.addActionListener(e -> chooseFile(primaryPathField, true));
        gbc.gridx = 2; gbc.gridy = 0; gbc.weightx = 0.0;
        form.add(browsePrimary, gbc);

        // Secondary DB input
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0.0;
        form.add(new JLabel("Secondary Database (to diff):"), gbc);

        secondaryPathField = new JTextField();
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0;
        form.add(secondaryPathField, gbc);

        JButton browseSecondary = new JButton("Browse...");
        browseSecondary.addActionListener(e -> chooseFile(secondaryPathField, false));
        gbc.gridx = 2; gbc.gridy = 1; gbc.weightx = 0.0;
        form.add(browseSecondary, gbc);

        // Options
        JPanel optionsPanel = new JPanel(new GridLayout(5, 2, 8, 8));
        optionsPanel.setBorder(new TitledBorder("Diffing & Export Options"));

        // Same options and defaults as Diaphora's CBinDiffExporterSetup / diaphora_config.py
        useDecompilerBox = new JCheckBox("Use the decompiler if available", true);
        ignoreSmallBox = new JCheckBox("Ignore small functions", false);
        enableUnreliableBox = new JCheckBox("Use probably unreliable methods", false);
        slowHeuristicsBox = new JCheckBox("Use slow heuristics", true);
        relaxedRatioBox = new JCheckBox("Relaxed calculations of differences ratios", false);
        experimentalBox = new JCheckBox("Use speed ups", true);
        ignoreSubNamesBox = new JCheckBox("Ignore automatically generated names", true);
        ignoreAllNamesBox = new JCheckBox("Ignore all function names", false);
        // Diaphora-ng: level 1 of the pseudo-code diff, an export option (util/DiffSettings; level 2 is in Pseudo-code diff settings)
        canonicalNamesBox = new JCheckBox("Name the locals v1, v2... (level 1)", DiffSettings.canonicalNames());
        canonicalNamesBox.setToolTipText("<html>Export the pseudo-code with the locals named v1, v2... in the order " +
            "of first use, as Hex-Rays does,<br>instead of Ghidra's uVar3, local_28... It also changes the " +
            "pseudo-code hashes.<br>Diff databases exported the same way.</html>");

        optionsPanel.add(useDecompilerBox);
        optionsPanel.add(ignoreSmallBox);
        optionsPanel.add(enableUnreliableBox);
        optionsPanel.add(slowHeuristicsBox);
        optionsPanel.add(relaxedRatioBox);
        optionsPanel.add(experimentalBox);
        optionsPanel.add(ignoreSubNamesBox);
        optionsPanel.add(ignoreAllNamesBox);
        optionsPanel.add(canonicalNamesBox);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3; gbc.weightx = 1.0;
        form.add(optionsPanel, gbc);

        panel.add(form, BorderLayout.CENTER);

        addWorkPanel(panel);

        // Buttons
        JButton diffButton = new JButton("Export & Diff");
        diffButton.addActionListener(e -> startExportAndDiff());
        addButton(diffButton);

        JButton exportOnlyButton = new JButton("Export Only");
        exportOnlyButton.addActionListener(e -> startExportOnly());
        addButton(exportOnlyButton);

        addCancelButton();

        if (lastPrimary != null) {
            primaryPathField.setText(lastPrimary.getAbsolutePath());
        }
        if (lastSecondary != null) {
            secondaryPathField.setText(lastSecondary.getAbsolutePath());
        }
    }

    /**
     * Folder of the current Ghidra project (where its .gpr file is), or the
     * temporary directory when there is no project.
     */
    private static File defaultDirectory(DiaphoraNgPlugin plugin) {
        try {
            ghidra.framework.model.Project project = plugin.getTool().getProject();
            if (project != null && project.getProjectLocator() != null) {
                File dir = new File(project.getProjectLocator().getLocation());
                if (dir.isDirectory()) {
                    return dir;
                }
            }
        } catch (Exception e) {
            // fall back to the temporary directory
        }
        return new File(System.getProperty("java.io.tmpdir"));
    }

    private void chooseFile(JTextField targetField, boolean isSave) {
        GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
        chooser.setTitle(isSave ? "Select Output SQLite Database" : "Select Secondary Diaphora Database");
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

        String txt = targetField.getText().trim();
        if (!txt.isEmpty()) {
            File current = new File(txt);
            if (current.exists() && current.isDirectory()) {
                chooser.setCurrentDirectory(current);
            } else if (current.getParentFile() != null && current.getParentFile().exists()) {
                chooser.setCurrentDirectory(current.getParentFile());
                if (isSave) {
                    chooser.setSelectedFile(current);
                }
            }
        }

        File selected = chooser.getSelectedFile();
        if (selected != null) {
            if (selected.isDirectory()) {
                return;
            }
            if (isSave && !selected.getName().contains(".")) {
                selected = new File(selected.getAbsolutePath() + ".sqlite");
            }
            targetField.setText(selected.getAbsolutePath());
        }
    }

    private void startExportOnly() {
        String primaryPath = primaryPathField.getText().trim();
        if (primaryPath.isEmpty()) {
            Msg.showError(this, getComponent(), "Missing Output File",
                    "Please specify an output SQLite database path.");
            return;
        }

        File primaryFile = new File(primaryPath);
        if (primaryFile.isDirectory()) {
            Msg.showError(this, getComponent(), "Invalid Output Path",
                    "The primary output path is a directory, not a database file:\n" + primaryFile.getAbsolutePath() +
                    "\n\nPlease specify a file name ending in .sqlite.");
            return;
        }
        if (!primaryFile.getName().contains(".")) {
            primaryFile = new File(primaryFile.getAbsolutePath() + ".sqlite");
            primaryPathField.setText(primaryFile.getAbsolutePath());
        }

        if (primaryFile.exists() && primaryFile.length() > 0) {
            int choice = JOptionPane.showConfirmDialog(
                    getComponent(),
                    "The output database already exists:\n" + primaryFile.getAbsolutePath() + "\n\nDo you want to overwrite it?",
                    "Export Database Already Exists",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );
            if (choice != JOptionPane.YES_OPTION) {
                return;
            }
        }

        final File finalPrimaryFile = primaryFile;
        boolean useDecomp = useDecompilerBox.isSelected();
        boolean canonical = canonicalNamesBox.isSelected();
        saveSettings();
        close();

        Task task = new Task("Diaphora-ng Export", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    DiaphoraExporter exporter = new DiaphoraExporter(plugin.getCurrentProgram(), finalPrimaryFile, useDecomp,
                                                                     canonical);
                    exporter.doExport(monitor);
                    Msg.showInfo(this, null, "Export Complete", "Primary binary exported successfully to:\n" + finalPrimaryFile.getAbsolutePath());
                } catch (Exception e) {
                    Msg.showError(this, null, "Export Error", "Export failed: " + e.getMessage(), e);
                }
            }
        };
        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void startExportAndDiff() {
        String primaryPath = primaryPathField.getText().trim();
        String secondaryPath = secondaryPathField.getText().trim();

        if (primaryPath.isEmpty()) {
            Msg.showError(this, getComponent(), "Missing Output File",
                    "Please specify an output SQLite database path.");
            return;
        }

        File primaryFile = new File(primaryPath);
        if (primaryFile.isDirectory()) {
            Msg.showError(this, getComponent(), "Invalid Output Path",
                    "The primary output path is a directory, not a database file:\n" + primaryFile.getAbsolutePath() +
                    "\n\nPlease specify a file name ending in .sqlite.");
            return;
        }
        if (!primaryFile.getName().contains(".")) {
            primaryFile = new File(primaryFile.getAbsolutePath() + ".sqlite");
            primaryPathField.setText(primaryFile.getAbsolutePath());
        }

        if (secondaryPath.isEmpty()) {
            Msg.showError(this, getComponent(), "Missing Secondary Database",
                    "Please select an existing secondary SQLite database (.sqlite) to diff against.\n\n" +
                    "Tip: If you only want to export the current program to SQLite without diffing, click 'Export Only'.");
            return;
        }

        File secondaryFile = new File(secondaryPath);
        if (!secondaryFile.exists()) {
            Msg.showError(this, getComponent(), "Secondary Database Not Found",
                    "The secondary database file does not exist:\n" + secondaryFile.getAbsolutePath() +
                    "\n\nPlease click 'Browse...' to select a valid .sqlite file.");
            return;
        }

        if (secondaryFile.isDirectory()) {
            Msg.showError(this, getComponent(), "Invalid Secondary Database",
                    "The selected secondary database is a directory, not an SQLite database file:\n" + secondaryFile.getAbsolutePath() +
                    "\n\nPlease click 'Browse...' and select an exported .sqlite file.");
            return;
        }

        boolean shouldExport = true;
        if (primaryFile.exists() && primaryFile.length() > 0) {
            Object[] options = {"Overwrite & Diff", "Use Existing & Diff", "Cancel"};
            int choice = JOptionPane.showOptionDialog(
                    getComponent(),
                    "The primary export database already exists:\n" + primaryFile.getAbsolutePath() + "\n\n" +
                    "Do you want to re-export (overwrite) or use the existing database to diff directly?",
                    "Export Database Already Exists",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[1] // Default to 'Use Existing & Diff' for convenience
            );

            if (choice == 0) {
                shouldExport = true;
            } else if (choice == 1) {
                shouldExport = false;
            } else {
                return; // Cancelled
            }
        }

        final boolean doExport = shouldExport;
        final File finalPrimaryFile = primaryFile;
        final File finalSecondaryFile = secondaryFile;
        boolean useDecomp = useDecompilerBox.isSelected();
        boolean canonical = canonicalNamesBox.isSelected();
        saveSettings();
        DiaphoraDiffer.Options diffOptions = new DiaphoraDiffer.Options();
        diffOptions.relaxedRatio = relaxedRatioBox.isSelected();
        diffOptions.unreliable = enableUnreliableBox.isSelected();
        diffOptions.ignoreSubNames = ignoreSubNamesBox.isSelected();
        diffOptions.slowHeuristics = slowHeuristicsBox.isSelected();
        diffOptions.experimental = experimentalBox.isSelected();
        diffOptions.ignoreAllNames = ignoreAllNamesBox.isSelected();
        diffOptions.ignoreSmallFunctions = ignoreSmallBox.isSelected();
        close();

        Task task = new Task("Diaphora-ng Diffing", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    if (doExport) {
                        monitor.setMessage("Step 1/2: Exporting primary program...");
                        DiaphoraExporter exporter = new DiaphoraExporter(plugin.getCurrentProgram(), finalPrimaryFile, useDecomp,
                                                                     canonical);
                        exporter.doExport(monitor);

                        if (monitor.isCancelled()) return;
                    }

                    monitor.setMessage(doExport ? "Step 2/2: Diffing with secondary database..." : "Diffing databases...");
                    DiaphoraDiffer differ = new DiaphoraDiffer(finalPrimaryFile, finalSecondaryFile, diffOptions);
                    Map<MatchCategory, List<MatchItem>> results = differ.diff(monitor);

                    SwingUtilities.invokeLater(() -> {
                        plugin.getProvider().setResults(results, finalPrimaryFile, finalSecondaryFile, diffOptions, useDecomp);
                        plugin.getProvider().setVisible(true);
                    });

                } catch (Exception e) {
                    Msg.showError(this, null, "Diff Error", "Diffing failed: " + e.getMessage(), e);
                }
            }
        };
        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }
    /** Diaphora-ng: level 1 as chosen here is the default of the next time (and of Local diff). */
    private void saveSettings() {
        DiffSettings.setCanonicalNames(canonicalNamesBox.isSelected());
    }
}
