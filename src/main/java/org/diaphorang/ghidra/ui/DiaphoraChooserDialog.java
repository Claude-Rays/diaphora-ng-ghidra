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
import docking.widgets.table.GTable;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;

/**
 * Modal chooser of one row, the equivalent of choose_func_ea() and of the
 * CBasicChooser used by "Add manual match".
 */
public class DiaphoraChooserDialog extends DialogComponentProvider {

    private final GTable table;
    private final List<String[]> rows;
    private int selected = -1;

    public DiaphoraChooserDialog(String title, String[] columns, List<String[]> rows) {
        super(title, true, true, true, false);
        this.rows = rows;

        AbstractTableModel model = new AbstractTableModel() {
            @Override
            public int getRowCount() {
                return rows.size();
            }

            @Override
            public int getColumnCount() {
                return columns.length;
            }

            @Override
            public String getColumnName(int c) {
                return columns[c];
            }

            @Override
            public Object getValueAt(int r, int c) {
                return rows.get(r)[c];
            }
        };
        table = new GTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        TableRowSorter<AbstractTableModel> sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) okCallback();
            }
        });

        JTextField filter = new JTextField();
        filter.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                String text = filter.getText().trim();
                sorter.setRowFilter(text.isEmpty() ? null
                    : RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
            }

            public void insertUpdate(DocumentEvent e) { update(); }
            public void removeUpdate(DocumentEvent e) { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });

        JPanel main = new JPanel(new BorderLayout(5, 5));
        main.setBorder(new EmptyBorder(8, 8, 8, 8));
        main.setPreferredSize(new Dimension(650, 500));
        JPanel top = new JPanel(new BorderLayout(5, 5));
        top.add(new JLabel("Filter: "), BorderLayout.WEST);
        top.add(filter, BorderLayout.CENTER);
        main.add(top, BorderLayout.NORTH);
        main.add(new JScrollPane(table), BorderLayout.CENTER);
        addWorkPanel(main);
        addOKButton();
        addCancelButton();
    }

    @Override
    protected void okCallback() {
        int row = table.getSelectedRow();
        if (row < 0) return;
        selected = table.convertRowIndexToModel(row);
        close();
    }

    /** Index of the chosen row in the list given to the constructor, -1 if cancelled. */
    public int getSelected() {
        return selected;
    }

    public String[] getSelectedRow() {
        return selected >= 0 ? rows.get(selected) : null;
    }
}
