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

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/**
 * show_graph_pair(): two related graphs side by side, zoomed to fit.
 */
public class DiaphoraGraphDialog extends DialogComponentProvider {

    public DiaphoraGraphDialog(String title, DiaphoraGraphPanel.GraphData g1, DiaphoraGraphPanel.GraphData g2) {
        super(title, false, true, true, false);

        JPanel main = new JPanel(new BorderLayout());
        main.setBorder(new EmptyBorder(4, 4, 4, 4));
        main.setPreferredSize(new Dimension(1200, 800));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, wrap(g1), wrap(g2));
        split.setResizeWeight(0.5);
        main.add(split, BorderLayout.CENTER);
        main.add(new JLabel("Drag to move, mouse wheel to zoom, double click on the background to fit the graph."),
                 BorderLayout.SOUTH);

        addWorkPanel(main);
        addDismissButton();
        setRememberSize(false);
    }

    private static JComponent wrap(DiaphoraGraphPanel.GraphData data) {
        JPanel p = new JPanel(new BorderLayout());
        JLabel label = new JLabel(data.title);
        label.setBorder(new EmptyBorder(2, 4, 4, 4));
        p.add(label, BorderLayout.NORTH);
        DiaphoraGraphPanel panel = new DiaphoraGraphPanel(data);
        panel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
        p.add(panel, BorderLayout.CENTER);
        return p;
    }
}
